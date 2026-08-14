use std::{
    ffi::OsStr,
    fmt,
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom},
    ops::Range,
    path::{Path, PathBuf},
};

use object::{
    Architecture as ObjectArchitecture, LittleEndian, Object, ObjectKind,
    read::{
        FileKind, ReadCache, ReadRef,
        pe::{ImageNtHeaders, ImageOptionalHeader, PeFile},
    },
};
use pdb::MachineType;
use serde::Serialize;

mod symbolicate;
mod symcache;

pub use symbolicate::{
    FrameSymbolStatus, InlineSymbol, ModuleSymbolStatus, SYMBOLICATION_SCHEMA_VERSION,
    SymbolicatedFrame, SymbolicatedModule, SymbolicatedThread, SymbolicationError,
    SymbolicationErrorKind, SymbolicationLimits, SymbolicationResult, ThreadUnwindStatus,
    symbolicate_minidump, symbolicate_minidump_bytes,
};
pub use symcache::{
    SYMCACHE_FORMAT_VERSION, SYMCACHE_PROCESSOR_VERSION, SymCacheArtifact, SymCacheGenerationError,
    SymCacheMetadata, generate_symcache, symbolicate_minidump_bytes_with_symcaches,
};

pub const ARTIFACT_SCAN_SCHEMA_VERSION: u32 = 1;
const MAX_METADATA_READ_BYTES: u64 = 16 * 1024 * 1024;
const MAX_DEBUG_DIRECTORY_BYTES: u64 = 64 * 1024;
const MAX_CODEVIEW_BYTES: u64 = 64 * 1024;
const MAX_PDB_PAGE_BYTES: usize = 64 * 1024;
const PDB_HEADER_BYTES: usize = 4096;
const PDB_RAW_HEADER_BYTES: usize = 52;
const PDB_DBI_HEADER_BYTES: usize = 64;
const PDB_DBI_STREAM: usize = 3;
const PDB_MAGIC: &[u8; 32] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";
const IMAGE_DEBUG_DIRECTORY_BYTES: usize = 28;
const IMAGE_DEBUG_TYPE_CODEVIEW_VALUE: u32 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    PeExecutable,
    PeDynamicLibrary,
    Pdb,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86,
    X86_64,
    Arm64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchState {
    Matched,
    MissingCompanion,
    Mismatched,
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactErrorCode {
    Malformed,
    MissingDebugIdentity,
    Unreadable,
    UnsupportedArchitecture,
    UnsupportedFormat,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ArtifactError {
    pub code: ArtifactErrorCode,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ArtifactRecord {
    pub path: String,
    pub module: String,
    pub artifact_type: ArtifactType,
    pub architecture: Option<Architecture>,
    pub size: Option<u64>,
    pub debug_id: Option<String>,
    pub code_id: Option<String>,
    pub match_state: MatchState,
    pub matches: Vec<String>,
    pub error: Option<ArtifactError>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ArtifactScan {
    pub schema_version: u32,
    pub artifacts: Vec<ArtifactRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactScanLimits {
    pub entries: usize,
    pub depth: usize,
    pub files: usize,
    pub file_bytes: u64,
    pub total_bytes: u64,
}

impl ArtifactScanLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            entries: usize::MAX,
            depth: usize::MAX,
            files: usize::MAX,
            file_bytes: u64::MAX,
            total_bytes: u64::MAX,
        }
    }
}

#[derive(Debug)]
pub enum ScanError {
    InspectRoot(io::Error),
    ReadDirectory(io::Error),
    TooManyEntries,
    DirectoryDepthExceeded,
    TooManyFiles,
    ArtifactTooLarge,
    TotalSizeExceeded,
}

impl fmt::Display for ScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InspectRoot(_) => write!(formatter, "failed to inspect artifact path"),
            Self::ReadDirectory(_) => write!(formatter, "failed to read artifact directory"),
            Self::TooManyEntries => write!(formatter, "artifact tree entry limit exceeded"),
            Self::DirectoryDepthExceeded => {
                write!(formatter, "artifact directory depth limit exceeded")
            }
            Self::TooManyFiles => write!(formatter, "artifact file count limit exceeded"),
            Self::ArtifactTooLarge => write!(formatter, "artifact file size limit exceeded"),
            Self::TotalSizeExceeded => write!(formatter, "artifact total size limit exceeded"),
        }
    }
}

impl std::error::Error for ScanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InspectRoot(error) | Self::ReadDirectory(error) => Some(error),
            Self::TooManyEntries
            | Self::DirectoryDepthExceeded
            | Self::TooManyFiles
            | Self::ArtifactTooLarge
            | Self::TotalSizeExceeded => None,
        }
    }
}

#[derive(Clone, Debug)]
struct Identity {
    guid: [u8; 16],
    age: u32,
    original_age: Option<u32>,
}

#[derive(Clone, Debug)]
struct ParsedArtifact {
    record: ArtifactRecord,
    identity: Option<Identity>,
    expected_pdb_name: Option<String>,
}

#[derive(Clone, Debug)]
struct PeCodeView {
    guid: [u8; 16],
    age: u32,
    path: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
struct PdbLayout {
    page_size: usize,
    pages_used: usize,
    directory_bytes: usize,
    file_bytes: u64,
}

#[derive(Clone, Copy, Debug)]
struct BoundedPeReader<'a> {
    inner: &'a ReadCache<File>,
}

impl<'a> ReadRef<'a> for BoundedPeReader<'a> {
    fn len(self) -> Result<u64, ()> {
        self.inner.len()
    }

    fn read_bytes_at(self, offset: u64, size: u64) -> Result<&'a [u8], ()> {
        if size > MAX_METADATA_READ_BYTES {
            return Err(());
        }
        self.inner.read_bytes_at(offset, size)
    }

    fn read_bytes_at_until(self, range: Range<u64>, delimiter: u8) -> Result<&'a [u8], ()> {
        if range
            .end
            .checked_sub(range.start)
            .is_none_or(|size| size > MAX_METADATA_READ_BYTES)
        {
            return Err(());
        }
        self.inner.read_bytes_at_until(range, delimiter)
    }
}

#[derive(Debug)]
struct BoundedPdbSource {
    file: File,
}

#[derive(Debug)]
struct PdbSourceView {
    bytes: Vec<u8>,
}

impl pdb::SourceView<'_> for PdbSourceView {
    fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

impl<'source> pdb::Source<'source> for BoundedPdbSource {
    fn view(
        &mut self,
        slices: &[pdb::SourceSlice],
    ) -> Result<Box<dyn pdb::SourceView<'source>>, io::Error> {
        let size = slices.iter().try_fold(0_u64, |total, slice| {
            let slice_size = u64::try_from(slice.size).map_err(io::Error::other)?;
            total
                .checked_add(slice_size)
                .filter(|size| *size <= MAX_METADATA_READ_BYTES)
                .ok_or_else(|| io::Error::other("PDB metadata read limit exceeded"))
        })?;
        let capacity = usize::try_from(size).map_err(io::Error::other)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(io::Error::other)?;

        for slice in slices {
            self.file.seek(SeekFrom::Start(slice.offset))?;
            let start = bytes.len();
            let end = start
                .checked_add(slice.size)
                .ok_or_else(|| io::Error::other("PDB metadata read limit exceeded"))?;
            bytes.resize(end, 0);
            self.file.read_exact(&mut bytes[start..end])?;
        }

        Ok(Box::new(PdbSourceView { bytes }))
    }
}

/// Scans one artifact file or directory tree.
///
/// # Errors
///
/// Returns an error when the root or a directory entry cannot be inspected.
pub fn scan_artifacts(root: &Path) -> Result<ArtifactScan, ScanError> {
    scan_artifacts_with_limits(root, ArtifactScanLimits::unlimited())
}

/// Scans one artifact file or directory tree within explicit file and byte limits.
///
/// # Errors
///
/// Returns an error when the tree cannot be inspected or a configured limit is exceeded.
pub fn scan_artifacts_with_limits(
    root: &Path,
    limits: ArtifactScanLimits,
) -> Result<ArtifactScan, ScanError> {
    let metadata = fs::symlink_metadata(root).map_err(ScanError::InspectRoot)?;
    let mut files = Vec::new();
    let mut total_bytes = 0;

    if metadata.file_type().is_file() {
        if supported_extension(root) {
            add_file(
                root.to_path_buf(),
                file_name(root),
                metadata.len(),
                &mut files,
                &mut total_bytes,
                limits,
            )?;
        }
    } else if metadata.file_type().is_dir() {
        discover_files(root, &mut files, &mut total_bytes, limits)?;
    }

    files.sort_by(|left, right| left.1.cmp(&right.1));
    let mut artifacts = files
        .into_iter()
        .map(|(path, relative)| parse_artifact(&path, relative))
        .collect::<Vec<_>>();
    match_artifacts(&mut artifacts);

    Ok(ArtifactScan {
        schema_version: ARTIFACT_SCAN_SCHEMA_VERSION,
        artifacts: artifacts
            .into_iter()
            .map(|artifact| artifact.record)
            .collect(),
    })
}

fn discover_files(
    root: &Path,
    files: &mut Vec<(PathBuf, String)>,
    total_bytes: &mut u64,
    limits: ArtifactScanLimits,
) -> Result<(), ScanError> {
    let mut directories = vec![(PathBuf::new(), 0_usize)];
    let mut entries_seen = 0_usize;

    while let Some((relative, depth)) = directories.pop() {
        if depth > limits.depth {
            return Err(ScanError::DirectoryDepthExceeded);
        }
        let entries = fs::read_dir(root.join(&relative)).map_err(ScanError::ReadDirectory)?;

        for entry in entries {
            entries_seen = entries_seen
                .checked_add(1)
                .filter(|count| *count <= limits.entries)
                .ok_or(ScanError::TooManyEntries)?;
            let entry = entry.map_err(ScanError::ReadDirectory)?;
            let file_type = entry.file_type().map_err(ScanError::ReadDirectory)?;
            let child_relative = relative.join(entry.file_name());
            if file_type.is_dir() {
                directories.push((child_relative, depth.saturating_add(1)));
            } else if file_type.is_file() && supported_extension(&child_relative) {
                let size = entry.metadata().map_err(ScanError::ReadDirectory)?.len();
                add_file(
                    entry.path(),
                    normalize_path(&child_relative),
                    size,
                    files,
                    total_bytes,
                    limits,
                )?;
            }
        }
    }

    Ok(())
}

fn add_file(
    path: PathBuf,
    relative: String,
    size: u64,
    files: &mut Vec<(PathBuf, String)>,
    total_bytes: &mut u64,
    limits: ArtifactScanLimits,
) -> Result<(), ScanError> {
    if files.len() >= limits.files {
        return Err(ScanError::TooManyFiles);
    }
    if size > limits.file_bytes {
        return Err(ScanError::ArtifactTooLarge);
    }
    *total_bytes = total_bytes
        .checked_add(size)
        .filter(|total| *total <= limits.total_bytes)
        .ok_or(ScanError::TotalSizeExceeded)?;
    files.push((path, relative));
    Ok(())
}

fn supported_extension(path: &Path) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("exe")
                || extension.eq_ignore_ascii_case("dll")
                || extension.eq_ignore_ascii_case("pdb")
        })
}

fn parse_artifact(path: &Path, relative: String) -> ParsedArtifact {
    let artifact_type = inferred_artifact_type(path);
    let module = file_name(path);
    let size = fs::metadata(path).ok().map(|metadata| metadata.len());

    let parsed = match File::open(path) {
        Ok(file) if artifact_type == ArtifactType::Pdb => parse_pdb(file, size),
        Ok(file) => parse_pe(file, size),
        Err(_) => Err(ArtifactErrorCode::Unreadable),
    };

    match parsed {
        Ok(mut artifact) => {
            artifact.record.path = relative;
            artifact.record.module = module;
            artifact
        }
        Err(code) => ParsedArtifact {
            record: ArtifactRecord {
                path: relative,
                module,
                artifact_type,
                architecture: None,
                size,
                debug_id: None,
                code_id: None,
                match_state: MatchState::Invalid,
                matches: Vec::new(),
                error: Some(ArtifactError { code }),
            },
            identity: None,
            expected_pdb_name: None,
        },
    }
}

fn parse_pe(file: File, size: Option<u64>) -> Result<ParsedArtifact, ArtifactErrorCode> {
    let cache = ReadCache::new(file);
    let data = BoundedPeReader { inner: &cache };
    match FileKind::parse(data).map_err(|_| ArtifactErrorCode::Malformed)? {
        FileKind::Pe32 => parse_pe_kind::<object::pe::ImageNtHeaders32>(data, size),
        FileKind::Pe64 => parse_pe_kind::<object::pe::ImageNtHeaders64>(data, size),
        _ => Err(ArtifactErrorCode::UnsupportedFormat),
    }
}

fn parse_pe_kind<Pe>(
    data: BoundedPeReader<'_>,
    size: Option<u64>,
) -> Result<ParsedArtifact, ArtifactErrorCode>
where
    Pe: ImageNtHeaders,
{
    let file = PeFile::<Pe, _>::parse(data).map_err(|_| ArtifactErrorCode::Malformed)?;
    let architecture = object_architecture(file.architecture())?;
    let code_view =
        read_pe_code_view(data, &file)?.ok_or(ArtifactErrorCode::MissingDebugIdentity)?;
    let guid = canonical_pe_guid(code_view.guid);
    let age = code_view.age;
    let timestamp = file
        .nt_headers()
        .file_header()
        .time_date_stamp
        .get(LittleEndian);
    let image_size = file.nt_headers().optional_header().size_of_image();
    let artifact_type = match file.kind() {
        ObjectKind::Dynamic => ArtifactType::PeDynamicLibrary,
        ObjectKind::Executable => ArtifactType::PeExecutable,
        _ => return Err(ArtifactErrorCode::UnsupportedFormat),
    };

    Ok(ParsedArtifact {
        record: ArtifactRecord {
            path: String::new(),
            module: String::new(),
            artifact_type,
            architecture: Some(architecture),
            size,
            debug_id: Some(format_debug_id(&guid, age)),
            code_id: Some(format!("{timestamp:08X}{image_size:X}")),
            match_state: MatchState::MissingCompanion,
            matches: Vec::new(),
            error: None,
        },
        identity: Some(Identity {
            guid,
            age,
            original_age: None,
        }),
        expected_pdb_name: Some(code_view_file_name(&code_view.path)),
    })
}

fn read_pe_code_view<'data, Pe>(
    data: BoundedPeReader<'data>,
    file: &PeFile<'data, Pe, BoundedPeReader<'data>>,
) -> Result<Option<PeCodeView>, ArtifactErrorCode>
where
    Pe: ImageNtHeaders,
{
    let Some(directory) = file.data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_DEBUG) else {
        return Ok(None);
    };
    let (offset, size) = directory
        .file_range(&file.section_table())
        .map_err(|_| ArtifactErrorCode::Malformed)?;
    if u64::from(size) > MAX_DEBUG_DIRECTORY_BYTES
        || usize::try_from(size)
            .ok()
            .is_none_or(|size| size % IMAGE_DEBUG_DIRECTORY_BYTES != 0)
    {
        return Err(ArtifactErrorCode::Malformed);
    }
    let bytes = data
        .read_bytes_at(u64::from(offset), u64::from(size))
        .map_err(|()| ArtifactErrorCode::Malformed)?;

    for entry in bytes.chunks_exact(IMAGE_DEBUG_DIRECTORY_BYTES) {
        let kind = read_u32_at(entry, 12)?;
        if kind != IMAGE_DEBUG_TYPE_CODEVIEW_VALUE {
            continue;
        }
        let code_view_size = read_u32_at(entry, 16)?;
        let code_view_offset = read_u32_at(entry, 24)?;
        if u64::from(code_view_size) > MAX_CODEVIEW_BYTES {
            return Err(ArtifactErrorCode::Malformed);
        }
        let code_view = data
            .read_bytes_at(u64::from(code_view_offset), u64::from(code_view_size))
            .map_err(|()| ArtifactErrorCode::Malformed)?;
        if code_view.get(..4) != Some(b"RSDS") || code_view.len() < 25 {
            continue;
        }
        let guid = code_view
            .get(4..20)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(ArtifactErrorCode::Malformed)?;
        let age = read_u32_at(code_view, 20)?;
        let path = code_view
            .get(24..)
            .and_then(|bytes| {
                bytes
                    .iter()
                    .position(|byte| *byte == 0)
                    .map(|end| &bytes[..end])
            })
            .ok_or(ArtifactErrorCode::Malformed)?
            .to_vec();
        return Ok(Some(PeCodeView { guid, age, path }));
    }

    Ok(None)
}

fn read_u32_at(bytes: &[u8], offset: usize) -> Result<u32, ArtifactErrorCode> {
    let value = bytes
        .get(offset..offset.saturating_add(4))
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(ArtifactErrorCode::Malformed)?;
    Ok(u32::from_le_bytes(value))
}

fn parse_pdb(mut file: File, size: Option<u64>) -> Result<ParsedArtifact, ArtifactErrorCode> {
    let (machine, original_age) = read_pdb_debug_header(&mut file)?;
    let mut pdb =
        pdb::PDB::open(BoundedPdbSource { file }).map_err(|_| ArtifactErrorCode::Malformed)?;
    let (guid, age) = {
        let information = pdb
            .pdb_information()
            .map_err(|_| ArtifactErrorCode::Malformed)?;
        (*information.guid.as_bytes(), information.age)
    };
    let architecture = pdb_architecture(MachineType::from(machine))?;

    Ok(ParsedArtifact {
        record: ArtifactRecord {
            path: String::new(),
            module: String::new(),
            artifact_type: ArtifactType::Pdb,
            architecture: Some(architecture),
            size,
            debug_id: Some(format_debug_id(&guid, age)),
            code_id: None,
            match_state: MatchState::MissingCompanion,
            matches: Vec::new(),
            error: None,
        },
        identity: Some(Identity {
            guid,
            age,
            original_age: Some(original_age),
        }),
        expected_pdb_name: None,
    })
}

fn read_pdb_debug_header(file: &mut File) -> Result<(u16, u32), ArtifactErrorCode> {
    let file_bytes = file
        .metadata()
        .map_err(|_| ArtifactErrorCode::Malformed)?
        .len();
    let header = read_file_bytes(file, 0, PDB_HEADER_BYTES, file_bytes)?;
    let layout = parse_pdb_layout(&header, file_bytes)?;
    let directory = read_pdb_directory(file, &header, layout)?;
    let debug_page = pdb_stream_first_page(&directory, layout)?;
    let debug_header = read_pdb_pages(
        file,
        &[debug_page],
        layout.page_size,
        PDB_DBI_HEADER_BYTES,
        layout.file_bytes,
    )?;
    if read_u32_at(&debug_header, 0)? != u32::MAX {
        return Err(ArtifactErrorCode::Malformed);
    }
    let original_age = read_u32_at(&debug_header, 8)?;
    let machine = read_u16_at(&debug_header, 58)?;
    Ok((machine, original_age))
}

fn parse_pdb_layout(header: &[u8], file_bytes: u64) -> Result<PdbLayout, ArtifactErrorCode> {
    if header.get(..PDB_MAGIC.len()) != Some(PDB_MAGIC) {
        return Err(ArtifactErrorCode::Malformed);
    }
    let page_size =
        usize::try_from(read_u32_at(header, 32)?).map_err(|_| ArtifactErrorCode::Malformed)?;
    let pages_used =
        usize::try_from(read_u32_at(header, 40)?).map_err(|_| ArtifactErrorCode::Malformed)?;
    let directory_bytes =
        usize::try_from(read_u32_at(header, 44)?).map_err(|_| ArtifactErrorCode::Malformed)?;
    if !page_size.is_power_of_two()
        || !(0x100..=MAX_PDB_PAGE_BYTES).contains(&page_size)
        || pages_used == 0
        || directory_bytes > usize::try_from(MAX_METADATA_READ_BYTES).unwrap_or(usize::MAX)
    {
        return Err(ArtifactErrorCode::Malformed);
    }
    let described_bytes = u64::try_from(pages_used)
        .ok()
        .and_then(|pages| pages.checked_mul(u64::try_from(page_size).ok()?))
        .ok_or(ArtifactErrorCode::Malformed)?;
    if described_bytes > file_bytes {
        return Err(ArtifactErrorCode::Malformed);
    }
    Ok(PdbLayout {
        page_size,
        pages_used,
        directory_bytes,
        file_bytes,
    })
}

fn read_pdb_directory(
    file: &mut File,
    header: &[u8],
    layout: PdbLayout,
) -> Result<Vec<u8>, ArtifactErrorCode> {
    let directory_pages = pages_needed(layout.directory_bytes, layout.page_size)?;
    let block_map_bytes = directory_pages
        .checked_mul(4)
        .ok_or(ArtifactErrorCode::Malformed)?;
    let block_map_pages = pages_needed(block_map_bytes, layout.page_size)?;
    let block_map_end = PDB_RAW_HEADER_BYTES
        .checked_add(
            block_map_pages
                .checked_mul(4)
                .ok_or(ArtifactErrorCode::Malformed)?,
        )
        .ok_or(ArtifactErrorCode::Malformed)?;
    if block_map_end > header.len() {
        return Err(ArtifactErrorCode::Malformed);
    }

    let mut block_map = Vec::new();
    block_map
        .try_reserve_exact(block_map_pages)
        .map_err(|_| ArtifactErrorCode::Malformed)?;
    for index in 0..block_map_pages {
        let offset = PDB_RAW_HEADER_BYTES
            .checked_add(index.checked_mul(4).ok_or(ArtifactErrorCode::Malformed)?)
            .ok_or(ArtifactErrorCode::Malformed)?;
        block_map.push(read_page_number(header, offset, layout.pages_used)?);
    }
    let directory_page_bytes = read_pdb_pages(
        file,
        &block_map,
        layout.page_size,
        block_map_bytes,
        layout.file_bytes,
    )?;
    let mut stream_table_pages = Vec::new();
    stream_table_pages
        .try_reserve_exact(directory_pages)
        .map_err(|_| ArtifactErrorCode::Malformed)?;
    for index in 0..directory_pages {
        let offset = index.checked_mul(4).ok_or(ArtifactErrorCode::Malformed)?;
        stream_table_pages.push(read_page_number(
            &directory_page_bytes,
            offset,
            layout.pages_used,
        )?);
    }
    read_pdb_pages(
        file,
        &stream_table_pages,
        layout.page_size,
        layout.directory_bytes,
        layout.file_bytes,
    )
}

fn pdb_stream_first_page(directory: &[u8], layout: PdbLayout) -> Result<u32, ArtifactErrorCode> {
    let stream_count =
        usize::try_from(read_u32_at(directory, 0)?).map_err(|_| ArtifactErrorCode::Malformed)?;
    if stream_count <= PDB_DBI_STREAM {
        return Err(ArtifactErrorCode::Malformed);
    }
    let stream_sizes_bytes = stream_count
        .checked_mul(4)
        .ok_or(ArtifactErrorCode::Malformed)?;
    let stream_pages_offset = 4_usize
        .checked_add(stream_sizes_bytes)
        .filter(|offset| *offset <= directory.len())
        .ok_or(ArtifactErrorCode::Malformed)?;
    let mut preceding_pages = 0_usize;
    for stream in 0..PDB_DBI_STREAM {
        let size = stream_size(directory, stream)?;
        if size != u32::MAX {
            preceding_pages = preceding_pages
                .checked_add(pages_needed(
                    usize::try_from(size).map_err(|_| ArtifactErrorCode::Malformed)?,
                    layout.page_size,
                )?)
                .ok_or(ArtifactErrorCode::Malformed)?;
        }
    }
    let debug_stream_bytes = stream_size(directory, PDB_DBI_STREAM)?;
    if debug_stream_bytes == u32::MAX
        || debug_stream_bytes < u32::try_from(PDB_DBI_HEADER_BYTES).unwrap_or(u32::MAX)
    {
        return Err(ArtifactErrorCode::Malformed);
    }
    let debug_pages = pages_needed(
        usize::try_from(debug_stream_bytes).map_err(|_| ArtifactErrorCode::Malformed)?,
        layout.page_size,
    )?;
    let first_debug_page_offset = stream_pages_offset
        .checked_add(
            preceding_pages
                .checked_mul(4)
                .ok_or(ArtifactErrorCode::Malformed)?,
        )
        .ok_or(ArtifactErrorCode::Malformed)?;
    let debug_page_list_end = first_debug_page_offset
        .checked_add(
            debug_pages
                .checked_mul(4)
                .ok_or(ArtifactErrorCode::Malformed)?,
        )
        .filter(|end| *end <= directory.len())
        .ok_or(ArtifactErrorCode::Malformed)?;
    let debug_page = read_page_number(directory, first_debug_page_offset, layout.pages_used)?;
    for offset in (first_debug_page_offset..debug_page_list_end).step_by(4) {
        let _ = read_page_number(directory, offset, layout.pages_used)?;
    }
    Ok(debug_page)
}

fn stream_size(directory: &[u8], stream: usize) -> Result<u32, ArtifactErrorCode> {
    let offset = 4_usize
        .checked_add(stream.checked_mul(4).ok_or(ArtifactErrorCode::Malformed)?)
        .ok_or(ArtifactErrorCode::Malformed)?;
    read_u32_at(directory, offset)
}

fn pages_needed(bytes: usize, page_size: usize) -> Result<usize, ArtifactErrorCode> {
    bytes
        .checked_add(page_size.saturating_sub(1))
        .map(|bytes| bytes / page_size)
        .ok_or(ArtifactErrorCode::Malformed)
}

fn read_page_number(
    bytes: &[u8],
    offset: usize,
    pages_used: usize,
) -> Result<u32, ArtifactErrorCode> {
    let page = read_u32_at(bytes, offset)?;
    let page_index = usize::try_from(page).map_err(|_| ArtifactErrorCode::Malformed)?;
    if page_index == 0 || page_index >= pages_used {
        return Err(ArtifactErrorCode::Malformed);
    }
    Ok(page)
}

fn read_pdb_pages(
    file: &mut File,
    pages: &[u32],
    page_size: usize,
    bytes: usize,
    file_bytes: u64,
) -> Result<Vec<u8>, ArtifactErrorCode> {
    let required_pages = pages_needed(bytes, page_size)?;
    if required_pages > pages.len() {
        return Err(ArtifactErrorCode::Malformed);
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(bytes)
        .map_err(|_| ArtifactErrorCode::Malformed)?;
    for page in pages.iter().take(required_pages) {
        let remaining = bytes.saturating_sub(output.len());
        let chunk_bytes = remaining.min(page_size);
        let page_offset = u64::from(*page)
            .checked_mul(u64::try_from(page_size).map_err(|_| ArtifactErrorCode::Malformed)?)
            .ok_or(ArtifactErrorCode::Malformed)?;
        let mut chunk = read_file_bytes(file, page_offset, chunk_bytes, file_bytes)?;
        output.append(&mut chunk);
    }
    Ok(output)
}

fn read_file_bytes(
    file: &mut File,
    offset: u64,
    bytes: usize,
    file_bytes: u64,
) -> Result<Vec<u8>, ArtifactErrorCode> {
    offset
        .checked_add(u64::try_from(bytes).map_err(|_| ArtifactErrorCode::Malformed)?)
        .filter(|end| *end <= file_bytes)
        .ok_or(ArtifactErrorCode::Malformed)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(bytes)
        .map_err(|_| ArtifactErrorCode::Malformed)?;
    output.resize(bytes, 0);
    file.seek(SeekFrom::Start(offset))
        .map_err(|_| ArtifactErrorCode::Malformed)?;
    file.read_exact(&mut output)
        .map_err(|_| ArtifactErrorCode::Malformed)?;
    Ok(output)
}

fn read_u16_at(bytes: &[u8], offset: usize) -> Result<u16, ArtifactErrorCode> {
    let value = bytes
        .get(offset..offset.saturating_add(2))
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(ArtifactErrorCode::Malformed)?;
    Ok(u16::from_le_bytes(value))
}

fn match_artifacts(artifacts: &mut [ParsedArtifact]) {
    for left in 0..artifacts.len() {
        if artifacts[left].record.match_state == MatchState::Invalid {
            continue;
        }

        let mut matches = Vec::new();
        for right in 0..artifacts.len() {
            if left != right && compatible(&artifacts[left], &artifacts[right]) {
                matches.push(artifacts[right].record.path.clone());
            }
        }
        matches.sort();

        artifacts[left].record.match_state = if matches.is_empty() {
            if has_named_mismatch(left, artifacts) {
                MatchState::Mismatched
            } else {
                MatchState::MissingCompanion
            }
        } else {
            MatchState::Matched
        };
        artifacts[left].record.matches = matches;
    }
}

fn compatible(left: &ParsedArtifact, right: &ParsedArtifact) -> bool {
    let (pe, pdb) = match (left.record.artifact_type, right.record.artifact_type) {
        (ArtifactType::PeExecutable | ArtifactType::PeDynamicLibrary, ArtifactType::Pdb) => {
            (left, right)
        }
        (ArtifactType::Pdb, ArtifactType::PeExecutable | ArtifactType::PeDynamicLibrary) => {
            (right, left)
        }
        _ => return false,
    };
    let (Some(pe_identity), Some(pdb_identity)) = (&pe.identity, &pdb.identity) else {
        return false;
    };

    pe.record.architecture == pdb.record.architecture
        && pe_identity.guid == pdb_identity.guid
        && pdb_identity.age >= pe_identity.age
        && pdb_identity
            .original_age
            .is_none_or(|age| age == pe_identity.age)
}

fn has_named_mismatch(index: usize, artifacts: &[ParsedArtifact]) -> bool {
    let artifact = &artifacts[index];
    artifacts.iter().enumerate().any(|(other_index, other)| {
        if index == other_index || other.record.match_state == MatchState::Invalid {
            return false;
        }
        match (artifact.record.artifact_type, other.record.artifact_type) {
            (ArtifactType::PeExecutable | ArtifactType::PeDynamicLibrary, ArtifactType::Pdb) => {
                artifact
                    .expected_pdb_name
                    .as_deref()
                    .is_some_and(|name| name.eq_ignore_ascii_case(&other.record.module))
            }
            (ArtifactType::Pdb, ArtifactType::PeExecutable | ArtifactType::PeDynamicLibrary) => {
                other
                    .expected_pdb_name
                    .as_deref()
                    .is_some_and(|name| name.eq_ignore_ascii_case(&artifact.record.module))
            }
            _ => false,
        }
    })
}

fn inferred_artifact_type(path: &Path) -> ArtifactType {
    if path
        .extension()
        .and_then(OsStr::to_str)
        .is_some_and(|extension| extension.eq_ignore_ascii_case("pdb"))
    {
        ArtifactType::Pdb
    } else if path
        .extension()
        .and_then(OsStr::to_str)
        .is_some_and(|extension| extension.eq_ignore_ascii_case("dll"))
    {
        ArtifactType::PeDynamicLibrary
    } else {
        ArtifactType::PeExecutable
    }
}

fn object_architecture(
    architecture: ObjectArchitecture,
) -> Result<Architecture, ArtifactErrorCode> {
    match architecture {
        ObjectArchitecture::I386 => Ok(Architecture::X86),
        ObjectArchitecture::X86_64 => Ok(Architecture::X86_64),
        ObjectArchitecture::Aarch64 => Ok(Architecture::Arm64),
        _ => Err(ArtifactErrorCode::UnsupportedArchitecture),
    }
}

fn pdb_architecture(machine: MachineType) -> Result<Architecture, ArtifactErrorCode> {
    match machine {
        MachineType::X86 => Ok(Architecture::X86),
        MachineType::Amd64 => Ok(Architecture::X86_64),
        MachineType::Arm64 => Ok(Architecture::Arm64),
        _ => Err(ArtifactErrorCode::UnsupportedArchitecture),
    }
}

fn canonical_pe_guid(raw: [u8; 16]) -> [u8; 16] {
    [
        raw[3], raw[2], raw[1], raw[0], raw[5], raw[4], raw[7], raw[6], raw[8], raw[9], raw[10],
        raw[11], raw[12], raw[13], raw[14], raw[15],
    ]
}

fn format_debug_id(guid: &[u8; 16], age: u32) -> String {
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}-{age:X}",
        guid[0],
        guid[1],
        guid[2],
        guid[3],
        guid[4],
        guid[5],
        guid[6],
        guid[7],
        guid[8],
        guid[9],
        guid[10],
        guid[11],
        guid[12],
        guid[13],
        guid[14],
        guid[15],
    )
}

fn code_view_file_name(path: &[u8]) -> String {
    String::from_utf8_lossy(path)
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .to_owned()
}

fn normalize_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy()
        .into_owned()
}

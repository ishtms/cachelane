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

pub const ARTIFACT_SCAN_SCHEMA_VERSION: u32 = 1;
const MAX_METADATA_READ_BYTES: u64 = 16 * 1024 * 1024;

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

#[derive(Debug)]
pub enum ScanError {
    InspectRoot(io::Error),
    ReadDirectory(io::Error),
}

impl fmt::Display for ScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InspectRoot(_) => write!(formatter, "failed to inspect artifact path"),
            Self::ReadDirectory(_) => write!(formatter, "failed to read artifact directory"),
        }
    }
}

impl std::error::Error for ScanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InspectRoot(error) | Self::ReadDirectory(error) => Some(error),
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
    let metadata = fs::symlink_metadata(root).map_err(ScanError::InspectRoot)?;
    let mut files = Vec::new();

    if metadata.file_type().is_file() {
        if supported_extension(root) {
            files.push((PathBuf::from(root), file_name(root)));
        }
    } else if metadata.file_type().is_dir() {
        discover_files(root, Path::new(""), &mut files)?;
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
    relative: &Path,
    files: &mut Vec<(PathBuf, String)>,
) -> Result<(), ScanError> {
    let directory = root.join(relative);
    let entries = fs::read_dir(directory).map_err(ScanError::ReadDirectory)?;

    for entry in entries {
        let entry = entry.map_err(ScanError::ReadDirectory)?;
        let file_type = entry.file_type().map_err(ScanError::ReadDirectory)?;
        let child_relative = relative.join(entry.file_name());
        if file_type.is_dir() {
            discover_files(root, &child_relative, files)?;
        } else if file_type.is_file() && supported_extension(&child_relative) {
            files.push((entry.path(), normalize_path(&child_relative)));
        }
    }

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
    let code_view = file
        .pdb_info()
        .map_err(|_| ArtifactErrorCode::Malformed)?
        .ok_or(ArtifactErrorCode::MissingDebugIdentity)?;
    let guid = canonical_pe_guid(code_view.guid());
    let age = code_view.age();
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
        expected_pdb_name: Some(code_view_file_name(code_view.path())),
    })
}

fn parse_pdb(file: File, size: Option<u64>) -> Result<ParsedArtifact, ArtifactErrorCode> {
    let mut pdb =
        pdb::PDB::open(BoundedPdbSource { file }).map_err(|_| ArtifactErrorCode::Malformed)?;
    let (guid, age) = {
        let information = pdb
            .pdb_information()
            .map_err(|_| ArtifactErrorCode::Malformed)?;
        (*information.guid.as_bytes(), information.age)
    };
    let debug_information = pdb
        .debug_information()
        .map_err(|_| ArtifactErrorCode::Malformed)?;
    let architecture = pdb_architecture(
        debug_information
            .machine_type()
            .map_err(|_| ArtifactErrorCode::Malformed)?,
    )?;
    let original_age = debug_information.age();

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
            original_age,
        }),
        expected_pdb_name: None,
    })
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

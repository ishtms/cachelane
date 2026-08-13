use std::{
    cell::Cell,
    collections::{BTreeSet, HashSet},
    error::Error,
    fmt,
    io::{self, BufRead, BufReader, Read},
    path::Path,
    rc::Rc,
};

use flate2::bufread::ZlibDecoder;
use serde::Serialize;

use crate::{CrashContextParser, ParseError};

const ENVELOPE_MAGIC: &[u8; 3] = b"CR1";
const ANSI_FIELD_BYTES: usize = 260;
const READ_BUFFER_BYTES: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CrashRequestLimits {
    pub compressed_bytes: u64,
    pub expanded_bytes: u64,
    pub expansion_ratio: u64,
    pub files: u32,
    pub file_bytes: u64,
    pub crash_context_bytes: u64,
    pub crash_context_nodes: u32,
}

impl Default for CrashRequestLimits {
    fn default() -> Self {
        Self {
            compressed_bytes: 64 * 1024 * 1024,
            expanded_bytes: 256 * 1024 * 1024,
            expansion_ratio: 200,
            files: 128,
            file_bytes: 128 * 1024 * 1024,
            crash_context_bytes: 4 * 1024 * 1024,
            crash_context_nodes: 100_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrashRequestFileKind {
    CrashContext,
    Minidump,
    Log,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CrashRequestFile {
    pub index: u32,
    pub name: String,
    pub size: u64,
    pub kind: CrashRequestFileKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CrashRequestManifest {
    pub schema_version: u32,
    pub envelope: &'static str,
    pub directory_name: String,
    pub archive_name: String,
    pub compressed_size: u64,
    pub expanded_size: u64,
    pub files: Vec<CrashRequestFile>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrashRequestErrorKind {
    ReadFailed,
    CompressedTooLarge,
    InvalidCompression,
    ExpandedTooLarge,
    ExpansionRatioExceeded,
    UnsupportedEnvelope,
    InvalidHeader,
    TooManyFiles,
    FileTooLarge,
    UnsafeFilename,
    DuplicateCriticalFile,
    InvalidCrashContextUtf8,
    InvalidCrashContext,
    TruncatedArchive,
    TrailingData,
    ExpandedSizeMismatch,
    FileCountMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CrashRequestError {
    kind: CrashRequestErrorKind,
    xml_error: Option<ParseError>,
}

impl CrashRequestError {
    const fn new(kind: CrashRequestErrorKind) -> Self {
        Self {
            kind,
            xml_error: None,
        }
    }

    const fn xml(error: ParseError) -> Self {
        Self {
            kind: CrashRequestErrorKind::InvalidCrashContext,
            xml_error: Some(error),
        }
    }

    #[must_use]
    pub const fn kind(self) -> CrashRequestErrorKind {
        self.kind
    }
}

impl fmt::Display for CrashRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(error) = self.xml_error {
            return error.fmt(formatter);
        }

        let message = match self.kind {
            CrashRequestErrorKind::ReadFailed => "failed to read crash request",
            CrashRequestErrorKind::CompressedTooLarge => "compressed crash request limit exceeded",
            CrashRequestErrorKind::InvalidCompression => "invalid crash request compression",
            CrashRequestErrorKind::ExpandedTooLarge => "expanded crash request limit exceeded",
            CrashRequestErrorKind::ExpansionRatioExceeded => {
                "crash request expansion ratio limit exceeded"
            }
            CrashRequestErrorKind::UnsupportedEnvelope => "unsupported crash request envelope",
            CrashRequestErrorKind::InvalidHeader => "invalid crash request header",
            CrashRequestErrorKind::TooManyFiles => "crash request file count limit exceeded",
            CrashRequestErrorKind::FileTooLarge => "crash request file size limit exceeded",
            CrashRequestErrorKind::UnsafeFilename => "unsafe crash request filename",
            CrashRequestErrorKind::DuplicateCriticalFile => "duplicate critical crash file",
            CrashRequestErrorKind::InvalidCrashContextUtf8 => "crash context must be UTF-8",
            CrashRequestErrorKind::InvalidCrashContext => "invalid crash context XML",
            CrashRequestErrorKind::TruncatedArchive => "truncated crash request archive",
            CrashRequestErrorKind::TrailingData => "trailing data after crash request stream",
            CrashRequestErrorKind::ExpandedSizeMismatch => "crash request expanded size mismatch",
            CrashRequestErrorKind::FileCountMismatch => "crash request file count mismatch",
        };

        formatter.write_str(message)
    }
}

impl Error for CrashRequestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.xml_error
            .as_ref()
            .map(|error| error as &(dyn Error + 'static))
    }
}

#[derive(Debug)]
struct ReadLimitError(CrashRequestErrorKind);

impl fmt::Display for ReadLimitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("crash request read limit exceeded")
    }
}

impl Error for ReadLimitError {}

struct CompressedReader<R> {
    inner: R,
    limit: u64,
    bytes_read: Rc<Cell<u64>>,
}

impl<R: Read> CompressedReader<R> {
    fn new(inner: R, limit: u64, bytes_read: Rc<Cell<u64>>) -> Self {
        Self {
            inner,
            limit,
            bytes_read,
        }
    }
}

impl<R: Read> Read for CompressedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }

        let read = self.bytes_read.get();
        if read == self.limit {
            let mut extra = [0_u8; 1];
            return match self.inner.read(&mut extra)? {
                0 => Ok(0),
                _ => Err(limit_error(CrashRequestErrorKind::CompressedTooLarge)),
            };
        }

        let remaining = self.limit - read;
        let buffer_length = u64::try_from(buffer.len()).unwrap_or(u64::MAX);
        let allowed = usize::try_from(remaining.min(buffer_length)).unwrap_or(buffer.len());
        let count = self.inner.read(&mut buffer[..allowed])?;
        let count = u64::try_from(count).unwrap_or(u64::MAX);
        self.bytes_read.set(read.saturating_add(count));
        usize::try_from(count).map_err(io::Error::other)
    }
}

struct ExpandedReader<R> {
    inner: R,
    limit: u64,
    ratio: u64,
    bytes_read: u64,
    compressed_bytes_read: Rc<Cell<u64>>,
}

impl<R: Read> ExpandedReader<R> {
    fn new(inner: R, limit: u64, ratio: u64, compressed_bytes_read: Rc<Cell<u64>>) -> Self {
        Self {
            inner,
            limit,
            ratio,
            bytes_read: 0,
            compressed_bytes_read,
        }
    }

    const fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for ExpandedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }

        if self.bytes_read == self.limit {
            let mut extra = [0_u8; 1];
            return match self.inner.read(&mut extra)? {
                0 => Ok(0),
                _ => Err(limit_error(CrashRequestErrorKind::ExpandedTooLarge)),
            };
        }

        let remaining = self.limit - self.bytes_read;
        let buffer_length = u64::try_from(buffer.len()).unwrap_or(u64::MAX);
        let allowed = usize::try_from(remaining.min(buffer_length)).unwrap_or(buffer.len());
        let count = self.inner.read(&mut buffer[..allowed])?;
        let count = u64::try_from(count).unwrap_or(u64::MAX);
        self.bytes_read = self.bytes_read.saturating_add(count);

        let ratio_limit = self.compressed_bytes_read.get().saturating_mul(self.ratio);
        if self.bytes_read > ratio_limit {
            return Err(limit_error(CrashRequestErrorKind::ExpansionRatioExceeded));
        }

        usize::try_from(count).map_err(io::Error::other)
    }
}

fn limit_error(kind: CrashRequestErrorKind) -> io::Error {
    io::Error::other(ReadLimitError(kind))
}

fn map_read_error(error: &io::Error) -> CrashRequestError {
    if let Some(limit) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<ReadLimitError>())
    {
        return CrashRequestError::new(limit.0);
    }

    let kind = match error.kind() {
        io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput => {
            CrashRequestErrorKind::InvalidCompression
        }
        io::ErrorKind::UnexpectedEof => CrashRequestErrorKind::TruncatedArchive,
        _ => CrashRequestErrorKind::ReadFailed,
    };
    CrashRequestError::new(kind)
}

fn read_exact(reader: &mut impl Read, output: &mut [u8]) -> Result<(), CrashRequestError> {
    reader
        .read_exact(output)
        .map_err(|error| map_read_error(&error))
}

fn read_i32(reader: &mut impl Read) -> Result<i32, CrashRequestError> {
    let mut bytes = [0_u8; 4];
    read_exact(reader, &mut bytes)?;
    Ok(i32::from_le_bytes(bytes))
}

fn read_count(reader: &mut impl Read) -> Result<u64, CrashRequestError> {
    let value = read_i32(reader)?;
    u64::try_from(value).map_err(|_| CrashRequestError::new(CrashRequestErrorKind::InvalidHeader))
}

fn read_ansi_field(reader: &mut impl Read) -> Result<String, CrashRequestError> {
    let length = read_i32(reader)?;
    if length != i32::try_from(ANSI_FIELD_BYTES).unwrap_or(i32::MAX) {
        return Err(CrashRequestError::new(CrashRequestErrorKind::InvalidHeader));
    }

    let mut bytes = [0_u8; ANSI_FIELD_BYTES];
    read_exact(reader, &mut bytes)?;
    let value_length = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if bytes[value_length..].iter().any(|byte| *byte != 0) {
        return Err(CrashRequestError::new(CrashRequestErrorKind::InvalidHeader));
    }

    let value = std::str::from_utf8(&bytes[..value_length])
        .map_err(|_| CrashRequestError::new(CrashRequestErrorKind::UnsafeFilename))?;
    if !safe_leaf_name(value) {
        return Err(CrashRequestError::new(
            CrashRequestErrorKind::UnsafeFilename,
        ));
    }

    Ok(value.to_owned())
}

fn safe_leaf_name(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value.ends_with(['.', ' '])
        && value
            .bytes()
            .all(|byte| (0x20..=0x7e).contains(&byte) && !b"<>:\"/\\|?*".contains(&byte))
}

fn file_kind(name: &str) -> CrashRequestFileKind {
    if name.eq_ignore_ascii_case("crashcontext.runtime-xml") {
        CrashRequestFileKind::CrashContext
    } else if Path::new(name)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("dmp"))
    {
        CrashRequestFileKind::Minidump
    } else if Path::new(name)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("log"))
    {
        CrashRequestFileKind::Log
    } else {
        CrashRequestFileKind::Unknown
    }
}

fn discard(reader: &mut impl Read, size: u64) -> Result<(), CrashRequestError> {
    let mut remaining = size;
    let mut buffer = [0_u8; READ_BUFFER_BYTES];

    while remaining > 0 {
        let buffer_length = u64::try_from(buffer.len()).unwrap_or(u64::MAX);
        let count = usize::try_from(remaining.min(buffer_length)).unwrap_or(buffer.len());
        read_exact(reader, &mut buffer[..count])?;
        remaining -= u64::try_from(count).unwrap_or(remaining);
    }

    Ok(())
}

fn inspect_files(
    expanded: &mut impl Read,
    file_count: u64,
    limits: CrashRequestLimits,
) -> Result<Vec<CrashRequestFile>, CrashRequestError> {
    let file_capacity = usize::try_from(file_count)
        .map_err(|_| CrashRequestError::new(CrashRequestErrorKind::TooManyFiles))?;
    let mut files = Vec::with_capacity(file_capacity);
    let mut critical_files = BTreeSet::new();
    let mut filenames = HashSet::new();

    for expected_index in 0..file_count {
        let index = read_count(expanded)?;
        if index != expected_index {
            return Err(CrashRequestError::new(
                CrashRequestErrorKind::FileCountMismatch,
            ));
        }

        let name = read_ansi_field(expanded)?;
        let kind = file_kind(&name);
        if matches!(
            kind,
            CrashRequestFileKind::CrashContext | CrashRequestFileKind::Minidump
        ) && !critical_files.insert(kind)
        {
            return Err(CrashRequestError::new(
                CrashRequestErrorKind::DuplicateCriticalFile,
            ));
        }
        if !filenames.insert(name.to_ascii_lowercase()) {
            return Err(CrashRequestError::new(
                CrashRequestErrorKind::DuplicateCriticalFile,
            ));
        }

        let size = read_count(expanded)?;
        if size > limits.file_bytes {
            return Err(CrashRequestError::new(CrashRequestErrorKind::FileTooLarge));
        }

        if kind == CrashRequestFileKind::CrashContext {
            validate_crash_context(expanded, size, limits)?;
        } else {
            discard(expanded, size)?;
        }

        let index = u32::try_from(index)
            .map_err(|_| CrashRequestError::new(CrashRequestErrorKind::FileCountMismatch))?;
        files.push(CrashRequestFile {
            index,
            name,
            size,
            kind,
        });
    }

    Ok(files)
}

fn validate_crash_context(
    reader: &mut impl Read,
    size: u64,
    limits: CrashRequestLimits,
) -> Result<(), CrashRequestError> {
    if size > limits.crash_context_bytes {
        return Err(CrashRequestError::new(CrashRequestErrorKind::FileTooLarge));
    }

    let size = usize::try_from(size)
        .map_err(|_| CrashRequestError::new(CrashRequestErrorKind::FileTooLarge))?;
    let mut bytes = vec![0_u8; size];
    read_exact(reader, &mut bytes)?;
    let xml = std::str::from_utf8(&bytes)
        .map_err(|_| CrashRequestError::new(CrashRequestErrorKind::InvalidCrashContextUtf8))?;
    CrashContextParser::new(limits.crash_context_nodes)
        .parse(xml)
        .map_err(CrashRequestError::xml)?;
    Ok(())
}

/// Inspects one UE 5.8 Crash Report Client request body without retaining all expanded files.
///
/// # Errors
///
/// Returns a typed safe error when the compressed stream, archive metadata, filename, resource
/// limit, or crash context is invalid.
pub fn inspect_crash_request<R: Read>(
    input: R,
    limits: CrashRequestLimits,
) -> Result<CrashRequestManifest, CrashRequestError> {
    let compressed_bytes_read = Rc::new(Cell::new(0));
    let compressed = CompressedReader::new(
        input,
        limits.compressed_bytes,
        Rc::clone(&compressed_bytes_read),
    );
    let decoder = ZlibDecoder::new(BufReader::new(compressed));
    let mut expanded = ExpandedReader::new(
        decoder,
        limits.expanded_bytes,
        limits.expansion_ratio,
        Rc::clone(&compressed_bytes_read),
    );

    let mut magic = [0_u8; ENVELOPE_MAGIC.len()];
    read_exact(&mut expanded, &mut magic)?;
    if magic != *ENVELOPE_MAGIC {
        return Err(CrashRequestError::new(
            CrashRequestErrorKind::UnsupportedEnvelope,
        ));
    }

    let directory_name = read_ansi_field(&mut expanded)?;
    let archive_name = read_ansi_field(&mut expanded)?;
    let reported_expanded_size = read_count(&mut expanded)?;
    if reported_expanded_size > limits.expanded_bytes {
        return Err(CrashRequestError::new(
            CrashRequestErrorKind::ExpandedTooLarge,
        ));
    }

    let reported_file_count = read_count(&mut expanded)?;
    if reported_file_count > u64::from(limits.files) {
        return Err(CrashRequestError::new(CrashRequestErrorKind::TooManyFiles));
    }

    let files = inspect_files(&mut expanded, reported_file_count, limits)?;

    let mut extra = [0_u8; 1];
    if expanded
        .read(&mut extra)
        .map_err(|error| map_read_error(&error))?
        != 0
    {
        return Err(CrashRequestError::new(
            CrashRequestErrorKind::ExpandedSizeMismatch,
        ));
    }

    let expanded_size = expanded.bytes_read();
    if expanded_size != reported_expanded_size {
        return Err(CrashRequestError::new(
            CrashRequestErrorKind::ExpandedSizeMismatch,
        ));
    }

    let decoder = expanded.into_inner();
    let mut compressed = decoder.into_inner();
    if !compressed
        .fill_buf()
        .map_err(|error| map_read_error(&error))?
        .is_empty()
    {
        return Err(CrashRequestError::new(CrashRequestErrorKind::TrailingData));
    }

    Ok(CrashRequestManifest {
        schema_version: 1,
        envelope: "cr1",
        directory_name,
        archive_name,
        compressed_size: compressed_bytes_read.get(),
        expanded_size,
        files,
    })
}

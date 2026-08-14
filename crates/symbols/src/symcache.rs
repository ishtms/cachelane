use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use symbolic_common::{ByteView, DebugId};
use symbolic_debuginfo::{FileFormat, Object};
use symbolic_symcache::{SYMCACHE_VERSION, SymCache, SymCacheConverter};

use crate::{
    FrameSymbolStatus, InlineSymbol, ModuleSymbolStatus, SymbolicationError, SymbolicationLimits,
    SymbolicationResult, symbolicate_minidump_bytes,
};

pub const SYMCACHE_FORMAT_VERSION: u32 = SYMCACHE_VERSION;
pub const SYMCACHE_PROCESSOR_VERSION: &str = "symbolic-symcache-13.3.1";
const MAX_SYMCACHE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SymCacheArtifact {
    pub debug_id: String,
    pub path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SymCacheMetadata {
    pub schema_version: u32,
    pub processor_version: &'static str,
    pub format_version: u32,
    pub debug_id: String,
    pub architecture: String,
    pub byte_size: u64,
}

#[derive(Debug)]
pub enum SymCacheGenerationError {
    InvalidInput,
    InputTooLarge,
    InvalidDebugFile,
    ConversionFailed,
    OutputTooLarge,
    WriteFailed,
}

impl fmt::Display for SymCacheGenerationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "invalid debug artifact",
            Self::InputTooLarge => "debug artifact size limit exceeded",
            Self::InvalidDebugFile => "debug artifact could not be parsed",
            Self::ConversionFailed => "derived symbol cache generation failed",
            Self::OutputTooLarge => "derived symbol cache size limit exceeded",
            Self::WriteFailed => "derived symbol cache could not be written",
        })
    }
}

impl std::error::Error for SymCacheGenerationError {}

/// Converts one PDB into the current `SymCache` format.
///
/// # Errors
///
/// Returns an error when the input is invalid or exceeds its limit, conversion fails, or the
/// output cannot be published within its limit.
pub fn generate_symcache(
    input: &Path,
    output: &Path,
    maximum_input_bytes: u64,
) -> Result<SymCacheMetadata, SymCacheGenerationError> {
    let metadata =
        fs::symlink_metadata(input).map_err(|_| SymCacheGenerationError::InvalidInput)?;
    if !metadata.is_file() {
        return Err(SymCacheGenerationError::InvalidInput);
    }
    if metadata.len() > maximum_input_bytes {
        return Err(SymCacheGenerationError::InputTooLarge);
    }

    let view = ByteView::open(input).map_err(|_| SymCacheGenerationError::InvalidInput)?;
    let object = Object::parse(&view).map_err(|_| SymCacheGenerationError::InvalidDebugFile)?;
    if object.file_format() != FileFormat::Pdb {
        return Err(SymCacheGenerationError::InvalidDebugFile);
    }
    let mut converter = SymCacheConverter::new();
    converter
        .process_object(&object)
        .map_err(|_| SymCacheGenerationError::ConversionFailed)?;
    let mut bytes = Vec::new();
    converter
        .serialize(&mut bytes)
        .map_err(|_| SymCacheGenerationError::ConversionFailed)?;
    if u64::try_from(bytes.len()).map_err(|_| SymCacheGenerationError::OutputTooLarge)?
        > MAX_SYMCACHE_BYTES
    {
        return Err(SymCacheGenerationError::OutputTooLarge);
    }
    let cache = SymCache::parse(&bytes).map_err(|_| SymCacheGenerationError::ConversionFailed)?;
    if !cache.is_latest() {
        return Err(SymCacheGenerationError::ConversionFailed);
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|_| SymCacheGenerationError::WriteFailed)?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| SymCacheGenerationError::WriteFailed)?;

    Ok(SymCacheMetadata {
        schema_version: 1,
        processor_version: SYMCACHE_PROCESSOR_VERSION,
        format_version: cache.version(),
        debug_id: cache.debug_id().to_string().to_ascii_uppercase(),
        architecture: cache.arch().to_string(),
        byte_size: u64::try_from(bytes.len())
            .map_err(|_| SymCacheGenerationError::OutputTooLarge)?,
    })
}

/// Unwinds a minidump from PE files and resolves frames from exact `SymCaches`.
///
/// # Errors
///
/// Returns an error when minidump processing fails or a selected cache is invalid, oversized, or
/// has the wrong embedded identity.
pub fn symbolicate_minidump_bytes_with_symcaches(
    dump: Vec<u8>,
    symbols: &Path,
    symcaches: &[SymCacheArtifact],
    limits: SymbolicationLimits,
) -> Result<SymbolicationResult, SymbolicationError> {
    let mut result = symbolicate_minidump_bytes(dump, symbols, limits)?;
    let mut artifacts = BTreeMap::new();
    for artifact in symcaches {
        let debug_id = DebugId::from_str(&artifact.debug_id)
            .map_err(|_| SymbolicationError::InvalidSymCache)?;
        if artifacts.insert(debug_id, artifact).is_some() {
            return Err(SymbolicationError::InvalidSymCache);
        }
    }

    for module_index in 0..result.modules.len() {
        let Some(debug_id) = result.modules[module_index]
            .debug_id
            .as_deref()
            .and_then(|value| DebugId::from_str(value).ok())
        else {
            continue;
        };
        let Some(artifact) = artifacts.get(&debug_id) else {
            continue;
        };
        let bytes = read_cache(&artifact.path)?;
        let cache = SymCache::parse(&bytes).map_err(|_| SymbolicationError::InvalidSymCache)?;
        if cache.debug_id() != debug_id || !cache.is_latest() {
            return Err(SymbolicationError::SymCacheIdentityMismatch);
        }
        let module_name = result.modules[module_index].module.clone();
        let mut resolved = false;
        for thread in &mut result.threads {
            for frame in &mut thread.frames {
                if frame
                    .module
                    .as_deref()
                    .is_none_or(|value| !value.eq_ignore_ascii_case(&module_name))
                {
                    continue;
                }
                let Some(address) = frame
                    .module_relative
                    .as_deref()
                    .and_then(parse_relative_address)
                else {
                    continue;
                };
                let mut locations = cache.lookup(address);
                let Some(location) = locations.next() else {
                    continue;
                };
                let function = location.function().name().to_owned();
                if function.is_empty() || function == "?" {
                    continue;
                }
                frame.function = Some(function);
                frame.source_file = location.file().map(|file| file.full_path());
                frame.source_line = (location.line() > 0).then(|| location.line());
                frame.inlines = locations
                    .filter_map(|inline| {
                        let function = inline.function().name().to_owned();
                        (!function.is_empty() && function != "?").then(|| InlineSymbol {
                            function,
                            source_file: inline.file().map(|file| file.full_path()),
                            source_line: (inline.line() > 0).then(|| inline.line()),
                        })
                    })
                    .collect();
                frame.symbol_status = FrameSymbolStatus::Resolved;
                resolved = true;
            }
        }
        if resolved && result.modules[module_index].pe.is_some() {
            result.modules[module_index].status = ModuleSymbolStatus::Matched;
            result.modules[module_index].symcache_format = Some(cache.version());
        }
    }

    Ok(result)
}

fn read_cache(path: &Path) -> Result<Vec<u8>, SymbolicationError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| SymbolicationError::InvalidSymCache)?;
    if !metadata.is_file() {
        return Err(SymbolicationError::InvalidSymCache);
    }
    if metadata.len() > MAX_SYMCACHE_BYTES {
        return Err(SymbolicationError::SymCacheTooLarge);
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| SymbolicationError::InvalidSymCache)?
        .take(MAX_SYMCACHE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SymbolicationError::InvalidSymCache)?;
    if u64::try_from(bytes.len()).map_err(|_| SymbolicationError::SymCacheTooLarge)?
        > MAX_SYMCACHE_BYTES
    {
        return Err(SymbolicationError::SymCacheTooLarge);
    }
    Ok(bytes)
}

fn parse_relative_address(value: &str) -> Option<u64> {
    u64::from_str_radix(value.strip_prefix("0x")?, 16).ok()
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use crate::{
        ArtifactType, SYMCACHE_FORMAT_VERSION, SymCacheArtifact, SymbolicationLimits,
        generate_symcache, scan_artifacts, symbolicate_minidump_bytes_with_symcaches,
    };

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "faultlane-symcache-test-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&path)
                .unwrap_or_else(|error| panic!("test directory must be created: {error}"));
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fixture_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../apps/cli/tests/fixtures/windows-symbolication")
    }

    fn fixture_debug_id() -> String {
        scan_artifacts(&fixture_root())
            .unwrap_or_else(|error| panic!("fixture scan must pass: {error}"))
            .artifacts
            .into_iter()
            .find(|artifact| artifact.artifact_type == ArtifactType::Pdb)
            .and_then(|artifact| artifact.debug_id)
            .unwrap_or_else(|| panic!("fixture PDB must have a debug identity"))
    }

    #[test]
    fn generated_cache_resolves_the_fixture_without_the_original_pdb() {
        let fixture = fixture_root();
        let temp = TestDirectory::new();
        let symbols = temp.path().join("symbols");
        fs::create_dir(&symbols)
            .unwrap_or_else(|error| panic!("symbol directory must be created: {error}"));
        fs::copy(
            fixture.join("faultlane-symbolication.exe"),
            symbols.join("faultlane-symbolication.exe"),
        )
        .unwrap_or_else(|error| panic!("fixture PE must be copied: {error}"));
        let cache_path = temp.path().join("fixture.symcache");
        let metadata = generate_symcache(
            &fixture.join("faultlane-symbolication.pdb"),
            &cache_path,
            1024 * 1024 * 1024,
        )
        .unwrap_or_else(|error| panic!("fixture cache must be generated: {error}"));
        let expected_debug_id = fixture_debug_id();
        assert_eq!(metadata.debug_id, expected_debug_id);
        assert_eq!(metadata.format_version, SYMCACHE_FORMAT_VERSION);

        let dump = fs::read(fixture.join("faultlane-symbolication.dmp"))
            .unwrap_or_else(|error| panic!("fixture dump must be read: {error}"));
        let result = symbolicate_minidump_bytes_with_symcaches(
            dump.clone(),
            &symbols,
            &[SymCacheArtifact {
                debug_id: expected_debug_id.clone(),
                path: cache_path.clone(),
            }],
            SymbolicationLimits::default(),
        )
        .unwrap_or_else(|error| panic!("fixture must symbolicate from the cache: {error}"));

        assert!(result.modules.iter().any(|module| {
            module.symcache_format == Some(SYMCACHE_FORMAT_VERSION)
                && module
                    .module
                    .eq_ignore_ascii_case("faultlane-symbolication.exe")
        }));
        assert!(
            result
                .threads
                .iter()
                .flat_map(|thread| &thread.frames)
                .any(|frame| {
                    frame
                        .function
                        .as_deref()
                        .is_some_and(|function| function.contains("CrashFixture"))
                        || frame
                            .inlines
                            .iter()
                            .any(|inline| inline.function.contains("CrashFixture"))
                }),
            "{result:#?}"
        );

        let duplicate = SymCacheArtifact {
            debug_id: expected_debug_id,
            path: cache_path,
        };
        let result = symbolicate_minidump_bytes_with_symcaches(
            dump,
            &symbols,
            &[duplicate.clone(), duplicate],
            SymbolicationLimits::default(),
        );
        let Err(error) = result else {
            panic!("duplicate cache identities must fail");
        };
        assert_eq!(error.kind(), crate::SymbolicationErrorKind::InvalidSymCache);
    }

    #[test]
    fn corrupt_cache_is_rejected() {
        let fixture = fixture_root();
        let temp = TestDirectory::new();
        let symbols = temp.path().join("symbols");
        fs::create_dir(&symbols)
            .unwrap_or_else(|error| panic!("symbol directory must be created: {error}"));
        fs::copy(
            fixture.join("faultlane-symbolication.exe"),
            symbols.join("faultlane-symbolication.exe"),
        )
        .unwrap_or_else(|error| panic!("fixture PE must be copied: {error}"));
        let cache_path = temp.path().join("corrupt.symcache");
        fs::write(&cache_path, b"not a symcache")
            .unwrap_or_else(|error| panic!("corrupt cache must be written: {error}"));
        let dump = fs::read(fixture.join("faultlane-symbolication.dmp"))
            .unwrap_or_else(|error| panic!("fixture dump must be read: {error}"));

        let result = symbolicate_minidump_bytes_with_symcaches(
            dump,
            &symbols,
            &[SymCacheArtifact {
                debug_id: fixture_debug_id(),
                path: cache_path,
            }],
            SymbolicationLimits::default(),
        );
        let Err(error) = result else {
            panic!("corrupt cache must fail");
        };

        assert_eq!(error.kind(), crate::SymbolicationErrorKind::InvalidSymCache);
    }
}

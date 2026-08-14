use std::{
    fmt,
    fs::File,
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
};

use clap::Subcommand;
use faultlane_processing::process_crash_request;
use faultlane_symbols::{
    ArtifactScanLimits, ArtifactType, SymCacheArtifact, generate_symcache,
    scan_artifacts_with_limits,
};
use serde::Deserialize;

const INPUT_ROOT: &str = "/input";
const SCRATCH_ROOT: &str = "/scratch";
const MAX_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_PREVIOUS_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Copy, Subcommand)]
pub(crate) enum ProcessorCommand {
    IndexPdb,
    IndexExe,
    IndexDll,
    GenerateSymcache,
    ProcessCrash,
}

#[derive(Debug)]
pub(crate) enum ProcessorError {
    InvalidInput,
    Scan,
    SymCache,
    Crash,
    Serialize,
    Write,
}

impl fmt::Display for ProcessorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "processor input is invalid",
            Self::Scan => "artifact indexing failed",
            Self::SymCache => "symbol cache generation failed",
            Self::Crash => "crash processing failed",
            Self::Serialize => "processor output could not be serialized",
            Self::Write => "processor output could not be written",
        })
    }
}

pub(crate) fn run(command: ProcessorCommand) -> Result<(), ProcessorError> {
    let input = Path::new(INPUT_ROOT);
    let scratch = Path::new(SCRATCH_ROOT);
    match command {
        ProcessorCommand::IndexPdb => index(&input.join("artifact.pdb"), ArtifactType::Pdb),
        ProcessorCommand::IndexExe => {
            index(&input.join("artifact.exe"), ArtifactType::PeExecutable)
        }
        ProcessorCommand::IndexDll => {
            index(&input.join("artifact.dll"), ArtifactType::PeDynamicLibrary)
        }
        ProcessorCommand::GenerateSymcache => generate(
            &input.join("artifact.pdb"),
            &scratch.join("artifact.symcache"),
        ),
        ProcessorCommand::ProcessCrash => process(
            &input.join("raw.bundle"),
            &input.join("symbols"),
            &input.join("symcaches.json"),
            &input.join("previous.json"),
        ),
    }
}

fn index(path: &Path, expected_type: ArtifactType) -> Result<(), ProcessorError> {
    let result = scan_artifacts_with_limits(
        path,
        ArtifactScanLimits {
            entries: 1,
            depth: 0,
            files: 1,
            file_bytes: MAX_ARTIFACT_BYTES,
            total_bytes: MAX_ARTIFACT_BYTES,
        },
    )
    .map_err(|_| ProcessorError::Scan)?;
    if result.artifacts.len() != 1
        || result.artifacts[0].artifact_type != expected_type
        || result.artifacts[0].error.is_some()
    {
        return Err(ProcessorError::InvalidInput);
    }
    write_json(&result)
}

fn generate(input: &Path, output: &Path) -> Result<(), ProcessorError> {
    let metadata = generate_symcache(input, output, MAX_ARTIFACT_BYTES)
        .map_err(|_| ProcessorError::SymCache)?;
    write_json(&metadata)
}

fn process(
    request: &Path,
    symbols: &Path,
    manifest: &Path,
    previous: &Path,
) -> Result<(), ProcessorError> {
    let request = File::open(request).map_err(|_| ProcessorError::InvalidInput)?;
    let manifest = read_manifest(manifest)?;
    let previous = read_optional(previous, MAX_PREVIOUS_BYTES)?;
    let caches = manifest
        .entries
        .into_iter()
        .map(|entry| {
            valid_cache_name(&entry.file).then(|| SymCacheArtifact {
                debug_id: entry.debug_id,
                path: symbols.join(entry.file),
            })
        })
        .collect::<Option<Vec<_>>>()
        .ok_or(ProcessorError::InvalidInput)?;
    let result = process_crash_request(request, symbols, &caches, previous.as_deref())
        .map_err(|_| ProcessorError::Crash)?;
    write_json(&result)
}

fn read_optional(path: &Path, maximum: u64) -> Result<Option<Vec<u8>>, ProcessorError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(ProcessorError::InvalidInput),
    };
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ProcessorError::InvalidInput)?;
    if u64::try_from(bytes.len()).map_or(true, |size| size > maximum) {
        return Err(ProcessorError::InvalidInput);
    }
    Ok(Some(bytes))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheManifest {
    entries: Vec<CacheEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheEntry {
    debug_id: String,
    file: PathBuf,
}

fn read_manifest(path: &Path) -> Result<CacheManifest, ProcessorError> {
    let file = File::open(path).map_err(|_| ProcessorError::InvalidInput)?;
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ProcessorError::InvalidInput)?;
    if u64::try_from(bytes.len()).map_or(true, |size| size > MAX_MANIFEST_BYTES) {
        return Err(ProcessorError::InvalidInput);
    }
    serde_json::from_slice(&bytes).map_err(|_| ProcessorError::InvalidInput)
}

fn valid_cache_name(path: &Path) -> bool {
    let mut components = path.components();
    let Some(Component::Normal(name)) = components.next() else {
        return false;
    };
    components.next().is_none()
        && name
            .to_str()
            .is_some_and(|value| value.len() == 73 && value.ends_with(".symcache"))
}

fn write_json(value: &impl serde::Serialize) -> Result<(), ProcessorError> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, value).map_err(|_| ProcessorError::Serialize)?;
    writeln!(output).map_err(|_| ProcessorError::Write)
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File},
        path::Path,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{MAX_PREVIOUS_BYTES, ProcessorError, read_optional, valid_cache_name};

    #[test]
    fn cache_manifest_accepts_only_fixed_leaf_names() {
        let valid = format!("{}.symcache", "a".repeat(64));
        assert!(valid_cache_name(Path::new(&valid)));
        assert!(!valid_cache_name(Path::new("../secret.symcache")));
        assert!(!valid_cache_name(Path::new("C:\\secret.symcache")));
        assert!(!valid_cache_name(Path::new("nested/cache.symcache")));
    }

    #[test]
    fn optional_previous_result_is_fixed_and_bounded() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|error| panic!("test clock must be valid: {error}"))
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "faultlane-processor-previous-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root)
            .unwrap_or_else(|error| panic!("test directory must be created: {error}"));
        let missing = root.join("missing.json");
        assert!(
            read_optional(&missing, MAX_PREVIOUS_BYTES)
                .unwrap_or_else(|error| panic!("missing previous result must be optional: {error}"))
                .is_none()
        );
        let previous = root.join("previous.json");
        fs::write(&previous, br#"{"schema_version":1}"#)
            .unwrap_or_else(|error| panic!("previous result must be written: {error}"));
        assert_eq!(
            read_optional(&previous, MAX_PREVIOUS_BYTES)
                .unwrap_or_else(|error| panic!("previous result must be read: {error}"))
                .as_deref(),
            Some(br#"{"schema_version":1}"#.as_slice())
        );
        let oversized = root.join("oversized.json");
        File::create(&oversized)
            .and_then(|file| file.set_len(MAX_PREVIOUS_BYTES + 1))
            .unwrap_or_else(|error| panic!("oversized result must be created: {error}"));
        assert!(matches!(
            read_optional(&oversized, MAX_PREVIOUS_BYTES),
            Err(ProcessorError::InvalidInput)
        ));
        fs::remove_dir_all(&root)
            .unwrap_or_else(|error| panic!("test directory must be removed: {error}"));
    }
}

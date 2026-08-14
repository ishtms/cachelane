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

fn process(request: &Path, symbols: &Path, manifest: &Path) -> Result<(), ProcessorError> {
    let request = File::open(request).map_err(|_| ProcessorError::InvalidInput)?;
    let manifest = read_manifest(manifest)?;
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
    let result = process_crash_request(request, symbols, &caches, None)
        .map_err(|_| ProcessorError::Crash)?;
    write_json(&result)
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
    use std::path::Path;

    use super::valid_cache_name;

    #[test]
    fn cache_manifest_accepts_only_fixed_leaf_names() {
        let valid = format!("{}.symcache", "a".repeat(64));
        assert!(valid_cache_name(Path::new(&valid)));
        assert!(!valid_cache_name(Path::new("../secret.symcache")));
        assert!(!valid_cache_name(Path::new("C:\\secret.symcache")));
        assert!(!valid_cache_name(Path::new("nested/cache.symcache")));
    }
}

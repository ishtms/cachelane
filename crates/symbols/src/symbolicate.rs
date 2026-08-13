use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, File},
    io::{self, Read},
    path::{Component, Path, PathBuf},
    sync::mpsc,
    time::Duration,
};

use minidump::{
    CodeView, Minidump, MinidumpModule, MinidumpModuleList, MinidumpSystemInfo, MinidumpThreadList,
    Module,
    system_info::{Cpu, Os},
};
use minidump_processor::{ProcessState, process_minidump};
use minidump_unwind::{CallStackInfo, StackFrame, symbols::debuginfo::DebugInfoSymbolProvider};
use serde::Serialize;

use crate::{
    Architecture, ArtifactRecord, ArtifactScan, ArtifactScanLimits, ArtifactType, ScanError,
    scan_artifacts_with_limits,
};

const MINIDUMP_VERSION: &str = "0.27.0";
const MINIDUMP_PROCESSOR_VERSION: &str = "0.27.0";
const MINIDUMP_UNWIND_VERSION: &str = "0.27.0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SymbolicationLimits {
    pub dump_bytes: u64,
    pub artifact_entries: usize,
    pub artifact_depth: usize,
    pub artifacts: usize,
    pub artifact_bytes: u64,
    pub total_artifact_bytes: u64,
    pub threads: usize,
    pub modules: usize,
    pub frames_per_thread: usize,
    pub wall_time: Duration,
}

impl Default for SymbolicationLimits {
    fn default() -> Self {
        Self {
            dump_bytes: 64 * 1024 * 1024,
            artifact_entries: 4096,
            artifact_depth: 64,
            artifacts: 512,
            artifact_bytes: 1024 * 1024 * 1024,
            total_artifact_bytes: 4 * 1024 * 1024 * 1024,
            threads: 512,
            modules: 4096,
            frames_per_thread: 512,
            wall_time: Duration::from_mins(2),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SymbolicationErrorKind {
    ReadDump,
    DumpTooLarge,
    InvalidDump,
    UnsupportedPlatform,
    UnsupportedArchitecture,
    TooManyThreads,
    TooManyModules,
    InvalidSymbolRoot,
    ArtifactScan,
    UnsafeArtifactPath,
    RuntimeFailed,
    ProcessingFailed,
    TimedOut,
    WorkerFailed,
}

#[derive(Debug)]
pub enum SymbolicationError {
    ReadDump(io::Error),
    DumpTooLarge,
    InvalidDump,
    UnsupportedPlatform,
    UnsupportedArchitecture,
    TooManyThreads,
    TooManyModules,
    InvalidSymbolRoot,
    ArtifactScan(ScanError),
    UnsafeArtifactPath,
    RuntimeFailed(io::Error),
    ProcessingFailed,
    TimedOut,
    WorkerFailed,
}

impl SymbolicationError {
    #[must_use]
    pub const fn kind(&self) -> SymbolicationErrorKind {
        match self {
            Self::ReadDump(_) => SymbolicationErrorKind::ReadDump,
            Self::DumpTooLarge => SymbolicationErrorKind::DumpTooLarge,
            Self::InvalidDump => SymbolicationErrorKind::InvalidDump,
            Self::UnsupportedPlatform => SymbolicationErrorKind::UnsupportedPlatform,
            Self::UnsupportedArchitecture => SymbolicationErrorKind::UnsupportedArchitecture,
            Self::TooManyThreads => SymbolicationErrorKind::TooManyThreads,
            Self::TooManyModules => SymbolicationErrorKind::TooManyModules,
            Self::InvalidSymbolRoot => SymbolicationErrorKind::InvalidSymbolRoot,
            Self::ArtifactScan(_) => SymbolicationErrorKind::ArtifactScan,
            Self::UnsafeArtifactPath => SymbolicationErrorKind::UnsafeArtifactPath,
            Self::RuntimeFailed(_) => SymbolicationErrorKind::RuntimeFailed,
            Self::ProcessingFailed => SymbolicationErrorKind::ProcessingFailed,
            Self::TimedOut => SymbolicationErrorKind::TimedOut,
            Self::WorkerFailed => SymbolicationErrorKind::WorkerFailed,
        }
    }
}

impl fmt::Display for SymbolicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadDump(_) => formatter.write_str("failed to read minidump"),
            Self::DumpTooLarge => formatter.write_str("minidump size limit exceeded"),
            Self::InvalidDump => formatter.write_str("invalid minidump"),
            Self::UnsupportedPlatform => formatter.write_str("minidump platform is not supported"),
            Self::UnsupportedArchitecture => {
                formatter.write_str("minidump architecture is not supported")
            }
            Self::TooManyThreads => formatter.write_str("minidump thread limit exceeded"),
            Self::TooManyModules => formatter.write_str("minidump module limit exceeded"),
            Self::InvalidSymbolRoot => formatter.write_str("invalid symbol directory"),
            Self::ArtifactScan(error) => error.fmt(formatter),
            Self::UnsafeArtifactPath => formatter.write_str("unsafe symbol artifact path"),
            Self::RuntimeFailed(_) => formatter.write_str("failed to start minidump processor"),
            Self::ProcessingFailed => formatter.write_str("failed to process minidump"),
            Self::TimedOut => formatter.write_str("minidump processing timed out"),
            Self::WorkerFailed => formatter.write_str("minidump processing worker failed"),
        }
    }
}

impl std::error::Error for SymbolicationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReadDump(error) | Self::RuntimeFailed(error) => Some(error),
            Self::ArtifactScan(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleSymbolStatus {
    Matched,
    MissingPe,
    MissingPdb,
    Mismatched,
    MissingIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SymbolicatedModule {
    pub module: String,
    pub base_address: String,
    pub size: u64,
    pub code_id: Option<String>,
    pub debug_id: Option<String>,
    pub status: ModuleSymbolStatus,
    pub pe: Option<String>,
    pub pdb: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameSymbolStatus {
    Resolved,
    Unresolved,
    MissingPe,
    MissingPdb,
    Mismatched,
    MissingIdentity,
    UnknownModule,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InlineSymbol {
    pub function: String,
    pub source_file: Option<String>,
    pub source_line: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SymbolicatedFrame {
    pub instruction: String,
    pub module: Option<String>,
    pub module_relative: Option<String>,
    pub trust: &'static str,
    pub symbol_status: FrameSymbolStatus,
    pub function: Option<String>,
    pub source_file: Option<String>,
    pub source_line: Option<u32>,
    pub inlines: Vec<InlineSymbol>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadUnwindStatus {
    Ok,
    MissingContext,
    MissingMemory,
    UnsupportedCpu,
    DumpThreadSkipped,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SymbolicatedThread {
    pub thread_id: u32,
    pub faulting: bool,
    pub name: Option<String>,
    pub unwind_status: ThreadUnwindStatus,
    pub frames_truncated: bool,
    pub frames: Vec<SymbolicatedFrame>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SymbolicationResult {
    pub schema_version: u32,
    pub symbolicator_version: &'static str,
    pub minidump_version: &'static str,
    pub minidump_processor_version: &'static str,
    pub minidump_unwind_version: &'static str,
    pub platform: &'static str,
    pub architecture: &'static str,
    pub faulting_thread_id: Option<u32>,
    pub modules: Vec<SymbolicatedModule>,
    pub threads: Vec<SymbolicatedThread>,
}

#[derive(Debug)]
struct ArtifactSelection<'a> {
    pe: Option<&'a ArtifactRecord>,
    pdb: Option<&'a ArtifactRecord>,
    status: ModuleSymbolStatus,
}

#[derive(Debug)]
struct PreparedModules {
    modules: MinidumpModuleList,
    diagnostics: Vec<SymbolicatedModule>,
}

/// Symbolicates one bounded Windows x64 minidump with local artifacts.
///
/// # Errors
///
/// Returns a safe typed error for invalid inputs, resource limits, processing failures, or timeouts.
pub fn symbolicate_minidump(
    dump_path: &Path,
    symbol_root: &Path,
    limits: SymbolicationLimits,
) -> Result<SymbolicationResult, SymbolicationError> {
    if limits.wall_time.is_zero() {
        return Err(SymbolicationError::TimedOut);
    }

    let dump_path = dump_path.to_path_buf();
    let symbol_root = symbol_root.to_path_buf();
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("cachelane-symbolicator".to_owned())
        .spawn(move || {
            let _ = sender.send(symbolicate_inner(&dump_path, &symbol_root, limits));
        })
        .map_err(SymbolicationError::RuntimeFailed)?;

    match receiver.recv_timeout(limits.wall_time) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(SymbolicationError::TimedOut),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(SymbolicationError::WorkerFailed),
    }
}

fn symbolicate_inner(
    dump_path: &Path,
    symbol_root: &Path,
    limits: SymbolicationLimits,
) -> Result<SymbolicationResult, SymbolicationError> {
    let bytes = read_dump(dump_path, limits.dump_bytes)?;
    let dump = Minidump::read(bytes).map_err(|_| SymbolicationError::InvalidDump)?;
    let system_info = dump
        .get_stream::<MinidumpSystemInfo>()
        .map_err(|_| SymbolicationError::InvalidDump)?;
    if system_info.os != Os::Windows {
        return Err(SymbolicationError::UnsupportedPlatform);
    }
    if system_info.cpu != Cpu::X86_64 {
        return Err(SymbolicationError::UnsupportedArchitecture);
    }

    let thread_list = dump
        .get_stream::<MinidumpThreadList<'_>>()
        .map_err(|_| SymbolicationError::InvalidDump)?;
    if thread_list.threads.len() > limits.threads {
        return Err(SymbolicationError::TooManyThreads);
    }
    let original_modules = dump
        .get_stream::<MinidumpModuleList>()
        .map_err(|_| SymbolicationError::InvalidDump)?;
    if original_modules.iter().count() > limits.modules {
        return Err(SymbolicationError::TooManyModules);
    }
    let (canonical_root, scan) = scan_symbol_root(symbol_root, limits)?;
    let prepared = prepare_modules(&original_modules, &scan, &canonical_root)?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(SymbolicationError::RuntimeFailed)?;
    let state = runtime.block_on(async {
        let provider = DebugInfoSymbolProvider::new(&system_info, &prepared.modules).await;
        process_minidump(&dump, &provider).await
    });
    let state = state.map_err(|_| SymbolicationError::ProcessingFailed)?;
    Ok(build_result(&state, prepared.diagnostics, limits))
}

fn read_dump(path: &Path, limit: u64) -> Result<Vec<u8>, SymbolicationError> {
    let file = File::open(path).map_err(SymbolicationError::ReadDump)?;
    let read_limit = limit.saturating_add(1);
    let mut bytes = Vec::new();
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(SymbolicationError::ReadDump)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(SymbolicationError::DumpTooLarge);
    }
    Ok(bytes)
}

fn scan_symbol_root(
    root: &Path,
    limits: SymbolicationLimits,
) -> Result<(PathBuf, ArtifactScan), SymbolicationError> {
    let metadata = fs::symlink_metadata(root).map_err(|_| SymbolicationError::InvalidSymbolRoot)?;
    if !metadata.file_type().is_dir() {
        return Err(SymbolicationError::InvalidSymbolRoot);
    }
    let canonical = fs::canonicalize(root).map_err(|_| SymbolicationError::InvalidSymbolRoot)?;
    let scan = scan_artifacts_with_limits(
        &canonical,
        ArtifactScanLimits {
            entries: limits.artifact_entries,
            depth: limits.artifact_depth,
            files: limits.artifacts,
            file_bytes: limits.artifact_bytes,
            total_bytes: limits.total_artifact_bytes,
        },
    )
    .map_err(SymbolicationError::ArtifactScan)?;
    Ok((canonical, scan))
}

fn choose_artifacts<'a>(
    module_name: &str,
    code_id: Option<&str>,
    debug_id: Option<&str>,
    artifacts: &'a [ArtifactRecord],
) -> ArtifactSelection<'a> {
    let exact_pe = code_id.and_then(|expected_code| {
        artifacts.iter().find(|artifact| {
            matches!(
                artifact.artifact_type,
                ArtifactType::PeExecutable | ArtifactType::PeDynamicLibrary
            ) && artifact.error.is_none()
                && artifact.architecture == Some(Architecture::X86_64)
                && artifact.code_id.as_deref() == Some(expected_code)
                && debug_id.is_none_or(|expected| artifact.debug_id.as_deref() == Some(expected))
        })
    });

    if let Some(pe) = exact_pe {
        if debug_id.is_none() {
            return ArtifactSelection {
                pe: Some(pe),
                pdb: None,
                status: ModuleSymbolStatus::MissingIdentity,
            };
        }
        let pdb = pe.matches.iter().find_map(|path| {
            artifacts.iter().find(|artifact| {
                artifact.path == *path
                    && artifact.artifact_type == ArtifactType::Pdb
                    && artifact.error.is_none()
                    && artifact.architecture == Some(Architecture::X86_64)
            })
        });
        return ArtifactSelection {
            pe: Some(pe),
            pdb,
            status: if pdb.is_some() {
                ModuleSymbolStatus::Matched
            } else {
                ModuleSymbolStatus::MissingPdb
            },
        };
    }

    if code_id.is_none() {
        return ArtifactSelection {
            pe: None,
            pdb: None,
            status: ModuleSymbolStatus::MissingIdentity,
        };
    }

    let has_related_pe = artifacts.iter().any(|artifact| {
        matches!(
            artifact.artifact_type,
            ArtifactType::PeExecutable | ArtifactType::PeDynamicLibrary
        ) && artifact.error.is_none()
            && (artifact.module.eq_ignore_ascii_case(module_name)
                || artifact.code_id.as_deref() == code_id
                || debug_id.is_some() && artifact.debug_id.as_deref() == debug_id)
    });
    ArtifactSelection {
        pe: None,
        pdb: None,
        status: if has_related_pe {
            ModuleSymbolStatus::Mismatched
        } else {
            ModuleSymbolStatus::MissingPe
        },
    }
}

fn prepare_modules(
    modules: &MinidumpModuleList,
    scan: &ArtifactScan,
    root: &Path,
) -> Result<PreparedModules, SymbolicationError> {
    let fallback = path_text(root)?;
    let mut rewritten = Vec::new();
    let mut diagnostics = Vec::new();

    for module in modules.iter() {
        let module_name = leaf_name(&module.name);
        let code_id = module
            .code_identifier()
            .map(|identifier| identifier.to_string().to_ascii_uppercase());
        let debug_id = module
            .debug_identifier()
            .map(|identifier| identifier.to_string().to_ascii_uppercase());
        let selection = choose_artifacts(
            &module_name,
            code_id.as_deref(),
            debug_id.as_deref(),
            &scan.artifacts,
        );
        let pe = selection
            .pe
            .map(|artifact| resolve_artifact(root, &artifact.path))
            .transpose()?;
        let pdb = selection
            .pdb
            .map(|artifact| resolve_artifact(root, &artifact.path))
            .transpose()?;

        let pe_path = pe.as_deref().map(path_text).transpose()?;
        let pdb_path = pdb.as_deref().map(path_text).transpose()?;
        let mut local_module = module.clone();
        local_module.name = pe_path.unwrap_or_else(|| fallback.clone());
        let debug_path = pdb_path.unwrap_or_else(|| fallback.clone());
        rewrite_debug_path(&mut local_module, &debug_path);
        rewritten.push(local_module);

        diagnostics.push(SymbolicatedModule {
            module: module_name,
            base_address: format_address(module.base_address()),
            size: module.size(),
            code_id,
            debug_id,
            status: selection.status,
            pe: selection.pe.map(|artifact| artifact.path.clone()),
            pdb: selection.pdb.map(|artifact| artifact.path.clone()),
        });
    }

    diagnostics.sort_by(|left, right| {
        left.base_address
            .cmp(&right.base_address)
            .then_with(|| left.module.cmp(&right.module))
    });
    Ok(PreparedModules {
        modules: MinidumpModuleList::from_modules(rewritten),
        diagnostics,
    })
}

fn resolve_artifact(root: &Path, relative: &str) -> Result<PathBuf, SymbolicationError> {
    let relative = Path::new(relative);
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(SymbolicationError::UnsafeArtifactPath);
    }
    let candidate = root.join(relative);
    let metadata =
        fs::symlink_metadata(&candidate).map_err(|_| SymbolicationError::UnsafeArtifactPath)?;
    if !metadata.file_type().is_file() {
        return Err(SymbolicationError::UnsafeArtifactPath);
    }
    let canonical =
        fs::canonicalize(candidate).map_err(|_| SymbolicationError::UnsafeArtifactPath)?;
    if !canonical.starts_with(root) {
        return Err(SymbolicationError::UnsafeArtifactPath);
    }
    Ok(canonical)
}

fn path_text(path: &Path) -> Result<String, SymbolicationError> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or(SymbolicationError::UnsafeArtifactPath)
}

fn rewrite_debug_path(module: &mut MinidumpModule, path: &str) {
    let mut bytes = path.as_bytes().to_vec();
    bytes.push(0);
    match module.codeview_info.as_mut() {
        Some(CodeView::Pdb20(info)) => info.pdb_file_name = bytes,
        Some(CodeView::Pdb70(info)) => info.pdb_file_name = bytes,
        _ => {}
    }
}

fn build_result(
    state: &ProcessState,
    modules: Vec<SymbolicatedModule>,
    limits: SymbolicationLimits,
) -> SymbolicationResult {
    let faulting_index = state
        .requesting_thread
        .filter(|index| *index < state.threads.len());
    let faulting_thread_id = faulting_index.map(|index| state.threads[index].thread_id);
    let module_status = modules
        .iter()
        .filter_map(|module| parse_address(&module.base_address).map(|base| (base, module.status)))
        .collect::<BTreeMap<_, _>>();
    let mut indexed_threads = state.threads.iter().enumerate().collect::<Vec<_>>();
    indexed_threads.sort_by_key(|(index, thread)| {
        (
            usize::from(Some(*index) != faulting_index),
            thread.thread_id,
            *index,
        )
    });
    let threads = indexed_threads
        .into_iter()
        .take(limits.threads)
        .map(|(index, thread)| SymbolicatedThread {
            thread_id: thread.thread_id,
            faulting: Some(index) == faulting_index,
            name: thread.thread_name.clone(),
            unwind_status: thread_status(&thread.info),
            frames_truncated: thread.frames.len() > limits.frames_per_thread,
            frames: thread
                .frames
                .iter()
                .take(limits.frames_per_thread)
                .map(|frame| map_frame(frame, &module_status))
                .collect(),
        })
        .collect();

    SymbolicationResult {
        schema_version: 1,
        symbolicator_version: env!("CARGO_PKG_VERSION"),
        minidump_version: MINIDUMP_VERSION,
        minidump_processor_version: MINIDUMP_PROCESSOR_VERSION,
        minidump_unwind_version: MINIDUMP_UNWIND_VERSION,
        platform: "windows",
        architecture: "x86_64",
        faulting_thread_id,
        modules,
        threads,
    }
}

fn map_frame(
    frame: &StackFrame,
    module_status: &BTreeMap<u64, ModuleSymbolStatus>,
) -> SymbolicatedFrame {
    let base = frame.module.as_ref().map(Module::base_address);
    let status = if frame.function_name.is_some() {
        FrameSymbolStatus::Resolved
    } else {
        base.and_then(|address| module_status.get(&address).copied())
            .map_or(FrameSymbolStatus::UnknownModule, frame_status)
    };
    SymbolicatedFrame {
        instruction: format_address(frame.instruction),
        module: frame.module.as_ref().map(|module| leaf_name(&module.name)),
        module_relative: base
            .and_then(|address| frame.instruction.checked_sub(address))
            .map(format_relative_address),
        trust: frame.trust.as_str(),
        symbol_status: status,
        function: frame.function_name.clone(),
        source_file: frame.source_file_name.clone(),
        source_line: frame.source_line,
        inlines: frame
            .inlines
            .iter()
            .map(|inline| InlineSymbol {
                function: inline.function_name.clone(),
                source_file: inline.source_file_name.clone(),
                source_line: inline.source_line,
            })
            .collect(),
    }
}

const fn frame_status(status: ModuleSymbolStatus) -> FrameSymbolStatus {
    match status {
        ModuleSymbolStatus::Matched => FrameSymbolStatus::Unresolved,
        ModuleSymbolStatus::MissingPdb => FrameSymbolStatus::MissingPdb,
        ModuleSymbolStatus::MissingPe => FrameSymbolStatus::MissingPe,
        ModuleSymbolStatus::Mismatched => FrameSymbolStatus::Mismatched,
        ModuleSymbolStatus::MissingIdentity => FrameSymbolStatus::MissingIdentity,
    }
}

const fn thread_status(status: &CallStackInfo) -> ThreadUnwindStatus {
    match status {
        CallStackInfo::Ok => ThreadUnwindStatus::Ok,
        CallStackInfo::MissingContext => ThreadUnwindStatus::MissingContext,
        CallStackInfo::MissingMemory => ThreadUnwindStatus::MissingMemory,
        CallStackInfo::UnsupportedCpu => ThreadUnwindStatus::UnsupportedCpu,
        CallStackInfo::DumpThreadSkipped => ThreadUnwindStatus::DumpThreadSkipped,
    }
}

fn leaf_name(path: &str) -> String {
    path.rsplit(['/', '\\'])
        .find(|part| !part.is_empty())
        .unwrap_or("unknown")
        .to_owned()
}

fn format_address(address: u64) -> String {
    format!("0x{address:016X}")
}

fn format_relative_address(address: u64) -> String {
    format!("0x{address:X}")
}

fn parse_address(address: &str) -> Option<u64> {
    u64::from_str_radix(address.strip_prefix("0x")?, 16).ok()
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::{ArtifactError, MatchState};

    fn pe(
        path: &str,
        module: &str,
        code_id: &str,
        debug_id: &str,
        matches: &[&str],
    ) -> ArtifactRecord {
        ArtifactRecord {
            path: path.to_owned(),
            module: module.to_owned(),
            artifact_type: ArtifactType::PeExecutable,
            architecture: Some(Architecture::X86_64),
            size: Some(1024),
            debug_id: Some(debug_id.to_owned()),
            code_id: Some(code_id.to_owned()),
            match_state: MatchState::Matched,
            matches: matches.iter().map(|path| (*path).to_owned()).collect(),
            error: None,
        }
    }

    fn pdb(path: &str, debug_id: &str) -> ArtifactRecord {
        ArtifactRecord {
            path: path.to_owned(),
            module: "Game.pdb".to_owned(),
            artifact_type: ArtifactType::Pdb,
            architecture: Some(Architecture::X86_64),
            size: Some(4096),
            debug_id: Some(debug_id.to_owned()),
            code_id: None,
            match_state: MatchState::Matched,
            matches: vec!["bin/Game.exe".to_owned()],
            error: None,
        }
    }

    #[test]
    fn selects_exact_ids_without_using_the_module_filename() {
        let artifacts = vec![
            pe(
                "bin/Renamed.exe",
                "Renamed.exe",
                "CODE",
                "DEBUG",
                &["symbols/Game.pdb"],
            ),
            pdb("symbols/Game.pdb", "DEBUG-2"),
        ];

        let selected = choose_artifacts("Game.exe", Some("CODE"), Some("DEBUG"), &artifacts);

        assert_eq!(selected.status, ModuleSymbolStatus::Matched);
        assert_eq!(
            selected.pe.map(|artifact| artifact.path.as_str()),
            Some("bin/Renamed.exe")
        );
        assert_eq!(
            selected.pdb.map(|artifact| artifact.path.as_str()),
            Some("symbols/Game.pdb")
        );
    }

    #[test]
    fn reports_same_name_identity_mismatches_without_selecting_them() {
        let artifacts = vec![pe("Game.exe", "Game.exe", "OTHER", "OTHER", &[])];

        let selected = choose_artifacts("Game.exe", Some("CODE"), Some("DEBUG"), &artifacts);

        assert_eq!(selected.status, ModuleSymbolStatus::Mismatched);
        assert!(selected.pe.is_none());
        assert!(selected.pdb.is_none());
    }

    #[test]
    fn reports_missing_artifacts_and_identities_separately() {
        let artifacts = Vec::new();
        assert_eq!(
            choose_artifacts("Game.exe", Some("CODE"), Some("DEBUG"), &artifacts).status,
            ModuleSymbolStatus::MissingPe
        );
        assert_eq!(
            choose_artifacts("Game.exe", None, Some("DEBUG"), &artifacts).status,
            ModuleSymbolStatus::MissingIdentity
        );
    }

    #[test]
    fn ignores_invalid_records_during_exact_selection() {
        let mut artifact = pe("Game.exe", "Game.exe", "CODE", "DEBUG", &[]);
        artifact.match_state = MatchState::Invalid;
        artifact.error = Some(ArtifactError {
            code: crate::ArtifactErrorCode::Malformed,
        });

        let artifacts = [artifact];
        let selected = choose_artifacts("Other.exe", Some("CODE"), Some("DEBUG"), &artifacts);

        assert_eq!(selected.status, ModuleSymbolStatus::MissingPe);
    }

    #[test]
    fn strips_private_module_paths() {
        assert_eq!(leaf_name(r"C:\private\build\Game.exe"), "Game.exe");
        assert_eq!(leaf_name("/private/build/Game.exe"), "Game.exe");
    }

    #[test]
    fn rejects_oversized_dumps_before_parsing() -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "cachelane-symbolicate-{}-oversized.dmp",
            std::process::id()
        ));
        let mut file = File::create(&path)?;
        file.write_all(b"ab")?;

        let result = read_dump(&path, 1);
        let _ = fs::remove_file(path);

        assert!(matches!(result, Err(SymbolicationError::DumpTooLarge)));
        Ok(())
    }

    #[test]
    fn zero_wall_time_fails_without_starting_a_worker() {
        let limits = SymbolicationLimits {
            wall_time: Duration::ZERO,
            ..SymbolicationLimits::default()
        };

        let result = symbolicate_minidump(Path::new("private.dmp"), Path::new("private"), limits);

        assert!(matches!(result, Err(SymbolicationError::TimedOut)));
    }

    #[test]
    fn module_limit_has_a_safe_typed_error() {
        let error = SymbolicationError::TooManyModules;

        assert_eq!(error.kind(), SymbolicationErrorKind::TooManyModules);
        assert_eq!(error.to_string(), "minidump module limit exceeded");
    }
}

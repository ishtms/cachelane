use std::{
    fmt,
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use cachelane_symbols::{
    ScanError, SymbolicationError, SymbolicationLimits, scan_artifacts, symbolicate_minidump,
    symbolicate_minidump_bytes,
};
use cachelane_unreal::{
    CrashClassification, CrashContextData, CrashContextExtractionOptions, CrashContextParser,
    CrashRequestError, CrashRequestLimits, CrashRequestLog, CrashRequestManifest, ParseError,
    inspect_crash_request, read_crash_request,
};
use clap::{Parser, Subcommand};
use serde::Serialize;
use serde_json::Value;

const MAX_CRASH_CONTEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_CRASH_CONTEXT_READ_BYTES: u64 = 4 * 1024 * 1024 + 1;
const MAX_CRASH_CONTEXT_NODES: u32 = 100_000;
const MAX_PREVIOUS_RESULT_BYTES: usize = 64 * 1024 * 1024;
const MAX_PREVIOUS_RESULT_READ_BYTES: u64 = 64 * 1024 * 1024 + 1;
const MAX_PROCESSING_HISTORY: usize = 16;
const LOCAL_RESULT_SCHEMA_VERSION: u32 = 1;
const LOCAL_PROCESSING_VERSION: u32 = 1;

#[derive(Parser)]
#[command(name = "cachelane", version, about = "CacheLane command line tools")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    #[command(subcommand)]
    Crash(CrashCommand),
    #[command(subcommand)]
    Symbols(SymbolsCommand),
}

#[derive(Subcommand)]
enum CrashCommand {
    Parse {
        path: PathBuf,
    },
    Process {
        input: PathBuf,
        #[arg(long)]
        crash_context: Option<PathBuf>,
        #[arg(long)]
        symbols: PathBuf,
        #[arg(long)]
        previous: Option<PathBuf>,
    },
    Unpack {
        path: PathBuf,
    },
    Symbolicate {
        dump: PathBuf,
        #[arg(long)]
        symbols: PathBuf,
    },
}

#[derive(Subcommand)]
enum SymbolsCommand {
    Scan { path: PathBuf },
}

enum CliError {
    Read(io::Error),
    TooLarge,
    InvalidUtf8,
    Parse(ParseError),
    MissingCrashIdentity,
    MissingRequestCrashContext,
    MissingRequestMinidump,
    PreviousRead,
    PreviousTooLarge,
    InvalidPrevious,
    UnsupportedPreviousSchema,
    UnsupportedPreviousProcessing,
    PreviousIdentityMismatch,
    PreviousHistoryTooLong,
    RequestRead,
    Request(CrashRequestError),
    Symbolicate(SymbolicationError),
    Scan(ScanError),
    Serialize(serde_json::Error),
    Write(io::Error),
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(error) => write!(formatter, "failed to read crash context: {error}"),
            Self::TooLarge => write!(
                formatter,
                "crash context exceeds {MAX_CRASH_CONTEXT_BYTES}-byte limit"
            ),
            Self::InvalidUtf8 => write!(formatter, "crash context must be UTF-8"),
            Self::Parse(error) => error.fmt(formatter),
            Self::MissingCrashIdentity => {
                formatter.write_str("crash context has no usable crash identity")
            }
            Self::MissingRequestCrashContext => {
                formatter.write_str("crash request has no crash context")
            }
            Self::MissingRequestMinidump => formatter.write_str("crash request has no minidump"),
            Self::PreviousRead => formatter.write_str("failed to read previous processing result"),
            Self::PreviousTooLarge => write!(
                formatter,
                "previous processing result exceeds {MAX_PREVIOUS_RESULT_BYTES}-byte limit"
            ),
            Self::InvalidPrevious => formatter.write_str("invalid previous processing result"),
            Self::UnsupportedPreviousSchema => {
                formatter.write_str("unsupported previous result schema version")
            }
            Self::UnsupportedPreviousProcessing => {
                formatter.write_str("unsupported previous processing version")
            }
            Self::PreviousIdentityMismatch => {
                formatter.write_str("previous result crash identity does not match")
            }
            Self::PreviousHistoryTooLong => {
                formatter.write_str("previous processing history limit exceeded")
            }
            Self::RequestRead => write!(formatter, "failed to read crash request"),
            Self::Request(error) => error.fmt(formatter),
            Self::Symbolicate(error) => error.fmt(formatter),
            Self::Scan(error) => error.fmt(formatter),
            Self::Serialize(error) => write!(formatter, "failed to serialize output: {error}"),
            Self::Write(error) => write!(formatter, "failed to write output: {error}"),
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Some(Command::Crash(CrashCommand::Parse { path })) => parse_crash_context(&path),
        Some(Command::Crash(CrashCommand::Process {
            input,
            crash_context,
            symbols,
            previous,
        })) => match crash_context {
            Some(crash_context) => {
                process_extracted_crash(&input, &crash_context, &symbols, previous.as_deref())
            }
            None => process_crash_request(&input, &symbols, previous.as_deref()),
        },
        Some(Command::Crash(CrashCommand::Unpack { path })) => unpack_crash_request(&path),
        Some(Command::Crash(CrashCommand::Symbolicate { dump, symbols })) => {
            symbolicate_crash(&dump, &symbols)
        }
        Some(Command::Symbols(SymbolsCommand::Scan { path })) => scan_symbols(&path),
        None => {
            println!("CacheLane CLI is ready");
            Ok(())
        }
    }
}

#[derive(Serialize)]
struct ProcessingAttempt<'result> {
    processing_version: u32,
    parser_version: u32,
    symbolication: &'result cachelane_symbols::SymbolicationResult,
}

#[derive(Serialize)]
struct LocalProcessingResult<'result> {
    schema_version: u32,
    crash_guid: &'result str,
    crash_context: &'result CrashContextData,
    #[serde(skip_serializing_if = "Option::is_none")]
    request: Option<&'result CrashRequestManifest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    classification: Option<&'result CrashClassification>,
    #[serde(skip_serializing_if = "Option::is_none")]
    log: Option<&'result CrashRequestLog>,
    current: &'result Value,
    history: &'result [Value],
}

struct PreviousProcessing {
    current: Value,
    history: Vec<Value>,
}

fn process_extracted_crash(
    dump: &Path,
    crash_context: &Path,
    symbols: &Path,
    previous: Option<&Path>,
) -> Result<(), CliError> {
    let xml = read_crash_context(crash_context)?;
    let crash_context = CrashContextParser::new(MAX_CRASH_CONTEXT_NODES)
        .parse(&xml)
        .map_err(CliError::Parse)?
        .extract(CrashContextExtractionOptions::default());
    let previous = load_previous_processing(&crash_context, previous)?;
    let symbolication = symbolicate_minidump(dump, symbols, SymbolicationLimits::default())
        .map_err(CliError::Symbolicate)?;

    write_processing_result(&crash_context, &symbolication, previous, None, None, None)
}

fn process_crash_request(
    request: &Path,
    symbols: &Path,
    previous: Option<&Path>,
) -> Result<(), CliError> {
    let file = File::open(request).map_err(|_| CliError::RequestRead)?;
    let contents =
        read_crash_request(file, CrashRequestLimits::default()).map_err(CliError::Request)?;
    let xml = contents
        .crash_context
        .as_deref()
        .ok_or(CliError::MissingRequestCrashContext)?;
    let parsed = CrashContextParser::new(MAX_CRASH_CONTEXT_NODES)
        .parse(xml)
        .map_err(CliError::Parse)?;
    let classification = parsed.classification();
    let crash_context = parsed.extract(CrashContextExtractionOptions::default());
    let previous = load_previous_processing(&crash_context, previous)?;
    let minidump = contents.minidump.ok_or(CliError::MissingRequestMinidump)?;
    let symbolication =
        symbolicate_minidump_bytes(minidump, symbols, SymbolicationLimits::default())
            .map_err(CliError::Symbolicate)?;

    write_processing_result(
        &crash_context,
        &symbolication,
        previous,
        Some(&contents.manifest),
        Some(&classification),
        contents.log.as_ref(),
    )
}

fn load_previous_processing(
    crash_context: &CrashContextData,
    previous: Option<&Path>,
) -> Result<Option<PreviousProcessing>, CliError> {
    let crash_guid = crash_guid(crash_context)?;
    previous
        .map(|path| read_previous_processing(path, crash_guid))
        .transpose()
}

fn crash_guid(crash_context: &CrashContextData) -> Result<&str, CliError> {
    crash_context
        .crash_guid
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or(CliError::MissingCrashIdentity)
}

fn write_processing_result(
    crash_context: &CrashContextData,
    symbolication: &cachelane_symbols::SymbolicationResult,
    previous: Option<PreviousProcessing>,
    request: Option<&CrashRequestManifest>,
    classification: Option<&CrashClassification>,
    log: Option<&CrashRequestLog>,
) -> Result<(), CliError> {
    let crash_guid = crash_guid(crash_context)?;
    let current = serde_json::to_value(ProcessingAttempt {
        processing_version: LOCAL_PROCESSING_VERSION,
        parser_version: crash_context.parser_version,
        symbolication,
    })
    .map_err(CliError::Serialize)?;
    let mut history = previous
        .as_ref()
        .map_or_else(Vec::new, |result| result.history.clone());

    if let Some(previous) = previous
        && previous.current != current
    {
        if history.len() == MAX_PROCESSING_HISTORY {
            return Err(CliError::PreviousHistoryTooLong);
        }
        history.push(previous.current);
    }

    let result = LocalProcessingResult {
        schema_version: LOCAL_RESULT_SCHEMA_VERSION,
        crash_guid,
        crash_context,
        request,
        classification,
        log,
        current: &current,
        history: &history,
    };
    let stdout = io::stdout();
    let mut output = stdout.lock();

    serde_json::to_writer(&mut output, &result).map_err(CliError::Serialize)?;
    writeln!(output).map_err(CliError::Write)
}

fn read_previous_processing(path: &Path, crash_guid: &str) -> Result<PreviousProcessing, CliError> {
    let file = File::open(path).map_err(|_| CliError::PreviousRead)?;
    let mut bytes = Vec::new();
    file.take(MAX_PREVIOUS_RESULT_READ_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|_| CliError::PreviousRead)?;
    if bytes.len() > MAX_PREVIOUS_RESULT_BYTES {
        return Err(CliError::PreviousTooLarge);
    }

    let result: Value = serde_json::from_slice(&bytes).map_err(|_| CliError::InvalidPrevious)?;
    let result = result.as_object().ok_or(CliError::InvalidPrevious)?;
    match result.get("schema_version").and_then(Value::as_u64) {
        Some(version) if version == u64::from(LOCAL_RESULT_SCHEMA_VERSION) => {}
        Some(_) => return Err(CliError::UnsupportedPreviousSchema),
        None => return Err(CliError::InvalidPrevious),
    }
    let previous_guid = result
        .get("crash_guid")
        .and_then(Value::as_str)
        .ok_or(CliError::InvalidPrevious)?;
    if previous_guid != crash_guid {
        return Err(CliError::PreviousIdentityMismatch);
    }
    let current = result
        .get("current")
        .cloned()
        .ok_or(CliError::InvalidPrevious)?;
    validate_attempt(&current)?;
    let history = result
        .get("history")
        .and_then(Value::as_array)
        .ok_or(CliError::InvalidPrevious)?;
    if history.len() > MAX_PROCESSING_HISTORY {
        return Err(CliError::PreviousHistoryTooLong);
    }
    for attempt in history {
        validate_attempt(attempt)?;
    }

    Ok(PreviousProcessing {
        current,
        history: history.clone(),
    })
}

fn validate_attempt(attempt: &Value) -> Result<(), CliError> {
    let attempt = attempt.as_object().ok_or(CliError::InvalidPrevious)?;
    if attempt.len() != 3
        || !attempt.contains_key("parser_version")
        || !attempt.get("symbolication").is_some_and(Value::is_object)
    {
        return Err(CliError::InvalidPrevious);
    }
    match attempt.get("processing_version").and_then(Value::as_u64) {
        Some(version) if version == u64::from(LOCAL_PROCESSING_VERSION) => {}
        Some(_) => return Err(CliError::UnsupportedPreviousProcessing),
        None => return Err(CliError::InvalidPrevious),
    }
    if !attempt.get("parser_version").is_some_and(Value::is_u64) {
        return Err(CliError::InvalidPrevious);
    }
    Ok(())
}

fn symbolicate_crash(dump: &Path, symbols: &Path) -> Result<(), CliError> {
    let result = symbolicate_minidump(dump, symbols, SymbolicationLimits::default())
        .map_err(CliError::Symbolicate)?;
    let stdout = io::stdout();
    let mut output = stdout.lock();

    serde_json::to_writer(&mut output, &result).map_err(CliError::Serialize)?;
    writeln!(output).map_err(CliError::Write)
}

fn unpack_crash_request(path: &Path) -> Result<(), CliError> {
    let file = File::open(path).map_err(|_| CliError::RequestRead)?;
    let manifest =
        inspect_crash_request(file, CrashRequestLimits::default()).map_err(CliError::Request)?;
    let stdout = io::stdout();
    let mut output = stdout.lock();

    serde_json::to_writer(&mut output, &manifest).map_err(CliError::Serialize)?;
    writeln!(output).map_err(CliError::Write)
}

fn scan_symbols(path: &Path) -> Result<(), CliError> {
    let result = scan_artifacts(path).map_err(CliError::Scan)?;
    let stdout = io::stdout();
    let mut output = stdout.lock();

    serde_json::to_writer(&mut output, &result).map_err(CliError::Serialize)?;
    writeln!(output).map_err(CliError::Write)
}

fn parse_crash_context(path: &Path) -> Result<(), CliError> {
    let xml = read_crash_context(path)?;
    let data = CrashContextParser::new(MAX_CRASH_CONTEXT_NODES)
        .parse(&xml)
        .map_err(CliError::Parse)?
        .extract(CrashContextExtractionOptions::default());
    let stdout = io::stdout();
    let mut output = stdout.lock();

    serde_json::to_writer(&mut output, &data).map_err(CliError::Serialize)?;
    writeln!(output).map_err(CliError::Write)
}

fn read_crash_context(path: &Path) -> Result<String, CliError> {
    let file = File::open(path).map_err(CliError::Read)?;
    let mut bytes = Vec::new();

    file.take(MAX_CRASH_CONTEXT_READ_BYTES)
        .read_to_end(&mut bytes)
        .map_err(CliError::Read)?;
    if bytes.len() > MAX_CRASH_CONTEXT_BYTES {
        return Err(CliError::TooLarge);
    }

    String::from_utf8(bytes).map_err(|_| CliError::InvalidUtf8)
}

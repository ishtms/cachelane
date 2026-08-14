use std::{
    fmt,
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Args, Parser, Subcommand};
use faultlane_processing::{
    CrashProcessingError, ProcessingResultError, build_processing_result, crash_guid,
    parse_previous_processing, process_crash_request as process_request,
};
use faultlane_symbols::{
    ScanError, SymbolicationError, SymbolicationLimits, scan_artifacts, symbolicate_minidump,
};
use faultlane_unreal::{
    CrashContextExtractionOptions, CrashContextParser, CrashRequestError, CrashRequestLimits,
    ParseError, inspect_crash_request,
};
use serde::Serialize;

mod processor;
mod symbol_upload;

const MAX_CRASH_CONTEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_CRASH_CONTEXT_READ_BYTES: u64 = 4 * 1024 * 1024 + 1;
const MAX_CRASH_CONTEXT_NODES: u32 = 100_000;
const MAX_PREVIOUS_RESULT_BYTES: usize = 64 * 1024 * 1024;
const MAX_PREVIOUS_RESULT_READ_BYTES: u64 = 64 * 1024 * 1024 + 1;

#[derive(Parser)]
#[command(name = "faultlane", version, about = "FaultLane command line tools")]
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
    #[command(subcommand, hide = true)]
    Processor(processor::ProcessorCommand),
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
    Upload(Box<SymbolUploadArgs>),
}

#[derive(Args)]
struct SymbolUploadArgs {
    path: PathBuf,
    #[arg(long)]
    project: String,
    #[arg(long)]
    release: String,
    #[arg(
        long,
        env = "FAULTLANE_API_URL",
        default_value = "http://127.0.0.1:8080"
    )]
    api_url: String,
    #[arg(long, env = "FAULTLANE_TOKEN", hide_env_values = true)]
    token: String,
    #[arg(long)]
    architecture: Option<String>,
    #[arg(long)]
    configuration: Option<String>,
    #[arg(long)]
    revision: Option<String>,
    #[arg(long)]
    channel: Option<String>,
    #[arg(long)]
    build_timestamp: Option<String>,
    #[arg(long, env = "FAULTLANE_CI_JOB")]
    ci_job: Option<String>,
}

enum CliError {
    Read(io::Error),
    TooLarge,
    InvalidUtf8,
    Parse(ParseError),
    PreviousRead,
    PreviousTooLarge,
    ProcessingResult(ProcessingResultError),
    CrashProcessing(CrashProcessingError),
    RequestRead,
    Request(CrashRequestError),
    Symbolicate(SymbolicationError),
    Scan(ScanError),
    Serialize(serde_json::Error),
    Processor(processor::ProcessorError),
    Upload(symbol_upload::UploadError),
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
            Self::PreviousRead => formatter.write_str("failed to read previous processing result"),
            Self::PreviousTooLarge => write!(
                formatter,
                "previous processing result exceeds {MAX_PREVIOUS_RESULT_BYTES}-byte limit"
            ),
            Self::ProcessingResult(error) => error.fmt(formatter),
            Self::CrashProcessing(error) => error.fmt(formatter),
            Self::RequestRead => write!(formatter, "failed to read crash request"),
            Self::Request(error) => error.fmt(formatter),
            Self::Symbolicate(error) => error.fmt(formatter),
            Self::Scan(error) => error.fmt(formatter),
            Self::Serialize(error) => write!(formatter, "failed to serialize output: {error}"),
            Self::Processor(error) => error.fmt(formatter),
            Self::Upload(error) => error.fmt(formatter),
            Self::Write(error) => write!(formatter, "failed to write output: {error}"),
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(match &error {
                CliError::Upload(error) => error.exit_code(),
                _ => 1,
            })
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
        Some(Command::Symbols(SymbolsCommand::Upload(upload))) => {
            symbol_upload::upload(&symbol_upload::UploadOptions {
                path: upload.path,
                project: upload.project,
                release: upload.release,
                api_url: upload.api_url,
                token: upload.token,
                architecture: upload.architecture,
                configuration: upload.configuration,
                revision: upload.revision,
                channel: upload.channel,
                build_timestamp: upload.build_timestamp,
                ci_job: upload.ci_job,
            })
            .map_err(CliError::Upload)
        }
        Some(Command::Processor(command)) => processor::run(command).map_err(CliError::Processor),
        None => {
            println!("FaultLane CLI is ready");
            Ok(())
        }
    }
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
    let previous = previous
        .map(read_previous_bytes)
        .transpose()?
        .map(|bytes| {
            let identity = crash_guid(&crash_context).map_err(CliError::ProcessingResult)?;
            parse_previous_processing(&bytes, identity).map_err(CliError::ProcessingResult)
        })
        .transpose()?;
    let symbolication = symbolicate_minidump(dump, symbols, SymbolicationLimits::default())
        .map_err(CliError::Symbolicate)?;
    let result =
        build_processing_result(&crash_context, &symbolication, previous, None, None, None)
            .map_err(CliError::ProcessingResult)?;
    write_json(&result)
}

fn process_crash_request(
    request: &Path,
    symbols: &Path,
    previous: Option<&Path>,
) -> Result<(), CliError> {
    let file = File::open(request).map_err(|_| CliError::RequestRead)?;
    let previous = previous.map(read_previous_bytes).transpose()?;
    let result = process_request(file, symbols, &[], previous.as_deref())
        .map_err(CliError::CrashProcessing)?;
    write_json(&result)
}

fn write_json(result: &impl Serialize) -> Result<(), CliError> {
    let stdout = io::stdout();
    let mut output = stdout.lock();

    serde_json::to_writer(&mut output, result).map_err(CliError::Serialize)?;
    writeln!(output).map_err(CliError::Write)
}

fn read_previous_bytes(path: &Path) -> Result<Vec<u8>, CliError> {
    let file = File::open(path).map_err(|_| CliError::PreviousRead)?;
    let mut bytes = Vec::new();
    file.take(MAX_PREVIOUS_RESULT_READ_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|_| CliError::PreviousRead)?;
    if bytes.len() > MAX_PREVIOUS_RESULT_BYTES {
        return Err(CliError::PreviousTooLarge);
    }
    Ok(bytes)
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

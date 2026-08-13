use std::{
    fmt,
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use cachelane_symbols::{ScanError, scan_artifacts};
use cachelane_unreal::{CrashContextExtractionOptions, CrashContextParser, ParseError};
use clap::{Parser, Subcommand};

const MAX_CRASH_CONTEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_CRASH_CONTEXT_READ_BYTES: u64 = 4 * 1024 * 1024 + 1;
const MAX_CRASH_CONTEXT_NODES: u32 = 100_000;

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
    Parse { path: PathBuf },
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
        Some(Command::Symbols(SymbolsCommand::Scan { path })) => scan_symbols(&path),
        None => {
            println!("CacheLane CLI is ready");
            Ok(())
        }
    }
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

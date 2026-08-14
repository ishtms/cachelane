use std::{
    error::Error,
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{Arc, Mutex},
    thread,
};

use flate2::{Compression, write::ZlibEncoder};

#[path = "../../../crates/symbols/tests/support/mod.rs"]
mod symbol_support;

use symbol_support::{GUID, TestDirectory, write_pdb, write_pe};

const MAX_CRASH_CONTEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_PREVIOUS_RESULT_BYTES: u64 = 64 * 1024 * 1024;

struct TempInput {
    path: PathBuf,
}

impl TempInput {
    fn new(name: &str, contents: &[u8]) -> Result<Self, std::io::Error> {
        let path =
            std::env::temp_dir().join(format!("faultlane-cli-{}-{name}", std::process::id()));
        fs::write(&path, contents)?;
        Ok(Self { path })
    }

    fn with_size(name: &str, size: u64) -> Result<Self, std::io::Error> {
        let path =
            std::env::temp_dir().join(format!("faultlane-cli-{}-{name}", std::process::id()));
        let file = fs::File::create(&path)?;
        file.set_len(size)?;
        Ok(Self { path })
    }
}

impl Drop for TempInput {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn run_parse(path: &Path) -> Result<Output, std::io::Error> {
    Command::new(env!("CARGO_BIN_EXE_faultlane"))
        .args(["crash", "parse"])
        .arg(path)
        .output()
}

fn run_unpack(path: &Path) -> Result<Output, std::io::Error> {
    Command::new(env!("CARGO_BIN_EXE_faultlane"))
        .args(["crash", "unpack"])
        .arg(path)
        .output()
}

fn run_scan(path: &Path) -> Result<Output, std::io::Error> {
    Command::new(env!("CARGO_BIN_EXE_faultlane"))
        .args(["symbols", "scan"])
        .arg(path)
        .output()
}

fn run_upload(path: &Path, api_url: &str) -> Result<Output, std::io::Error> {
    Command::new(env!("CARGO_BIN_EXE_faultlane"))
        .args(["symbols", "upload"])
        .arg(path)
        .args([
            "--project",
            "faultlane-proof",
            "--release",
            "1.0.0",
            "--api-url",
            api_url,
            "--token",
            "clsu_0000000000000000000000000000000000000000000000000000000000000000",
            "--configuration",
            "shipping",
        ])
        .output()
}

fn run_symbolicate(dump: &Path, symbols: &Path) -> Result<Output, std::io::Error> {
    Command::new(env!("CARGO_BIN_EXE_faultlane"))
        .args(["crash", "symbolicate"])
        .arg(dump)
        .arg("--symbols")
        .arg(symbols)
        .output()
}

fn run_process(
    dump: &Path,
    crash_context: &Path,
    symbols: &Path,
    previous: Option<&Path>,
) -> Result<Output, std::io::Error> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_faultlane"));
    command
        .args(["crash", "process"])
        .arg(dump)
        .arg("--crash-context")
        .arg(crash_context)
        .arg("--symbols")
        .arg(symbols);
    if let Some(previous) = previous {
        command.arg("--previous").arg(previous);
    }
    command.output()
}

fn run_request_process(
    request: &Path,
    symbols: &Path,
    previous: Option<&Path>,
) -> Result<Output, std::io::Error> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_faultlane"));
    command
        .args(["crash", "process"])
        .arg(request)
        .arg("--symbols")
        .arg(symbols);
    if let Some(previous) = previous {
        command.arg("--previous").arg(previous);
    }
    command.output()
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn write_i32(output: &mut Vec<u8>, value: i32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn write_ansi_field(output: &mut Vec<u8>, value: &str) {
    write_i32(output, 260);
    output.extend_from_slice(value.as_bytes());
    output.resize(output.len() + 260 - value.len(), 0);
}

fn crash_request(files: &[(&str, &[u8])]) -> Result<Vec<u8>, std::io::Error> {
    let mut expanded = Vec::new();
    expanded.extend_from_slice(b"CR1");
    write_ansi_field(&mut expanded, "UECC-Windows-Synthetic");
    write_ansi_field(&mut expanded, "UECC-Windows-Synthetic.uecrash");
    let expanded_size_offset = expanded.len();
    write_i32(&mut expanded, 0);
    write_i32(
        &mut expanded,
        i32::try_from(files.len()).map_err(std::io::Error::other)?,
    );

    for (index, (name, contents)) in files.iter().enumerate() {
        write_i32(
            &mut expanded,
            i32::try_from(index).map_err(std::io::Error::other)?,
        );
        write_ansi_field(&mut expanded, name);
        write_i32(
            &mut expanded,
            i32::try_from(contents.len()).map_err(std::io::Error::other)?,
        );
        expanded.extend_from_slice(contents);
    }

    let expanded_size = i32::try_from(expanded.len()).map_err(std::io::Error::other)?;
    expanded[expanded_size_offset..expanded_size_offset + 4]
        .copy_from_slice(&expanded_size.to_le_bytes());
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&expanded)?;
    encoder.finish()
}

#[derive(Default)]
struct UploadServerState {
    fail_first: bool,
    resume_first: bool,
    negotiate_calls: usize,
    uploaded_parts: usize,
    recorded_parts: usize,
    complete_calls: usize,
    uploaded_bytes: Vec<u8>,
    request_error: Option<String>,
}

struct UploadServer {
    address: String,
    state: Arc<Mutex<UploadServerState>>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl UploadServer {
    fn start() -> Result<Self, std::io::Error> {
        Self::start_with_state(UploadServerState::default())
    }

    fn start_resumed() -> Result<Self, std::io::Error> {
        Self::start_with_state(UploadServerState {
            resume_first: true,
            ..UploadServerState::default()
        })
    }

    fn start_retryable_failure() -> Result<Self, std::io::Error> {
        Self::start_with_state(UploadServerState {
            fail_first: true,
            ..UploadServerState::default()
        })
    }

    fn start_with_state(initial_state: UploadServerState) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = format!("http://{}", listener.local_addr()?);
        let state = Arc::new(Mutex::new(initial_state));
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread_state = state.clone();
        let thread_shutdown = shutdown.clone();
        let thread_address = address.clone();
        let handle = thread::spawn(move || {
            while !thread_shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if let Err(error) =
                            handle_upload_request(stream, &thread_address, &thread_state)
                            && let Ok(mut state) = thread_state.lock()
                        {
                            state.request_error = Some(error.to_string());
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            address,
            state,
            shutdown,
            thread: Some(handle),
        })
    }
}

impl Drop for UploadServer {
    fn drop(&mut self) {
        self.shutdown
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = TcpStream::connect(self.address.trim_start_matches("http://"));
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

#[allow(clippy::too_many_lines)]
fn handle_upload_request(
    mut stream: TcpStream,
    address: &str,
    state: &Mutex<UploadServerState>,
) -> Result<(), std::io::Error> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    let (method, path, headers, body) = read_http_request(&mut stream)?;
    if path.starts_with("/api/") {
        assert_eq!(
            headers.get("authorization").map(String::as_str),
            Some("Bearer clsu_0000000000000000000000000000000000000000000000000000000000000000")
        );
    } else {
        assert!(!headers.contains_key("authorization"));
    }
    let (status, response_headers, response_body) = match (method.as_str(), path.as_str()) {
        ("POST", "/api/v1/projects/faultlane-proof/artifact-uploads") => {
            let request: serde_json::Value = serde_json::from_slice(&body)?;
            assert_eq!(request["release"]["platform"], "windows");
            assert_eq!(request["release"]["configuration"], "shipping");
            assert_eq!(request["artifacts"].as_array().map(Vec::len), Some(2));
            let mut state = state
                .lock()
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            state.negotiate_calls += 1;
            let artifact = &request["artifacts"][0];
            if state.fail_first && state.negotiate_calls == 1 {
                (
                    "503 Service Unavailable",
                    vec![("content-type", "application/json")],
                    br#"{"code":"upload_unavailable","message":"artifact upload is temporarily unavailable","retryable":true}"#.to_vec(),
                )
            } else if state.negotiate_calls == 1 || (state.fail_first && state.negotiate_calls == 2)
            {
                let completed_parts = if state.resume_first {
                    vec![serde_json::json!({
                        "part_number": 1,
                        "byte_size": artifact["byte_size"],
                        "content_md5": "AAAAAAAAAAAAAAAAAAAAAA=="
                    })]
                } else {
                    Vec::new()
                };
                (
                    "200 OK",
                    vec![("content-type", "application/json")],
                    serde_json::to_vec(&serde_json::json!({
                        "release": release_json(),
                        "artifacts": [
                            {
                                "path": artifact["path"],
                                "sha256": artifact["sha256"],
                                "status": "upload_required",
                                "upload": {
                                    "id": "upload-1",
                                    "part_size": artifact["byte_size"],
                                    "part_count": 1,
                                    "completed_parts": completed_parts
                                }
                            },
                            {
                                "path": request["artifacts"][1]["path"],
                                "sha256": request["artifacts"][1]["sha256"],
                                "status": "already_present"
                            },
                        ],
                        "coverage": coverage_json(1, 1)
                    }))?,
                )
            } else {
                let artifacts = request["artifacts"]
                    .as_array()
                    .ok_or_else(|| std::io::Error::other("missing artifacts"))?
                    .iter()
                    .map(|artifact| {
                        serde_json::json!({
                            "path": artifact["path"],
                            "sha256": artifact["sha256"],
                            "status": "already_present"
                        })
                    })
                    .collect::<Vec<_>>();
                (
                    "200 OK",
                    vec![("content-type", "application/json")],
                    serde_json::to_vec(&serde_json::json!({
                        "release": release_json(),
                        "artifacts": artifacts,
                        "coverage": coverage_json(2, 0)
                    }))?,
                )
            }
        }
        ("POST", "/api/v1/artifact-uploads/upload-1/parts") => {
            let request: serde_json::Value = serde_json::from_slice(&body)?;
            (
                "200 OK",
                vec![("content-type", "application/json")],
                serde_json::to_vec(&serde_json::json!({
                    "method": "PUT",
                    "url": format!("{address}/object/upload-1/1"),
                    "headers": {
                        "content-length": request["byte_size"].as_i64().unwrap_or_default().to_string(),
                        "content-md5": request["content_md5"]
                    },
                    "expires_in_seconds": 600
                }))?,
            )
        }
        ("PUT", "/object/upload-1/1") => {
            let mut state = state
                .lock()
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            state.uploaded_parts += 1;
            state.uploaded_bytes = body;
            ("200 OK", vec![("etag", "\"part-etag\"")], Vec::new())
        }
        ("PATCH", "/api/v1/artifact-uploads/upload-1/parts/1") => {
            let request: serde_json::Value = serde_json::from_slice(&body)?;
            assert_eq!(request["etag"], "\"part-etag\"");
            let mut state = state
                .lock()
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            state.recorded_parts += 1;
            ("204 No Content", Vec::new(), Vec::new())
        }
        ("POST", "/api/v1/artifact-uploads/upload-1/complete") => {
            let mut state = state
                .lock()
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            state.complete_calls += 1;
            (
                "200 OK",
                vec![("content-type", "application/json")],
                serde_json::to_vec(&serde_json::json!({
                    "release_id": "release-1",
                    "artifact_status": "available",
                    "coverage": coverage_json(2, 0)
                }))?,
            )
        }
        ("GET", "/api/v1/releases/release-1/coverage") => (
            "200 OK",
            vec![("content-type", "application/json")],
            serde_json::to_vec(&serde_json::json!({
                "release": release_json(),
                "coverage": coverage_json(2, 0)
            }))?,
        ),
        _ => (
            "404 Not Found",
            vec![("content-type", "application/json")],
            br#"{"code":"not_found","message":"resource was not found","retryable":false}"#
                .to_vec(),
        ),
    };
    write_http_response(&mut stream, status, &response_headers, &response_body)
}

fn release_json() -> serde_json::Value {
    serde_json::json!({
        "id": "release-1",
        "version": "1.0.0",
        "platform": "windows",
        "architecture": "x86_64",
        "configuration": "shipping",
        "revision": null
    })
}

fn coverage_json(available: u64, missing: u64) -> serde_json::Value {
    serde_json::json!({
        "total": available + missing,
        "available": available,
        "missing": missing,
        "mismatch": 0,
        "processing": 0,
        "quarantined": 0,
        "ready": missing == 0
    })
}

type HttpRequest = (
    String,
    String,
    std::collections::HashMap<String, String>,
    Vec<u8>,
);

fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest, std::io::Error> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    let header_end = loop {
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            return Err(std::io::Error::other("request ended before headers"));
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.len() > 1024 * 1024 {
            return Err(std::io::Error::other("request headers too large"));
        }
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers_text = std::str::from_utf8(&bytes[..header_end]).map_err(std::io::Error::other)?;
    let mut lines = headers_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| std::io::Error::other("missing request line"))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or_default().to_owned();
    let path = request_parts.next().unwrap_or_default().to_owned();
    let mut headers = std::collections::HashMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| std::io::Error::other("invalid header"))?;
        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
    }
    let content_length = headers
        .get("content-length")
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(std::io::Error::other)?
        .unwrap_or_default();
    let mut body = bytes[header_end..].to_vec();
    while body.len() < content_length {
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            return Err(std::io::Error::other("request body ended early"));
        }
        body.extend_from_slice(&buffer[..count]);
    }
    body.truncate(content_length);
    Ok((method, path, headers, body))
}

fn write_http_response(
    stream: &mut TcpStream,
    status: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<(), std::io::Error> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    )?;
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    stream.write_all(b"\r\n")?;
    stream.write_all(body)?;
    stream.flush()
}

#[test]
fn help_identifies_the_cli() -> Result<(), std::io::Error> {
    let output = Command::new(env!("CARGO_BIN_EXE_faultlane"))
        .arg("--help")
        .output()?;

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("FaultLane command line tools"));
    Ok(())
}

#[test]
fn version_matches_the_package() -> Result<(), std::io::Error> {
    let output = Command::new(env!("CARGO_BIN_EXE_faultlane"))
        .arg("--version")
        .output()?;

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        format!("faultlane {}", env!("CARGO_PKG_VERSION"))
    );
    Ok(())
}

#[test]
fn no_arguments_keeps_the_readiness_message() -> Result<(), std::io::Error> {
    let output = Command::new(env!("CARGO_BIN_EXE_faultlane")).output()?;

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "FaultLane CLI is ready\n"
    );
    Ok(())
}

#[test]
fn uploads_only_missing_artifacts_and_second_run_transfers_zero_bytes() -> Result<(), Box<dyn Error>>
{
    let server = UploadServer::start()?;
    let fixtures = fixture("windows-symbolication");
    let first = run_upload(&fixtures, &server.address)?;

    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(first.stderr.is_empty());
    let first_result: serde_json::Value = serde_json::from_slice(&first.stdout)?;
    assert_eq!(first_result["schema_version"], 1);
    assert_eq!(first_result["artifacts_scanned"], 2);
    assert_eq!(first_result["uploaded"], 1);
    assert_eq!(first_result["already_present"], 1);
    assert!(
        first_result["bytes_transferred"]
            .as_u64()
            .is_some_and(|value| value > 0)
    );
    assert_eq!(first_result["coverage"], coverage_json(2, 0));

    let second = run_upload(&fixtures, &server.address)?;
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(second.stderr.is_empty());
    let second_result: serde_json::Value = serde_json::from_slice(&second.stdout)?;
    assert_eq!(second_result["release"], first_result["release"]);
    assert_eq!(second_result["coverage"], first_result["coverage"]);
    assert_eq!(second_result["uploaded"], 0);
    assert_eq!(second_result["already_present"], 2);
    assert_eq!(second_result["bytes_transferred"], 0);

    let third = run_upload(&fixtures, &server.address)?;
    assert!(
        third.status.success(),
        "{}",
        String::from_utf8_lossy(&third.stderr)
    );
    assert_eq!(third.stdout, second.stdout);

    let state = server
        .state
        .lock()
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    assert_eq!(state.negotiate_calls, 3);
    assert_eq!(state.uploaded_parts, 1);
    assert_eq!(state.recorded_parts, 1);
    assert_eq!(state.complete_calls, 1);
    assert!(!state.uploaded_bytes.is_empty());
    Ok(())
}

#[test]
fn upload_rejects_non_https_remote_api_urls() -> Result<(), Box<dyn Error>> {
    let output = run_upload(&fixture("windows-symbolication"), "http://example.com")?;

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr)?,
        "URL must use HTTPS or literal loopback HTTP\n"
    );
    Ok(())
}

#[test]
fn upload_resumes_without_retransmitting_completed_parts() -> Result<(), Box<dyn Error>> {
    let server = UploadServer::start_resumed()?;
    let output = run_upload(&fixture("windows-symbolication"), &server.address)?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(result["uploaded"], 1);
    assert_eq!(result["already_present"], 1);
    assert_eq!(result["bytes_transferred"], 0);
    assert_eq!(result["coverage"], coverage_json(2, 0));

    let state = server
        .state
        .lock()
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    assert_eq!(state.negotiate_calls, 1);
    assert_eq!(state.uploaded_parts, 0);
    assert_eq!(state.recorded_parts, 0);
    assert_eq!(state.complete_calls, 1);
    Ok(())
}

#[test]
fn upload_recovers_from_a_retryable_service_failure() -> Result<(), Box<dyn Error>> {
    let server = UploadServer::start_retryable_failure()?;
    let fixtures = fixture("windows-symbolication");
    let failed = run_upload(&fixtures, &server.address)?;

    assert_eq!(failed.status.code(), Some(4));
    assert!(failed.stdout.is_empty());
    assert_eq!(
        String::from_utf8(failed.stderr)?,
        "artifact upload failed and can be retried\n"
    );

    let recovered = run_upload(&fixtures, &server.address)?;
    let request_error = server
        .state
        .lock()
        .ok()
        .and_then(|state| state.request_error.clone());
    assert!(
        recovered.status.success(),
        "{}; server error: {request_error:?}",
        String::from_utf8_lossy(&recovered.stderr),
    );
    let result: serde_json::Value = serde_json::from_slice(&recovered.stdout)?;
    assert_eq!(result["uploaded"], 1);
    assert_eq!(result["coverage"], coverage_json(2, 0));

    let state = server
        .state
        .lock()
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    assert_eq!(state.negotiate_calls, 2);
    assert_eq!(state.uploaded_parts, 1);
    assert_eq!(state.complete_calls, 1);
    Ok(())
}

#[test]
fn parses_crash_context_to_stable_json() -> Result<(), Box<dyn Error>> {
    let input = fixture("crash-context.xml");
    let first = run_parse(&input)?;
    let second = run_parse(&input)?;
    let expected = concat!(
        r#"{"parser_version":1,"crash_guid":"UECC-Synthetic-150","crash_type":"assert","error_message":null,"build_version":null,"engine_version":"5.8.1-56057345","platform":{"original":"Win64","normalized":"windows"},"architecture":null,"build_configuration":null,"modules":[],"threads":[],"system_metadata":[],"user_comment":null,"game_data":[{"name":"MapName","value":"Arena"}],"unknown_fields":{"FutureProperties":{"Zulu":["value"]},"RuntimeProperties":{"FutureField":["kept"]}}}"#,
        "\n"
    );

    assert!(first.status.success());
    assert!(first.stderr.is_empty());
    assert_eq!(String::from_utf8(first.stdout.clone())?, expected);
    assert_eq!(first.stdout, second.stdout);
    assert!(!String::from_utf8(second.stdout)?.contains("do-not-print"));
    Ok(())
}

#[test]
fn unpacks_crash_request_to_stable_json() -> Result<(), Box<dyn Error>> {
    let xml = b"<FGenericCrashContext/>";
    let log = b"LogFaultLane: synthetic\n";
    let unknown = b"future";
    let request = crash_request(&[
        ("CrashContext.runtime-xml", xml),
        ("Synthetic.log", log),
        ("Future.bin", unknown),
    ])?;
    let input = TempInput::new("valid.uecrash", &request)?;
    let first = run_unpack(&input.path)?;
    let second = run_unpack(&input.path)?;
    let expected = format!(
        concat!(
            r#"{{"schema_version":1,"envelope":"cr1","directory_name":"UECC-Windows-Synthetic","archive_name":"UECC-Windows-Synthetic.uecrash","compressed_size":{},"expanded_size":{},"files":["#,
            r#"{{"index":0,"name":"CrashContext.runtime-xml","size":{},"kind":"crash_context"}},"#,
            r#"{{"index":1,"name":"Synthetic.log","size":{},"kind":"log"}},"#,
            r#"{{"index":2,"name":"Future.bin","size":{},"kind":"unknown"}}]}}"#,
            "\n"
        ),
        request.len(),
        539 + (272 * 3) + xml.len() + log.len() + unknown.len(),
        xml.len(),
        log.len(),
        unknown.len()
    );

    assert!(first.status.success());
    assert!(first.stderr.is_empty());
    assert_eq!(String::from_utf8(first.stdout.clone())?, expected);
    assert_eq!(first.stdout, second.stdout);
    Ok(())
}

#[test]
fn rejects_unsafe_crash_requests_without_echoing_input() -> Result<(), Box<dyn Error>> {
    let dtd = crash_request(&[(
        "CrashContext.runtime-xml",
        br#"<!DOCTYPE FGenericCrashContext [<!ENTITY secret "do-not-echo">]><FGenericCrashContext/>"#,
    )])?;
    let traversal = crash_request(&[("../do-not-echo.txt", b"secret")])?;
    let duplicate = crash_request(&[
        ("CrashContext.runtime-xml", b"<FGenericCrashContext/>"),
        ("CrashContext.runtime-xml", b"<FGenericCrashContext/>"),
    ])?;
    let mut truncated = crash_request(&[("CrashContext.runtime-xml", b"<FGenericCrashContext/>")])?;
    truncated.truncate(truncated.len() / 2);

    for (name, request, expected) in [
        ("dtd.uecrash", dtd, "DTD is forbidden"),
        (
            "traversal.uecrash",
            traversal,
            "unsafe crash request filename",
        ),
        (
            "duplicate.uecrash",
            duplicate,
            "duplicate critical crash file",
        ),
        (
            "truncated.uecrash",
            truncated,
            "truncated crash request archive",
        ),
        (
            "malformed.uecrash",
            b"do-not-echo".to_vec(),
            "invalid crash request compression",
        ),
    ] {
        let input = TempInput::new(name, &request)?;
        let output = run_unpack(&input.path)?;
        let stderr = String::from_utf8(output.stderr)?;

        assert!(!output.status.success(), "{name}");
        assert!(output.stdout.is_empty());
        assert!(stderr.contains(expected), "{name}: {stderr}");
        assert!(!stderr.contains("do-not-echo"));
    }
    Ok(())
}

#[test]
fn rejects_unsafe_xml_without_echoing_input() -> Result<(), Box<dyn Error>> {
    for (name, input, expected) in [
        (
            "malformed.xml",
            b"<FGenericCrashContext><Secret>do-not-echo</FGenericCrashContext>".as_slice(),
            "invalid crash context XML",
        ),
        (
            "dtd.xml",
            br#"<!DOCTYPE FGenericCrashContext [<!ENTITY secret "do-not-echo">]>
<FGenericCrashContext><Secret>&secret;</Secret></FGenericCrashContext>"#
                .as_slice(),
            "DTD is forbidden",
        ),
        (
            "wrong-root.xml",
            b"<SecretRoot>do-not-echo</SecretRoot>".as_slice(),
            "unexpected crash context XML root",
        ),
    ] {
        let input = TempInput::new(name, input)?;
        let output = run_parse(&input.path)?;
        let stderr = String::from_utf8(output.stderr)?;

        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(stderr.contains(expected));
        assert!(!stderr.contains("do-not-echo"));
        assert!(!stderr.contains("SecretRoot"));
    }
    Ok(())
}

#[test]
fn rejects_invalid_utf8() -> Result<(), Box<dyn Error>> {
    let input = TempInput::new("invalid-utf8.xml", b"<FGenericCrashContext>\xff")?;
    let output = run_parse(&input.path)?;

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr)?.contains("must be UTF-8"));
    Ok(())
}

#[test]
fn rejects_oversized_input() -> Result<(), Box<dyn Error>> {
    let input = TempInput::new("oversized.xml", &vec![b'x'; MAX_CRASH_CONTEXT_BYTES + 1])?;
    let output = run_parse(&input.path)?;

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr)?.contains("4194304-byte limit"));
    Ok(())
}

#[test]
fn rejects_the_xml_node_limit() -> Result<(), Box<dyn Error>> {
    let mut xml = String::from("<FGenericCrashContext>");
    xml.push_str(&"<N/>".repeat(100_000));
    xml.push_str("</FGenericCrashContext>");
    let input = TempInput::new("node-limit.xml", xml.as_bytes())?;
    let output = run_parse(&input.path)?;

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr)?.contains("node limit exceeded"));
    Ok(())
}

#[test]
fn reports_missing_files_without_echoing_the_path() -> Result<(), Box<dyn Error>> {
    let missing = std::env::temp_dir().join(format!(
        "faultlane-cli-{}-private-do-not-echo.xml",
        std::process::id()
    ));
    let output = run_parse(&missing)?;
    let stderr = String::from_utf8(output.stderr)?;

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(stderr.contains("failed to read crash context"));
    assert!(!stderr.contains("private-do-not-echo"));
    Ok(())
}

#[test]
fn scans_windows_artifacts_to_stable_json() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new("cli-matched")?;
    write_pe(
        &directory.path().join("bin/Game.exe"),
        GUID,
        1,
        "Game.pdb",
        false,
    )?;
    write_pdb(&directory.path().join("symbols/Game.pdb"), GUID, 2, 1)?;

    let first = run_scan(directory.path())?;
    let second = run_scan(directory.path())?;
    let expected = concat!(
        r#"{"schema_version":1,"artifacts":[{"path":"bin/Game.exe","module":"Game.exe","artifact_type":"pe_executable","architecture":"x86_64","size":1024,"debug_id":"00112233-4455-6677-8899-AABBCCDDEEFF-1","code_id":"123456782000","match_state":"matched","matches":["symbols/Game.pdb"],"error":null},{"path":"symbols/Game.pdb","module":"Game.pdb","artifact_type":"pdb","architecture":"x86_64","size":4096,"debug_id":"00112233-4455-6677-8899-AABBCCDDEEFF-2","code_id":null,"match_state":"matched","matches":["bin/Game.exe"],"error":null}]}"#,
        "\n"
    );

    assert!(first.status.success());
    assert!(first.stderr.is_empty());
    assert_eq!(String::from_utf8(first.stdout.clone())?, expected);
    assert_eq!(first.stdout, second.stdout);
    Ok(())
}

#[test]
fn scan_errors_do_not_echo_the_root_path() -> Result<(), Box<dyn Error>> {
    let missing = std::env::temp_dir().join(format!(
        "faultlane-symbols-{}-private-do-not-echo",
        std::process::id()
    ));
    let output = run_scan(&missing)?;
    let stderr = String::from_utf8(output.stderr)?;

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(stderr.contains("failed to inspect artifact path"));
    assert!(!stderr.contains("private-do-not-echo"));
    Ok(())
}

#[test]
fn symbolicates_a_windows_minidump_to_stable_json() -> Result<(), Box<dyn Error>> {
    let directory = fixture("windows-symbolication");
    let dump = directory.join("faultlane-symbolication.dmp");
    let first = run_symbolicate(&dump, &directory)?;
    let second = run_symbolicate(&dump, &directory)?;

    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(first.stderr.is_empty());
    assert_eq!(first.stdout, second.stdout);
    let result: serde_json::Value = serde_json::from_slice(&first.stdout)?;
    let threads = result["threads"].as_array().ok_or("missing threads")?;
    assert!(threads[0]["faulting"].as_bool().is_some_and(|value| value));
    assert!(
        result["modules"]
            .as_array()
            .ok_or("missing modules")?
            .iter()
            .any(|module| {
                module["module"] == "faultlane-symbolication.exe"
                    && module["status"] == "matched"
                    && module["code_id"] == "14F736966000"
                    && module["debug_id"] == "794DF05F-2D04-EFA3-A764-F49ED2297069-3"
            })
    );
    let frames = threads[0]["frames"].as_array().ok_or("missing frames")?;
    let crash = frames
        .iter()
        .find(|frame| frame["function"] == "CrashFixture()")
        .ok_or("missing fixture frame")?;
    assert_eq!(crash["symbol_status"], "resolved");
    assert_eq!(crash["source_file"], r"Z:\source.cpp");
    assert_eq!(crash["source_line"], 16);
    assert!(crash["inlines"].as_array().is_some_and(|inlines| {
        inlines
            .iter()
            .any(|inline| inline["function"] == "RaiseFixtureException(long*)")
    }));
    Ok(())
}

#[test]
fn keeps_partial_frames_for_missing_and_mismatched_symbols() -> Result<(), Box<dyn Error>> {
    let fixture_directory = fixture("windows-symbolication");
    let dump = fixture_directory.join("faultlane-symbolication.dmp");
    let missing = TestDirectory::new("symbolicate-missing")?;
    fs::copy(
        fixture_directory.join("faultlane-symbolication.exe"),
        missing.path().join("faultlane-symbolication.exe"),
    )?;
    let missing_output = run_symbolicate(&dump, missing.path())?;
    assert!(missing_output.status.success());
    let missing_result: serde_json::Value = serde_json::from_slice(&missing_output.stdout)?;
    assert!(
        missing_result["modules"]
            .as_array()
            .is_some_and(|modules| modules.iter().any(|module| {
                module["module"] == "faultlane-symbolication.exe"
                    && module["status"] == "missing_pdb"
            }))
    );
    assert!(
        missing_result["threads"][0]["frames"]
            .as_array()
            .is_some_and(|frames| !frames.is_empty())
    );

    let mismatched = TestDirectory::new("symbolicate-mismatched")?;
    write_pe(
        &mismatched.path().join("faultlane-symbolication.exe"),
        GUID,
        1,
        "faultlane-symbolication.pdb",
        false,
    )?;
    let mismatched_output = run_symbolicate(&dump, mismatched.path())?;
    assert!(mismatched_output.status.success());
    let mismatched_result: serde_json::Value = serde_json::from_slice(&mismatched_output.stdout)?;
    assert!(
        mismatched_result["modules"]
            .as_array()
            .is_some_and(|modules| modules.iter().any(|module| {
                module["module"] == "faultlane-symbolication.exe"
                    && module["status"] == "mismatched"
            }))
    );
    Ok(())
}

#[test]
fn symbolication_errors_do_not_echo_private_inputs() -> Result<(), Box<dyn Error>> {
    let input = TempInput::new("private-do-not-echo.dmp", b"private-do-not-echo")?;
    let symbols = TestDirectory::new("symbolicate-errors")?;
    let output = run_symbolicate(&input.path, symbols.path())?;
    let stderr = String::from_utf8(output.stderr)?;

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(stderr.contains("invalid minidump"));
    assert!(!stderr.contains("private-do-not-echo"));
    Ok(())
}

#[test]
fn reprocesses_a_partial_crash_after_symbols_arrive() -> Result<(), Box<dyn Error>> {
    let directory = fixture("windows-symbolication");
    let dump = directory.join("faultlane-symbolication.dmp");
    let crash_context = fixture("crash-context.xml");
    let empty_symbols = TestDirectory::new("process-empty")?;
    let first = run_process(&dump, &crash_context, empty_symbols.path(), None)?;

    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(first.stderr.is_empty());
    let partial: serde_json::Value = serde_json::from_slice(&first.stdout)?;
    assert_eq!(partial["schema_version"], 1);
    assert_eq!(partial["crash_guid"], "UECC-Synthetic-150");
    assert_eq!(partial["crash_context"]["parser_version"], 1);
    assert_eq!(partial["current"]["processing_version"], 1);
    assert_eq!(partial["current"]["parser_version"], 1);
    assert!(partial["history"].as_array().is_some_and(Vec::is_empty));
    assert!(
        partial["current"]["symbolication"]["modules"]
            .as_array()
            .is_some_and(|modules| modules.iter().any(|module| {
                module["module"] == "faultlane-symbolication.exe"
                    && module["status"] == "missing_pe"
                    && module["code_id"] == "14F736966000"
                    && module["debug_id"] == "794DF05F-2D04-EFA3-A764-F49ED2297069-3"
            }))
    );
    assert!(
        partial["current"]["symbolication"]["threads"][0]["frames"]
            .as_array()
            .is_some_and(|frames| !frames.is_empty())
    );

    let previous = TempInput::new("process-partial.json", &first.stdout)?;
    let second = run_process(&dump, &crash_context, &directory, Some(&previous.path))?;
    let repeated = run_process(&dump, &crash_context, &directory, Some(&previous.path))?;

    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(second.stderr.is_empty());
    assert_eq!(second.stdout, repeated.stdout);
    let resolved: serde_json::Value = serde_json::from_slice(&second.stdout)?;
    let history = resolved["history"].as_array().ok_or("missing history")?;
    assert_eq!(history, &[partial["current"].clone()]);
    assert_eq!(
        history[0]["symbolication"]["symbolicator_version"],
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(
        history[0]["symbolication"]["minidump_processor_version"],
        "0.27.0"
    );
    assert!(
        resolved["current"]["symbolication"]["threads"][0]["frames"]
            .as_array()
            .is_some_and(|frames| frames
                .iter()
                .any(|frame| frame["function"] == "CrashFixture()"))
    );

    let resolved_input = TempInput::new("process-resolved.json", &second.stdout)?;
    let unchanged = run_process(
        &dump,
        &crash_context,
        &directory,
        Some(&resolved_input.path),
    )?;
    assert!(unchanged.status.success());
    assert_eq!(unchanged.stdout, second.stdout);
    Ok(())
}

#[test]
fn rejects_invalid_previous_results_without_echoing_input() -> Result<(), Box<dyn Error>> {
    let directory = fixture("windows-symbolication");
    let dump = directory.join("faultlane-symbolication.dmp");
    let crash_context = fixture("crash-context.xml");
    let attempt = serde_json::json!({
        "processing_version": 1,
        "parser_version": 1,
        "symbolication": {}
    });
    let valid = serde_json::json!({
        "schema_version": 1,
        "crash_guid": "UECC-Synthetic-150",
        "crash_context": {},
        "current": attempt,
        "history": []
    });
    let mut unsupported_schema = valid.clone();
    unsupported_schema["schema_version"] = 2.into();
    let mut unsupported_processing = valid.clone();
    unsupported_processing["current"]["processing_version"] = 2.into();
    let mut mismatch = valid.clone();
    mismatch["crash_guid"] = "private-do-not-echo".into();
    let mut excessive_history = valid.clone();
    excessive_history["history"] = serde_json::Value::Array(vec![attempt.clone(); 17]);
    let mut nested_history = valid;
    nested_history["current"]["history"] = serde_json::json!([]);

    let cases = [
        (
            "malformed-previous.json",
            b"private-do-not-echo".to_vec(),
            "invalid previous processing result",
        ),
        (
            "unsupported-schema.json",
            serde_json::to_vec(&unsupported_schema)?,
            "unsupported previous result schema version",
        ),
        (
            "unsupported-processing.json",
            serde_json::to_vec(&unsupported_processing)?,
            "unsupported previous processing version",
        ),
        (
            "identity-mismatch.json",
            serde_json::to_vec(&mismatch)?,
            "previous result crash identity does not match",
        ),
        (
            "excessive-history.json",
            serde_json::to_vec(&excessive_history)?,
            "previous processing history limit exceeded",
        ),
        (
            "nested-history.json",
            serde_json::to_vec(&nested_history)?,
            "invalid previous processing result",
        ),
    ];

    for (name, contents, expected) in cases {
        let previous = TempInput::new(name, &contents)?;
        let output = run_process(&dump, &crash_context, &directory, Some(&previous.path))?;
        let stderr = String::from_utf8(output.stderr)?;

        assert!(!output.status.success(), "{name}");
        assert!(output.stdout.is_empty());
        assert!(stderr.contains(expected), "{name}: {stderr}");
        assert!(!stderr.contains("private-do-not-echo"));
    }

    let oversized = TempInput::with_size("oversized-previous.json", MAX_PREVIOUS_RESULT_BYTES + 1)?;
    let output = run_process(&dump, &crash_context, &directory, Some(&oversized.path))?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr)?.contains("67108864-byte limit"));
    Ok(())
}

#[test]
fn process_errors_remain_fixed_and_safe() -> Result<(), Box<dyn Error>> {
    let directory = fixture("windows-symbolication");
    let dump = directory.join("faultlane-symbolication.dmp");
    let missing_identity = TempInput::new(
        "missing-identity.xml",
        b"<FGenericCrashContext><RuntimeProperties/></FGenericCrashContext>",
    )?;
    let malformed_context = TempInput::new(
        "malformed-process.xml",
        b"<FGenericCrashContext><Secret>private-do-not-echo</FGenericCrashContext>",
    )?;
    let invalid_dump = TempInput::new("invalid-process.dmp", b"private-do-not-echo")?;

    for (name, output, expected) in [
        (
            "missing identity",
            run_process(&dump, &missing_identity.path, &directory, None)?,
            "crash context has no usable crash identity",
        ),
        (
            "malformed context",
            run_process(&dump, &malformed_context.path, &directory, None)?,
            "invalid crash context XML",
        ),
        (
            "invalid minidump",
            run_process(
                &invalid_dump.path,
                &fixture("crash-context.xml"),
                &directory,
                None,
            )?,
            "invalid minidump",
        ),
    ] {
        let stderr = String::from_utf8(output.stderr)?;
        assert!(!output.status.success(), "{name}");
        assert!(output.stdout.is_empty());
        assert!(stderr.contains(expected), "{name}: {stderr}");
        assert!(!stderr.contains("private-do-not-echo"));
    }
    Ok(())
}

#[test]
fn processes_a_complete_crash_request_and_reprocesses_it() -> Result<(), Box<dyn Error>> {
    let directory = fixture("windows-symbolication");
    let dump = fs::read(directory.join("faultlane-symbolication.dmp"))?;
    let crash_context = fs::read(fixture("crash-context.xml"))?;
    let log = b"LogFaultLane: old\nLogFaultLane: newest\n";
    let request = crash_request(&[
        ("CrashContext.runtime-xml", &crash_context),
        ("Synthetic.log", log),
        ("UEMinidump.dmp", &dump),
        ("Future.bin", b"do-not-retain"),
    ])?;
    let input = TempInput::new("complete-request.uecrash", &request)?;
    let empty_symbols = TestDirectory::new("request-process-empty")?;
    let first = run_request_process(&input.path, empty_symbols.path(), None)?;

    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(first.stderr.is_empty());
    let partial: serde_json::Value = serde_json::from_slice(&first.stdout)?;
    assert_eq!(partial["request"]["schema_version"], 1);
    assert_eq!(partial["request"]["envelope"], "cr1");
    assert_eq!(
        partial["request"]["files"].as_array().map(Vec::len),
        Some(4)
    );
    assert_eq!(partial["classification"]["crash_type"], "assert");
    assert_eq!(partial["classification"]["confidence"], "high");
    assert_eq!(
        partial["crash_context"]["unknown_fields"]["FutureProperties"]["Zulu"],
        serde_json::json!(["value"])
    );
    assert_eq!(partial["log"]["name"], "Synthetic.log");
    assert_eq!(
        partial["log"]["tail"]["text"],
        "LogFaultLane: old\nLogFaultLane: newest\n"
    );
    assert!(
        partial["current"]["symbolication"]["modules"]
            .as_array()
            .is_some_and(|modules| modules.iter().any(|module| {
                module["module"] == "faultlane-symbolication.exe"
                    && module["status"] == "missing_pe"
            }))
    );

    let previous = TempInput::new("complete-request-partial.json", &first.stdout)?;
    let second = run_request_process(&input.path, &directory, Some(&previous.path))?;
    let repeated = run_request_process(&input.path, &directory, Some(&previous.path))?;

    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(second.stderr.is_empty());
    assert_eq!(second.stdout, repeated.stdout);
    let resolved: serde_json::Value = serde_json::from_slice(&second.stdout)?;
    assert_eq!(resolved["history"].as_array().map(Vec::len), Some(1));
    assert_eq!(resolved["history"][0], partial["current"]);
    let frames = resolved["current"]["symbolication"]["threads"][0]["frames"]
        .as_array()
        .ok_or("missing resolved frames")?;
    let crash = frames
        .iter()
        .find(|frame| frame["function"] == "CrashFixture()")
        .ok_or("missing resolved fixture frame")?;
    assert_eq!(crash["module"], "faultlane-symbolication.exe");
    assert_eq!(crash["source_file"], r"Z:\source.cpp");
    assert_eq!(crash["source_line"], 16);
    assert!(crash["trust"].as_str().is_some());
    assert!(crash["inlines"].as_array().is_some_and(|inlines| {
        inlines
            .iter()
            .any(|inline| inline["function"] == "RaiseFixtureException(long*)")
    }));
    Ok(())
}

#[test]
fn exposes_classification_evidence_through_request_processing() -> Result<(), Box<dyn Error>> {
    let directory = fixture("windows-symbolication");
    let dump = fs::read(directory.join("faultlane-symbolication.dmp"))?;
    let crash_context = br"<FGenericCrashContext><RuntimeProperties>
  <CrashGUID>UECC-Synthetic-Signals</CrashGUID>
  <CrashType>GPU Crash</CrashType>
  <ErrorMessage>GPU crashed after out of memory: do-not-copy</ErrorMessage>
  <MemoryStats.bIsOOM>1</MemoryStats.bIsOOM>
</RuntimeProperties></FGenericCrashContext>";
    let request = crash_request(&[
        ("CrashContext.runtime-xml", crash_context),
        ("UEMinidump.dmp", &dump),
    ])?;
    let input = TempInput::new("classified-request.uecrash", &request)?;
    let output = run_request_process(&input.path, &directory, None)?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert!(
        result["classification"]["signals"]
            .as_array()
            .is_some_and(|signals| {
                signals.iter().any(|signal| {
                    signal["kind"] == "out_of_memory" && signal["confidence"] == "high"
                }) && signals
                    .iter()
                    .any(|signal| signal["kind"] == "gpu_crash" && signal["confidence"] == "high")
            })
    );
    let classification = serde_json::to_string(&result["classification"])?;
    assert!(classification.contains("crash_context.memory_stats.is_oom"));
    assert!(classification.contains("crash_context.crash_type_gpu"));
    assert!(!classification.contains("do-not-copy"));
    Ok(())
}

#[test]
fn request_processing_errors_remain_fixed_and_safe() -> Result<(), Box<dyn Error>> {
    let directory = fixture("windows-symbolication");
    let dump = fs::read(directory.join("faultlane-symbolication.dmp"))?;
    let context = fs::read(fixture("crash-context.xml"))?;
    let missing_context = crash_request(&[("UEMinidump.dmp", &dump)])?;
    let missing_dump = crash_request(&[("CrashContext.runtime-xml", &context)])?;
    let malformed_context = crash_request(&[
        (
            "CrashContext.runtime-xml",
            b"<FGenericCrashContext><Secret>do-not-echo</FGenericCrashContext>",
        ),
        ("UEMinidump.dmp", &dump),
    ])?;
    let invalid_dump = crash_request(&[
        ("CrashContext.runtime-xml", &context),
        ("UEMinidump.dmp", b"do-not-echo"),
    ])?;

    for (name, request, expected) in [
        (
            "missing-context.uecrash",
            missing_context,
            "crash request has no crash context",
        ),
        (
            "missing-dump.uecrash",
            missing_dump,
            "crash request has no minidump",
        ),
        (
            "malformed-context.uecrash",
            malformed_context,
            "invalid crash context XML",
        ),
        ("invalid-dump.uecrash", invalid_dump, "invalid minidump"),
        (
            "malformed-request.uecrash",
            b"do-not-echo".to_vec(),
            "invalid crash request compression",
        ),
    ] {
        let input = TempInput::new(name, &request)?;
        let output = run_request_process(&input.path, &directory, None)?;
        let stderr = String::from_utf8(output.stderr)?;

        assert!(!output.status.success(), "{name}");
        assert!(output.stdout.is_empty());
        assert!(stderr.contains(expected), "{name}: {stderr}");
        assert!(!stderr.contains("do-not-echo"));
    }
    Ok(())
}

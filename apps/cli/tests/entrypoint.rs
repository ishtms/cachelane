use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const MAX_CRASH_CONTEXT_BYTES: usize = 4 * 1024 * 1024;

struct TempInput {
    path: PathBuf,
}

impl TempInput {
    fn new(name: &str, contents: &[u8]) -> Result<Self, std::io::Error> {
        let path =
            std::env::temp_dir().join(format!("cachelane-cli-{}-{name}", std::process::id()));
        fs::write(&path, contents)?;
        Ok(Self { path })
    }
}

impl Drop for TempInput {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn run_parse(path: &Path) -> Result<Output, std::io::Error> {
    Command::new(env!("CARGO_BIN_EXE_cachelane"))
        .args(["crash", "parse"])
        .arg(path)
        .output()
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn help_identifies_the_cli() -> Result<(), std::io::Error> {
    let output = Command::new(env!("CARGO_BIN_EXE_cachelane"))
        .arg("--help")
        .output()?;

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("CacheLane command line tools"));
    Ok(())
}

#[test]
fn version_matches_the_package() -> Result<(), std::io::Error> {
    let output = Command::new(env!("CARGO_BIN_EXE_cachelane"))
        .arg("--version")
        .output()?;

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        format!("cachelane {}", env!("CARGO_PKG_VERSION"))
    );
    Ok(())
}

#[test]
fn no_arguments_keeps_the_readiness_message() -> Result<(), std::io::Error> {
    let output = Command::new(env!("CARGO_BIN_EXE_cachelane")).output()?;

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "CacheLane CLI is ready\n"
    );
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
        "cachelane-cli-{}-private-do-not-echo.xml",
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

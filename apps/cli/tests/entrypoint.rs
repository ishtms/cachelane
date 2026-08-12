use std::process::Command;

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

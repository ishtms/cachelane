use std::{
    error::Error,
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn temporary_directory(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = std::env::temp_dir().join(format!(
        "faultlane-unreal-check-{name}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn write(path: &Path, contents: &str) -> Result<(), io::Error> {
    let Some(parent) = path.parent() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing parent",
        ));
    };
    fs::create_dir_all(parent)?;
    fs::write(path, contents)
}

#[test]
fn checks_a_packaged_unreal_project_without_disclosing_configuration() -> Result<(), Box<dyn Error>>
{
    let root = temporary_directory("valid")?;
    let project = root.join("project");
    let package = root.join("package");
    write(
        &project.join("Game.uproject"),
        r#"{"EngineAssociation":"5.8"}"#,
    )?;
    write(
        &project.join("Config/DefaultEngine.ini"),
        "[CrashReportClient]\nDataRouterUrl=https://example.invalid/u/clpk_do-not-echo\n",
    )?;
    write(
        &project.join("Config/DefaultGame.ini"),
        "[/Script/UnrealEd.ProjectPackagingSettings]\nIncludeCrashReporter=True\n",
    )?;
    write(&package.join("Game.exe"), "game")?;
    write(
        &package.join("Engine/Binaries/Win64/CrashReportClient.exe"),
        "reporter",
    )?;

    let output = Command::new(env!("CARGO_BIN_EXE_faultlane"))
        .args(["unreal", "check"])
        .arg(&project)
        .arg("--package")
        .arg(&package)
        .output()?;

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    let report: serde_json::Value = serde_json::from_str(&stdout)?;
    assert_eq!(report["valid"], true);
    assert_eq!(report["checks"].as_array().map(Vec::len), Some(8));
    assert!(!stdout.contains("clpk_do-not-echo"));
    assert!(!stdout.contains(&project.to_string_lossy().to_string()));
    assert!(stderr.is_empty());

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn reports_editor_only_and_packaging_mistakes_with_exit_code_two() -> Result<(), Box<dyn Error>> {
    let root = temporary_directory("invalid")?;
    let project = root.join("project");
    let package = root.join("package");
    write(
        &project.join("Game.uproject"),
        r#"{"EngineAssociation":"5.7"}"#,
    )?;
    write(
        &project.join("Saved/Config/WindowsEditor/Engine.ini"),
        "[CrashReportClient]\nDataRouterUrl=https://example.invalid/u/clpk_do-not-echo\n",
    )?;
    write(
        &project.join("Config/DefaultGame.ini"),
        "[/Script/UnrealEd.ProjectPackagingSettings]\nIncludeCrashReporter=False\n",
    )?;
    write(&package.join("UnrealEditor-Game.exe"), "editor")?;

    let output = Command::new(env!("CARGO_BIN_EXE_faultlane"))
        .args(["unreal", "check"])
        .arg(&project)
        .arg("--package")
        .arg(&package)
        .output()?;

    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stdout.contains("engine_association_supported"));
    assert!(stdout.contains("endpoint_not_editor_only"));
    assert!(stdout.contains("packaged_crash_reporter_enabled"));
    assert!(!stdout.contains("clpk_do-not-echo"));
    assert!(!stderr.contains("clpk_do-not-echo"));
    assert_eq!(stderr.trim(), "Unreal configuration check failed");

    fs::remove_dir_all(root)?;
    Ok(())
}

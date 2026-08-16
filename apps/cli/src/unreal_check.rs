use std::{
    collections::VecDeque,
    fmt, fs,
    io::Read,
    path::{Path, PathBuf},
};

use serde::Serialize;
use serde_json::Value;

const MAX_FILE_BYTES: u64 = 1024 * 1024;
const MAX_PACKAGE_ENTRIES: usize = 4096;
const MAX_PACKAGE_DEPTH: usize = 8;

#[derive(Serialize)]
pub(crate) struct UnrealCheckReport {
    pub(crate) valid: bool,
    checks: Vec<CheckResult>,
}

#[derive(Serialize)]
struct CheckResult {
    id: &'static str,
    status: &'static str,
    path: &'static str,
    message: &'static str,
}

#[derive(Debug)]
pub(crate) enum UnrealCheckError {
    InvalidRoot,
    Bounds,
    Read,
}

impl fmt::Display for UnrealCheckError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRoot => "project and package roots must be directories",
            Self::Bounds => "Unreal configuration check exceeded its inspection limit",
            Self::Read => "Unreal configuration check could not read a required file",
        })
    }
}

impl std::error::Error for UnrealCheckError {}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum Presence {
    #[default]
    Absent,
    Present,
}

#[derive(Default)]
struct PackageFiles {
    game_executable: Presence,
    editor_executable: Presence,
    crash_reporter: Presence,
    links_ignored: Presence,
}

pub(crate) fn check(
    project_root: &Path,
    package_root: &Path,
) -> Result<UnrealCheckReport, UnrealCheckError> {
    if !plain_directory(project_root) || !plain_directory(package_root) {
        return Err(UnrealCheckError::InvalidRoot);
    }
    let project_files = direct_project_files(project_root)?;
    let project_file = project_files.first();
    let project_name = project_file
        .and_then(|path| path.file_stem())
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let engine_supported = project_file
        .and_then(|path| read_text(path).ok())
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .and_then(|value| {
            value
                .get("EngineAssociation")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .is_some_and(|association| association == "5.8" || association.starts_with("5.8."));

    let engine_ini = read_optional_text(&project_root.join("Config/DefaultEngine.ini"))?;
    let game_ini = read_optional_text(&project_root.join("Config/DefaultGame.ini"))?;
    let source_endpoint = engine_ini
        .as_deref()
        .is_some_and(|text| ini_truthy_value(text, "CrashReportClient", "DataRouterUrl"));
    let crash_reporter_enabled = game_ini.as_deref().is_some_and(|text| {
        ini_boolean(
            text,
            "/Script/UnrealEd.ProjectPackagingSettings",
            "IncludeCrashReporter",
        ) == Some(true)
    });
    let editor_endpoint = [
        project_root.join("Config/DefaultEditor.ini"),
        project_root.join("Saved/Config/WindowsEditor/Engine.ini"),
    ]
    .into_iter()
    .map(|path| read_optional_text(&path))
    .collect::<Result<Vec<_>, _>>()?
    .iter()
    .flatten()
    .any(|text| ini_truthy_value(text, "CrashReportClient", "DataRouterUrl"));
    let package = package_files(package_root, project_name)?;

    let checks = vec![
        result(
            "project_file_present",
            project_files.len() == 1,
            "<project-root>/*.uproject",
            "Found one Unreal project descriptor.",
            "Expected exactly one Unreal project descriptor.",
        ),
        result(
            "engine_association_supported",
            engine_supported,
            "<project-root>/*.uproject",
            "The project targets Unreal Engine 5.8.",
            "EngineAssociation must target Unreal Engine 5.8.",
        ),
        result(
            "source_crash_endpoint",
            source_endpoint,
            "Config/DefaultEngine.ini",
            "The source configuration contains a crash endpoint.",
            "Add DataRouterUrl under [CrashReportClient] in the source configuration.",
        ),
        result(
            "packaged_crash_reporter_enabled",
            crash_reporter_enabled,
            "Config/DefaultGame.ini",
            "The packaged Crash Reporter setting is enabled.",
            "Set IncludeCrashReporter=True in ProjectPackagingSettings.",
        ),
        result(
            "endpoint_not_editor_only",
            !editor_endpoint || source_endpoint,
            "Saved/Config/WindowsEditor/Engine.ini",
            "No editor-only crash endpoint mistake was found.",
            "Move the crash endpoint from editor-only configuration to Config/DefaultEngine.ini.",
        ),
        result(
            "packaged_game_executable",
            package.game_executable == Presence::Present
                && package.editor_executable == Presence::Absent,
            "<packaged-build-root>/*.exe",
            "Found the packaged game executable.",
            "Expected a packaged game executable, not UnrealEditor.",
        ),
        result(
            "packaged_crash_report_client",
            package.crash_reporter == Presence::Present,
            "Engine/Binaries/Win64/CrashReportClient.exe",
            "Found the packaged CrashReportClient binary.",
            "Package the project with the Crash Reporter included.",
        ),
        result(
            "symbolic_links_ignored",
            true,
            "<project-root> and <packaged-build-root>",
            if package.links_ignored == Presence::Present {
                "Symbolic links were ignored during bounded inspection."
            } else {
                "No symbolic links were followed during bounded inspection."
            },
            "Symbolic links are never followed.",
        ),
    ];
    let valid = checks.iter().all(|check| check.status == "pass");
    Ok(UnrealCheckReport { valid, checks })
}

fn result(
    id: &'static str,
    valid: bool,
    path: &'static str,
    success: &'static str,
    failure: &'static str,
) -> CheckResult {
    CheckResult {
        id,
        status: if valid { "pass" } else { "error" },
        path,
        message: if valid { success } else { failure },
    }
}

fn plain_directory(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
}

fn direct_project_files(root: &Path) -> Result<Vec<PathBuf>, UnrealCheckError> {
    let mut files = fs::read_dir(root)
        .map_err(|_| UnrealCheckError::Read)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| UnrealCheckError::Read)?;
    files.sort_by_key(fs::DirEntry::file_name);
    Ok(files
        .into_iter()
        .filter_map(|entry| {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).ok()?;
            (metadata.is_file()
                && !metadata.file_type().is_symlink()
                && path
                    .extension()
                    .and_then(|value| value.to_str())
                    .is_some_and(|value| value.eq_ignore_ascii_case("uproject")))
            .then_some(path)
        })
        .collect())
}

fn read_optional_text(path: &Path) -> Result<Option<String>, UnrealCheckError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            read_text(path).map(Some)
        }
        Ok(_) => Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(UnrealCheckError::Read),
    }
}

fn read_text(path: &Path) -> Result<String, UnrealCheckError> {
    let file = fs::File::open(path).map_err(|_| UnrealCheckError::Read)?;
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| UnrealCheckError::Read)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES {
        return Err(UnrealCheckError::Bounds);
    }
    String::from_utf8(bytes).map_err(|_| UnrealCheckError::Read)
}

fn ini_truthy_value(text: &str, section: &str, key: &str) -> bool {
    ini_value(text, section, key).is_some_and(|value| {
        let value = value.trim().trim_matches('"').trim();
        !value.is_empty()
    })
}

fn ini_boolean(text: &str, section: &str, key: &str) -> Option<bool> {
    ini_value(text, section, key).and_then(|value| match value.trim().trim_matches('"') {
        value if value.eq_ignore_ascii_case("true") => Some(true),
        value if value.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    })
}

fn ini_value<'a>(text: &'a str, section: &str, key: &str) -> Option<&'a str> {
    let mut current = "";
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with([';', '#']) {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            current = line[1..line.len() - 1].trim();
            continue;
        }
        if current.eq_ignore_ascii_case(section) {
            let Some((name, value)) = line.split_once('=') else {
                continue;
            };
            if name.trim().eq_ignore_ascii_case(key) {
                return Some(value);
            }
        }
    }
    None
}

fn package_files(root: &Path, project_name: &str) -> Result<PackageFiles, UnrealCheckError> {
    let mut pending = VecDeque::from([(root.to_path_buf(), 0_usize)]);
    let mut inspected = 0_usize;
    let mut result = PackageFiles::default();
    while let Some((directory, depth)) = pending.pop_front() {
        let mut entries = fs::read_dir(directory)
            .map_err(|_| UnrealCheckError::Read)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| UnrealCheckError::Read)?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            inspected = inspected.saturating_add(1);
            if inspected > MAX_PACKAGE_ENTRIES {
                return Err(UnrealCheckError::Bounds);
            }
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|_| UnrealCheckError::Read)?;
            if metadata.file_type().is_symlink() {
                result.links_ignored = Presence::Present;
                continue;
            }
            if metadata.is_dir() {
                if depth >= MAX_PACKAGE_DEPTH {
                    return Err(UnrealCheckError::Bounds);
                }
                pending.push_back((path, depth + 1));
                continue;
            }
            if !metadata.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            let lowercase_name = name.to_ascii_lowercase();
            let executable = path
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case("exe"));
            if name.eq_ignore_ascii_case("CrashReportClient.exe") {
                result.crash_reporter = Presence::Present;
            }
            if lowercase_name.starts_with("unrealeditor") && executable {
                result.editor_executable = Presence::Present;
            }
            if !project_name.is_empty()
                && executable
                && (name.eq_ignore_ascii_case(&format!("{project_name}.exe"))
                    || lowercase_name
                        .starts_with(&format!("{}-win64-", project_name.to_ascii_lowercase())))
            {
                result.game_executable = Presence::Present;
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::{ini_boolean, ini_truthy_value};

    #[test]
    fn reads_only_the_requested_ini_section() {
        let text = "[Other]\nDataRouterUrl=secret\n[CrashReportClient]\nDataRouterUrl=\"https://example.invalid/u/key\"\n[/Script/UnrealEd.ProjectPackagingSettings]\nIncludeCrashReporter=True\n";
        assert!(ini_truthy_value(text, "CrashReportClient", "DataRouterUrl"));
        assert_eq!(
            ini_boolean(
                text,
                "/Script/UnrealEd.ProjectPackagingSettings",
                "IncludeCrashReporter"
            ),
            Some(true)
        );
    }
}

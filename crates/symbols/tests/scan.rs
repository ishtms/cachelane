mod support;

use std::{error::Error, fs, fs::File};

use cachelane_symbols::{ArtifactErrorCode, ArtifactType, MatchState, scan_artifacts};
use support::{GUID, TestDirectory, write_pdb, write_pe};

#[test]
fn scans_and_matches_pe_and_pdb_by_identity() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new("matched")?;
    write_pdb(&directory.path().join("symbols/Game.pdb"), GUID, 2, 1)?;
    write_pe(
        &directory.path().join("bin/Game.exe"),
        GUID,
        1,
        r"C:\build\Game.pdb",
        false,
    )?;
    let mut pdb = pdb::PDB::open(File::open(directory.path().join("symbols/Game.pdb"))?)?;
    let _ = pdb.pdb_information()?;
    let _ = pdb.debug_information()?;

    let scan = scan_artifacts(directory.path())?;

    assert_eq!(scan.artifacts.len(), 2);
    let executable = &scan.artifacts[0];
    assert_eq!(executable.path, "bin/Game.exe");
    assert_eq!(executable.artifact_type, ArtifactType::PeExecutable);
    assert_eq!(
        executable.debug_id.as_deref(),
        Some("00112233-4455-6677-8899-AABBCCDDEEFF-1")
    );
    assert_eq!(executable.code_id.as_deref(), Some("123456782000"));
    assert_eq!(executable.match_state, MatchState::Matched, "{scan:#?}");
    assert_eq!(executable.matches, ["symbols/Game.pdb"]);

    let pdb = &scan.artifacts[1];
    assert_eq!(pdb.artifact_type, ArtifactType::Pdb);
    assert_eq!(
        pdb.debug_id.as_deref(),
        Some("00112233-4455-6677-8899-AABBCCDDEEFF-2")
    );
    assert_eq!(pdb.match_state, MatchState::Matched);
    assert_eq!(pdb.matches, ["bin/Game.exe"]);
    Ok(())
}

#[test]
fn reports_named_identity_mismatches() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new("mismatch")?;
    write_pe(
        &directory.path().join("Game.dll"),
        GUID,
        1,
        "Game.pdb",
        true,
    )?;
    let mut different_guid = GUID;
    different_guid[15] = 0;
    write_pdb(&directory.path().join("Game.pdb"), different_guid, 1, 1)?;

    let scan = scan_artifacts(directory.path())?;

    assert!(
        scan.artifacts
            .iter()
            .all(|artifact| artifact.match_state == MatchState::Mismatched),
        "{scan:#?}"
    );
    Ok(())
}

#[test]
fn returns_safe_errors_and_stable_json() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new("malformed")?;
    fs::write(
        directory.path().join("secret-do-not-print.dll"),
        b"private bytes",
    )?;
    fs::write(directory.path().join("ignored.txt"), b"not an artifact")?;

    let first = scan_artifacts(directory.path())?;
    let second = scan_artifacts(directory.path())?;
    let json = serde_json::to_string(&first)?;

    assert_eq!(first, second);
    assert_eq!(first.artifacts.len(), 1);
    assert_eq!(first.artifacts[0].match_state, MatchState::Invalid);
    assert_eq!(
        first.artifacts[0].error.as_ref().map(|error| error.code),
        Some(ArtifactErrorCode::Malformed)
    );
    assert!(!json.contains("private bytes"));
    Ok(())
}

#[test]
fn missing_root_errors_do_not_echo_the_path() {
    let missing = std::env::temp_dir().join("cachelane-private-do-not-echo");
    let Err(error) = scan_artifacts(&missing) else {
        panic!("missing root must fail");
    };

    assert_eq!(error.to_string(), "failed to inspect artifact path");
    assert!(!error.to_string().contains("private-do-not-echo"));
}

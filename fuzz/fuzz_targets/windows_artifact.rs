#![no_main]

use std::fs;

use faultlane_symbols::scan_artifacts;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let extension = if data.first().is_some_and(|byte| byte & 1 == 0) {
        "pdb"
    } else {
        "dll"
    };
    let path = std::env::temp_dir().join(format!(
        "faultlane-artifact-fuzz-{}.{}",
        std::process::id(),
        extension
    ));
    if fs::write(&path, data).is_ok() {
        let _ = scan_artifacts(&path);
    }
});

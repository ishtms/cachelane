#![no_main]

use faultlane_unreal::{CrashRequestLimits, inspect_crash_request, read_crash_request};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = CrashRequestLimits {
        compressed_bytes: 1024 * 1024,
        expanded_bytes: 4 * 1024 * 1024,
        expansion_ratio: 32,
        files: 16,
        file_bytes: 1024 * 1024,
        crash_context_bytes: 256 * 1024,
        crash_context_nodes: 10_000,
        minidump_bytes: 1024 * 1024,
        log_tail_bytes: 64 * 1024,
        log_tail_lines: 200,
    };
    let _ = inspect_crash_request(data, limits);
    let _ = read_crash_request(data, limits);
});

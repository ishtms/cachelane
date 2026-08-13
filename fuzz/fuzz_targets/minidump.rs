#![no_main]

use libfuzzer_sys::fuzz_target;
use minidump::Minidump;

fuzz_target!(|data: &[u8]| {
    let _ = Minidump::read(data);
});

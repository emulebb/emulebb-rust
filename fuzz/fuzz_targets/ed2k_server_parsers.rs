#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    emulebb_ed2k::fuzzing::server_binary_parsers(data);
});

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = emulebb_kad_proto::KadPacket::decode(data);
});

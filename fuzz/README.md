# Parser fuzzing

These `cargo-fuzz` targets exercise the hand-written binary parser families
used on untrusted ED2K/Kad traffic:

- `ed2k_server_parsers`: server TCP/UDP result, tag, metadata, list and packed
  payload codecs;
- `ed2k_peer_tcp_parsers`: peer envelopes, hello/tags, transfer blocks,
  hashsets/AICH, SX1/SX2, secure-ident and browse payloads;
- `ed2k_client_udp_parser`: clear and encrypted client-UDP v1-v4 reask and
  callback traffic;
- `kad_packet_parser`: Kad v2 packet bodies including contact, search, publish,
  firewall, buddy, callback and tag paths.

Run from the repository root with a nightly Rust toolchain and `cargo-fuzz`:

```text
cargo +nightly fuzz run ed2k_server_parsers -- -max_total_time=60
cargo +nightly fuzz run ed2k_peer_tcp_parsers -- -max_total_time=60
cargo +nightly fuzz run ed2k_client_udp_parser -- -max_total_time=60
cargo +nightly fuzz run kad_packet_parser -- -max_total_time=60
```

On Windows/MSVC the fuzz executable also needs the AddressSanitizer runtime
next to the generated executable (or on `PATH`). Use the
`clang_rt.asan_dynamic-x86_64.dll` shipped in the active Visual Studio MSVC
tool directory: it includes the sanitizer-coverage cleanup exports used by
Rust's libFuzzer instrumentation. The similarly named standalone LLVM DLL may
not include those exports, even when its LLVM version matches the toolchain.

Corpus, artifacts and coverage output are intentionally ignored. Crashing
inputs should be minimized with `cargo +nightly fuzz tmin`, converted into a
deterministic regression test, and retained only in that test.

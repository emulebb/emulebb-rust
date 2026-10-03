# Third-party licensing

The emulebb-rust source is licensed under GPL-2.0-only. Dependencies keep their
own licenses. The enforced allow-list and dependency-specific licensing choices
are recorded in `deny.toml`; `cargo deny check licenses sources` verifies the
resolved dependency graph.

## Symphonia

Media metadata extraction uses Symphonia under the Mozilla Public License 2.0.
Symphonia remains a separately licensed third-party component; its source files
and upstream notices remain under the MPL-2.0.

# Third-party licensing

The emulebb-rust source is licensed under GPL-2.0-only. Dependencies keep their
own licenses. The enforced allow-list and dependency-specific licensing choices
are recorded in `deny.toml`; `cargo deny check licenses sources` verifies the
resolved dependency graph.

## Slint

The desktop UI uses Slint 1.17.1 under the
[Slint Royalty-free Desktop, Mobile, and Web Applications License 2.0](https://github.com/slint-ui/slint/blob/master/LICENSES/LicenseRef-Slint-Royalty-free-2.0.md),
not under Slint's GPL-3.0-only alternative. The required Slint attribution badge
is displayed in the repository README. Any future download page that distributes
the UI binary must retain an easily found Slint badge or provide the license's
`AboutSlint` attribution in the application.

The Slint license and upstream copyright notices must not be removed or altered.

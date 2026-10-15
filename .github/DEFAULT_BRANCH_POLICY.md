# Default branch policy

The `Default branch policy` repository ruleset protects `main`. Its reviewed
configuration is [rulesets/main.json](rulesets/main.json); the GitHub ruleset
is the effective enforcement boundary.

Normal changes use a topic branch and pull request. The pull request must be
current with `main`, all review conversations must be resolved, and each human
author may have only one open pull request targeting `main`. Bot-authored pull
requests are exempt. Deliberately parallel human work requires the
maintainer-controlled `parallel-approved` label on every affected pull request,
with the reason recorded on each pull request before labeling.

These GitHub Actions checks must pass:

- `Single active PR`, which enforces the author limit before expensive normal
  CI jobs start.

- `Required CI`, which succeeds only after workflow lint, all three platform
  build/test jobs, live REST/OpenAPI conformance, policy/format/Clippy,
  cargo-deny, and the single-active-PR policy succeed.
- `Required CodeQL`, which succeeds only after every configured CodeQL
  language succeeds.

The stable aggregate names are the ruleset contract. Matrix job display names
remain implementation details. The ruleset requires a pull request but zero
approvals, so a single maintainer can merge a green change without self-review.
Only squash and rebase merges are allowed. Branch deletion, force pushes, and
merge commits on `main` are blocked. GitHub automatically deletes merged topic
branches.

There are no standing bypass actors. For an emergency security update, a
repository administrator may temporarily disable the ruleset only after
opening an issue that records the reason and intended commit. Restore active
enforcement immediately after the update, record the exact commit and CI run
URLs on that issue, and verify the effective configuration with:

```console
gh api repos/emulebb/emulebb-rust/rulesets \
  --jq '.[] | select(.name == "Default branch policy")'
```

For initial repository setup only, an administrator can create the reviewed
configuration with:

```console
gh api --method POST repos/emulebb/emulebb-rust/rulesets \
  --input .github/rulesets/main.json
```

Do not repeat the create command when the ruleset already exists. Update the
existing ruleset by ID and review the normalized API response against the
tracked configuration instead.

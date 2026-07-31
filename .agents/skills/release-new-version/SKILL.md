---
name: release-new-version
description: Release a new version of the sshdt Rust crate from the sshdt repository by confirming CI is green, bumping the root Cargo.toml, refreshing Cargo.lock, committing and pushing the change, waiting for commit CI, then pushing a matching tag that publishes to crates.io and creates a GitHub release. Use for explicit invocations like "/release-new-version" or requests like "release a new sshdt version", "bump sshdt", or "publish sshdt".
---

# Release New Version

## Overview

Release the `sshdt` crate and CLI from the `prabirshrestha/sshdt` repository. Use the root `Cargo.toml`, preserve the lockfile, and let tag-triggered GitHub Actions publish the crate and packaged binaries.

## Preconditions

- Work from the `sshdt` repository root unless the user explicitly directs otherwise.
- Run the release from `main` only. If the current branch is not `main`, stop and ask before switching.
- Treat the release as live unless the user asks for a dry run.
- Inspect `git status --short --branch` before changing files.
- If the worktree has user changes, do not overwrite or mix them into the release. Ask before proceeding.
- When `main` tracks a remote, run `git pull --ff-only` before editing.
- Keep unrelated untracked files out of the release commit.

## Upstream CI Gate

After pulling, confirm the latest CI workflow run for the current `main` commit completed successfully:

```bash
gh run list --workflow ci.yml --branch main --limit 5 --json databaseId,headSha,status,conclusion,workflowName,displayTitle,createdAt,url
```

Match the run's `headSha` to `git rev-parse HEAD`; do not accept a successful run for a different commit. If CI cannot be determined or is not green, stop and ask whether to run all feasible local CI checks before continuing.

## Version Bump

1. Read the current package version from the root `Cargo.toml`. Confirm the package name is `sshdt`.
2. Inspect release tags with `git tag --sort=-version:refname | head` and review commits since the latest release tag.
3. Choose the semantic-version bump from commit impact unless the user specified a version.
4. Update `[package].version` in the root `Cargo.toml`.
5. Refresh and verify `Cargo.lock`:

```bash
cargo build --locked --all-targets --all-features
```

If `--locked` fails only because the package version changed, run:

```bash
cargo build --all-targets --all-features
cargo build --locked --all-targets --all-features
```

Verify that the lockfile changed only for the `sshdt` package version. Confirm only `Cargo.toml` and `Cargo.lock` contain intended release changes.

## Validation

When upstream CI for the previous commit was green and the release edit contains only the version and lockfile update, the locked build above is the required local validation.

If upstream CI was not green, could not be confirmed, or the release edit contains anything else, ask before running all feasible local equivalents of `.github/workflows/ci.yml`:

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo build --locked --all-targets --all-features
cargo test --locked --all-features
cargo build --locked --lib --no-default-features
```

The GitHub workflow also tests Ubuntu, macOS, and Windows and builds five release targets. Do not claim those matrix checks passed from a single local platform; rely on the tag workflow for them.

## Commit And Tag

After validation passes:

1. Commit the manifest and lockfile with `chore: bump version to X.Y.Z`, matching existing release history.
2. Push the commit with `git push origin HEAD`.
3. Wait for all jobs in the CI workflow on that commit to complete successfully.
4. Create a matching lightweight tag, following existing release history: `git tag vX.Y.Z`.
5. Push it with `git push origin vX.Y.Z`.
6. Monitor the tag-triggered workflow through completion.

Do not create or push the tag until release-commit CI is green. The workflow validates that the tag is exactly `v` plus the version in `Cargo.toml`.

## Publishing

Do not run `cargo publish` or create the GitHub release manually. `.github/workflows/ci.yml` handles both from matching version tags:

```text
v0.*.*
v0.*.*-alpha.*
v0.*.*-beta.*
```

The tag workflow:

- Publishes the `sshdt` crate to crates.io using trusted publishing.
- Builds Linux GNU, Linux musl, Intel macOS, Apple Silicon macOS, and Windows binaries.
- Generates `SHA256SUMS`.
- Creates the GitHub release and attaches all packaged binaries and checksums.

## Reporting

Tell the user:

- Previous and new `sshdt` versions.
- Whether upstream CI for the previous commit was green.
- Validation commands run and whether they passed.
- Release commit hash and tag.
- Whether crates.io publishing and GitHub release creation succeeded.
- Any skipped steps and why.

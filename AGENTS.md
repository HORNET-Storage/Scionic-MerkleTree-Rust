# Scionic MerkleTree Rust contributor policy

`AGENTS.md` is this repository's only agent instruction file; the workspace policy is `../AGENTS.md`. `CLAUDE.md` is retired in every repository (2026-09-19): do not add one here.

**Documentation placement.** READMEs explain purpose, components, ownership boundaries, data flow, usage and verification. Current protocol/API/format documentation, security limitations, reproducible benchmarks and reference comparisons stay with the code, with revisions, methods and evidence limits where relevant. Session transcripts, personal/live-account examples, machine-specific observations, agent notes, task checklists, dated build narratives and superseded plans belong in the parent workspace's `repository-history/YYYY-MM-DD/<repository>/`, never a history folder inside a product repository. Keep active work in the workspace `TODO.md` and the stable `CURRENT_LIST.md`. Archive before removing historical material, retain unresolved findings and technical evidence, repair links, and make current product contracts understandable without private workspace notes.

Go is deprecated. This Rust crate is authoritative for active DAG structures, codecs, and security invariants. Do not modify Go repositories, block secure Rust cleanup on Go parity, or add compatibility aliases, permissive decoding, downgrade behavior, or insecure legacy paths for Go.

Cargo has no native minimum-release-age or dependency-cooldown setting. Do not invent a Cargo key for one. Keep `Cargo.lock`, run dependency-resolving gates with `--locked --offline`, and review any new dependency for advisories, licensing, maintenance, and duplicate versions before adoption.

Required offline gates:

1. `cargo fmt --check`
2. `cargo clippy --all-targets --locked --offline -- -D warnings`
3. `cargo test --locked --offline`

Committed Go vectors are historical evidence only. Keep useful vector names and manifests current, but current Rust invariants take precedence over Go byte parity.

The gitignored `.local/` notes (`.local/AGENTS.md`, `.local/PORT-PLAN.md`) are the 2026-07 porting record. Where they ask for Go byte parity as a requirement, this file and the workspace `../AGENTS.md` take precedence.

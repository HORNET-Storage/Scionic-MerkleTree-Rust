# Scionic MerkleTree Rust contributor policy

Go is deprecated. This Rust crate is authoritative for active DAG structures, codecs, and security invariants. Do not modify Go repositories, block secure Rust cleanup on Go parity, or add compatibility aliases, permissive decoding, downgrade behavior, or insecure legacy paths for Go.

Cargo has no native minimum-release-age or dependency-cooldown setting. Do not invent a Cargo key for one. Keep `Cargo.lock`, run dependency-resolving gates with `--locked --offline`, and review any new dependency for advisories, licensing, maintenance, and duplicate versions before adoption.

Required offline gates:

1. `cargo fmt --check`
2. `cargo clippy --all-targets --locked --offline -- -D warnings`
3. `cargo test --locked --offline`

Committed Go vectors are historical evidence only. Keep useful vector names and manifests current, but current Rust invariants take precedence over Go byte parity.

# Security scan exceptions and open exposures

What the secret, dependency and SBOM gates report on this repository, what is
allowlisted and why, and what is genuinely open. The gates are in
`.github/workflows/security.yml`; the secret allowlist is `.gitleaks.toml`.
SAST is GitHub's CodeQL default setup (the `Analyze (...)` checks); it is not a
workflow file in this repository.

Last local run: 2026-11-11 on the tree of this document (gitleaks 8.30.1,
trivy 0.76.1). Re-run after any dependency change; dependency pins are
reviewed at least monthly.

## Secrets

`gitleaks detect` over the full history of `main` (828 commits) reports no
findings with `.gitleaks.toml`.

Open item (owner action, not a repository change): commit `8983f0df` adds a
`.env` containing a `WEBAUTH_PKEY` test value. That commit exists only on a
local branch of one developer clone (`feat/webauthn-wallet-compat`). It is on
no remote branch and not in `main`. `main` only references the variable
(`.env.localnet.example` carries it empty; the E2E scripts read it from the
environment). The owner should confirm the key was never shared or used beyond
local testing, rotate it if it was, and delete or rewrite that local branch.
Nothing in the repository can do this.

## Allowlisted (documented in `.gitleaks.toml`)

- The removed vendored crypto library under `crates/pulsevm_ffi/pulsevm/`
  (BoringSSL CAVP and Wycheproof known-answer data): present only in history,
  tens of thousands of matches, none are credentials.
- Public keys and signatures (`PUB_K1_`, `EOS...`, `SIG_K1_`): public by
  construction.
- 64-hex ids and digests, limited to the `generic-api-key` rule and to test,
  fixture, documentation, example, contract and genesis paths
  (`condition = "AND"`, so the path must match as well). A raw hex key in
  source code is still reported. Real keys on this chain are WIF
  (`PVT_K1_` / `5K...`), which are scanned everywhere.
- One compressed public key in a test vector in a historical copy of
  `public_key.rs` (commit `5410042f`).
- Disposable local-network fixture private keys, prefix-matched (the genesis
  dev key, the `chain_config.json` dev key, the rehearsal WIF). They must
  never be used on a real network. Owner: chain ops. Review by 2027-02-01.

## Dependency CVEs

`trivy fs . --scanners vuln --severity HIGH,CRITICAL`: no findings in
`Cargo.lock` or `tests/e2e/go.mod`. Before this change `main` had 31
findings (one CRITICAL, grpc) in `tests/e2e/go.mod`, a test-only module that
is not shipped. They were cleared by upgrading to patched versions (grpc
1.83.2, x/crypto 0.57.0, x/net 0.60.0, x/text 0.42.0, x/mod 0.41.0, otel sdk
1.44.0, gnark-crypto 0.18.1, klauspost/compress 1.18.7, spdystream 0.5.1, plus
go-kzg-4844 1.1.0 which the patched gnark-crypto requires) and `rustls`
0.23.44 to 0.23.46. The module now requires Go 1.26, so the e2e workflow uses
it. `go vet ./...` is clean.

## Supply chain

Every GitHub Action is pinned to a commit SHA (a mutable tag such as `@v4`
can be repointed), and every workflow declares read-only `permissions`; the
release job keeps its own wider block. Security tool versions are pinned in
`security.yml`. The tool downloads there are not yet verified against a
published checksum, which is an open improvement.

## Known gap: consensus replay gate

The consensus replay workflow downloaded its frozen corpus from a release
asset on a personal fork that no longer exists (HTTP 404). The archive is
pinned by SHA-256, so it cannot be regenerated. The workflow was removed; see
`ARENA_CUTOVER.md`. Until the archive is re-hosted somewhere the organization
owns, `scripts/run-replay-regression.sh` must be run locally before any
consensus change, and the replay evidence in that document cannot be
re-verified in CI.

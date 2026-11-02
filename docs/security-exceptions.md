# Security scan exceptions and open exposures

What the secret, dependency and SAST gates report on this repository, what is
allowlisted and why, and what is genuinely open. The gates are in
`.github/workflows/security.yml`; the secret allowlist is `.gitleaks.toml`.
Last full local run: 2026-11-02 (gitleaks 8.30.1, trivy 0.76.1, syft 1.55.0,
semgrep 1.183.0).

## Open: historical credential in git history (needs the key owner)

Commit `8983f0df` added a `.env` file containing a `WEBAUTH_PKEY` value.
The file is no longer tracked and `.env` is in `.gitignore`, but the value is
still in history, which is how `gitleaks detect` finds it: one finding, the
only one that survives `.gitleaks.toml`. It is deliberately **not**
allowlisted.

Required, in order, by the owner of that credential (this cannot be done from
the repository):

1. Treat it as exposed: rotate the key, revoke anything it authorizes, and
   check what it was used for since that commit (incident process).
2. Only then decide whether to rewrite history. A rewrite does not undo the
   exposure, only stops re-distributing it.
3. Once rotated, record the commit in a gitleaks baseline so the full-history
   scan returns to green without hiding new findings.

Until then the pull-request job scans only its own commits and the weekly job
is allowed to report this single known finding.

## Allowlisted (documented in `.gitleaks.toml`)

- Vendored third-party crypto test vectors under `crates/pulsevm_ffi/pulsevm/`
  (BoringSSL CAVP and Wycheproof known-answer data): tens of thousands of
  matches, none are credentials.
- Public keys (`PUB_K1_`, `EOS...`, `SIG_K1_`) and 64-hex ids: public by
  construction.
- Disposable local-network fixture private keys, prefix-matched (the genesis
  dev key, the `chain_config.json` dev key, the rehearsal WIF). They must
  never be used on a real network. Owner: chain ops. Review by 2027-02-01.

## Dependency CVEs

`trivy fs` (HIGH/CRITICAL): no findings in `Cargo.lock`. The Go e2e module
(`tests/e2e/go.mod`) had 30, all fixed by upgrading to patched versions
(grpc 1.83.2, x/crypto 0.57.0, x/net 0.60.0, x/text 0.42.0, x/mod 0.41.0,
otel sdk 1.44.0, gnark-crypto 0.18.1, klauspost/compress 1.18.7, spdystream
0.5.1, plus go-kzg-4844 1.1.0 which the patched gnark-crypto requires);
`go vet` is clean and the module's tests compile. Re-run after any
dependency change; pins are reviewed at least monthly.

## SAST

Semgrep (rust, github-actions, secrets, dockerfile rulesets) on the
cutover code, harness and workflows: two `run-shell-injection` errors fixed
(workflow inputs now pass through `env`), 38 mutable-action-tag warnings
fixed (every action pinned to a commit SHA). Remaining INFO notes are
`std::env::args` in developer CLI examples and one temp dir in a unit test:
not security findings, accepted. CodeQL (rust, go) runs in CI.

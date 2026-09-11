# Code coverage

The [Coverage workflow](../.github/workflows/coverage.yml) runs the Rust workspace
tests with [cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov) on Linux
x86-64. It runs for pushes to `main`, pull requests targeting `main`, and manual
dispatches. It uses stable Rust, the default Cargo features, LLVM 22 for the WASM
backend, and the Rust toolchain's `llvm-tools-preview` for coverage collection.

The workflow saves `target/coverage/lcov.info` as the `coverage-lcov` GitHub
Actions artifact for 14 days and uploads it to Codecov. Upload errors fail the
job, so a missing or rejected upload cannot silently leave a green coverage run.

## Coverage scope

All workspace packages participate in the test run. The report excludes standalone
test, benchmark, and example directories, along with the test/tooling-only
`pulsevm_unittests`, `pulsevm_e2e_boot`, and `pulsevm_benchmark` crates. Tests in
those crates still contribute coverage of the production code they execute.
Generated protobuf output under `target/` is excluded by cargo-llvm-cov's default
report filtering.

The report measures Rust code exercised by the workspace tests. It does not
measure WASM guest instructions, native dependency code, Go E2E tests, or ignored
tests that require external fixtures. Doctest coverage requires nightly Rust and
is not included; the existing unit-test workflow still runs doctests normally.
Preview protocol features remain checked by the existing unit-test workflow.

## Status checks

[codecov.yml](../codecov.yml) configures two checks:

| Check | Policy |
| --- | --- |
| `codecov/project` | Overall coverage may drop by at most one percentage point from the base commit. |
| `codecov/patch` | At least 80% of the changed executable lines must be covered. |

The overall target follows the base commit instead of imposing a fixed minimum
on the existing codebase. Run the workflow on `main` to establish the initial
baseline. These are Codecov status checks; the upload action itself only checks
whether uploading succeeds. GitHub branch protection or a ruleset must require
the checks to make their failures block merging. See Codecov's
[status-check documentation](https://docs.codecov.com/docs/commit-status) for the
comparison rules.

## Repository setup

1. Enable `MetalBlockchain/pulsevm` in Codecov and grant its GitHub App access to
   the repository so it can publish checks.
2. Add the repository's Codecov upload token as the GitHub Actions secret
   `CODECOV_TOKEN`. If Dependabot opens pull requests, add it as a Dependabot
   secret too.
3. Run the workflow on `main`. After Codecov processes the first report, the
   README badge will show the coverage percentage for `main`.
4. To enforce coverage before merging, require `Rust coverage` and the Codecov
   project and patch checks in the repository's branch protection or ruleset.
   Select the exact check names GitHub shows after the first run.

Public-repository fork pull requests can use Codecov's tokenless fork uploads;
GitHub does not expose the repository secret to them. The workflow uses
`pull_request`, with read-only repository permissions. See the
[Codecov action documentation](https://github.com/codecov/codecov-action) for
authentication requirements, including private repositories and tokenless upload
settings. A private repository may also need the badge URL supplied by Codecov's
badge settings.

## Run locally

Install the normal [build prerequisites](../README.md#build-from-source), then:

```bash
rustup component add llvm-tools-preview --toolchain stable
cargo +stable install cargo-llvm-cov --version 0.8.7 --locked

export LLVM_SYS_221_PREFIX=/usr/lib/llvm-22
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
mkdir -p target/coverage
cargo +stable llvm-cov --workspace --locked --lcov \
  --ignore-filename-regex '(^|/)(tests|benches|examples)/|(^|/)crates/pulsevm_(unittests|e2e_boot|benchmark)/' \
  --output-path target/coverage/lcov.info
```

Generate a browsable report from the same run without rerunning the tests:

```bash
cargo +stable llvm-cov report --html \
  --ignore-filename-regex '(^|/)(tests|benches|examples)/|(^|/)crates/pulsevm_(unittests|e2e_boot|benchmark)/'
```

Open `target/llvm-cov/html/index.html` in a browser. Keep all coverage output under
the ignored `target/` directory. Coverage instrumentation is used only for tests;
release builds and consensus rules are unchanged.

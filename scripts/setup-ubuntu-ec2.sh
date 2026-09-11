#!/usr/bin/env bash
# Install the pinned Ubuntu toolchain used by PulseVM and build the sibling
# MetalGo/metal-network-runner repositories expected by the EC2 launcher.
set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly WORKSPACE_ROOT="$(cd "$REPO_ROOT/.." && pwd)"
readonly GO_VERSION="1.23.9"
readonly PROTOC_VERSION="27.1"
readonly RUSTFMT_TOOLCHAIN="nightly-2026-07-27"
readonly METALGO_REVISION="9e18361001d848d9ccfadd9fe04b515dc13c8c2c"
readonly RUNNER_REVISION="869d8a0cd62dac3a0fd1c503a36bdd6dfabda025"
readonly RUNNER_PATCH="$REPO_ROOT/tools/metal-network-runner-checkpoint-startup.patch"

fail() {
  echo "error: $*" >&2
  exit 1
}

download() {
  curl --proto '=https' --tlsv1.2 --fail --location --retry 5 \
    --retry-all-errors --silent --show-error --output "$2" "$1"
}

verify_sha256() {
  printf '%s  %s\n' "$2" "$1" | sha256sum --check --status || \
    fail "SHA-256 mismatch for $1"
}

install_link() {
  local target="$1"
  local link="$2"
  if [[ -L "$link" && "$(readlink "$link")" == "$target" ]]; then
    return
  fi
  [[ ! -e "$link" && ! -L "$link" ]] || \
    fail "$link already exists and is not managed by this installer"
  sudo ln -s "$target" "$link"
}

checkout_clean_revision() {
  local repo="$1"
  local revision="$2"
  [[ -d "$repo/.git" ]] || fail "missing sibling repository: $repo"
  if [[ -n "$(git -C "$repo" status --porcelain)" ]]; then
    fail "refusing to change dirty repository $repo"
  fi
  if [[ "$(git -C "$repo" rev-parse HEAD)" != "$revision" ]]; then
    git -C "$repo" fetch origin "$revision"
    git -C "$repo" switch --detach "$revision"
  fi
}

prepare_runner_revision() {
  local repo="$WORKSPACE_ROOT/metal-network-runner"
  [[ -d "$repo/.git" ]] || fail "missing sibling repository: $repo"
  [[ -f "$RUNNER_PATCH" ]] || fail "missing runner patch: $RUNNER_PATCH"
  if [[ -n "$(git -C "$repo" status --porcelain)" ]]; then
    [[ "$(git -C "$repo" rev-parse HEAD)" == "$RUNNER_REVISION" ]] || \
      fail "dirty runner is not based on the pinned revision"
    [[ "$(git -C "$repo" status --porcelain)" == " M local/network.go" ]] || \
      fail "runner contains changes beyond the checkpoint-startup patch"
    git -C "$repo" apply --unidiff-zero --reverse --check "$RUNNER_PATCH" || \
      fail "runner's local change is not the expected checkpoint-startup patch"
    return
  fi
  checkout_clean_revision "$repo" "$RUNNER_REVISION"
  git -C "$repo" apply --unidiff-zero "$RUNNER_PATCH"
}

[[ "$(uname -s)" == "Linux" ]] || fail "Linux is required"
[[ "${EUID:-$(id -u)}" -ne 0 ]] || \
  fail "run this script as the normal Ubuntu user; it invokes sudo itself"
[[ -r /etc/os-release ]] || fail "cannot identify the operating system"
# shellcheck disable=SC1091
source /etc/os-release
[[ "${ID:-}" == "ubuntu" ]] || fail "Ubuntu is required (found ${ID:-unknown})"
case "${VERSION_ID:-}" in
  22.04|24.04) ;;
  *) fail "supported Ubuntu releases are 22.04 and 24.04 (found ${VERSION_ID:-unknown})" ;;
esac
sudo -n true || fail "passwordless sudo is required for unattended EC2 setup"

case "$(uname -m)" in
  x86_64)
    go_arch="amd64"
    go_sha256="de03e45d7a076c06baaa9618d42b3b6a0561125b87f6041c6397680a71e5bb26"
    protoc_arch="x86_64"
    protoc_sha256="8970e3d8bbd67d53768fe8c2e3971bdd71e51cfe2001ca06dacad17258a7dae3"
    ;;
  aarch64)
    go_arch="arm64"
    go_sha256="3dc4dd64bdb0275e3ec65a55ecfc2597009c7c46a1b256eefab2f2172a53a602"
    protoc_arch="aarch_64"
    protoc_sha256="8809c2ec85368c6b6e9af161b6771a153aa92670a24adbe46dd34fa02a04df2f"
    ;;
  *) fail "unsupported architecture: $(uname -m)" ;;
esac

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/pulsevm-ubuntu-setup.XXXXXX")"
trap 'rm -rf -- "$tmp_dir"' EXIT

echo "==> Installing Ubuntu build packages"
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  binutils \
  build-essential \
  ca-certificates \
  cmake \
  curl \
  g++-12 \
  gcc-12 \
  git \
  gnupg \
  jq \
  libffi-dev \
  libssl-dev \
  libzstd-dev \
  lsb-release \
  ninja-build \
  perl \
  pkg-config \
  ripgrep \
  software-properties-common \
  unzip \
  wget \
  xz-utils \
  zlib1g-dev \
  zstd

if [[ ! -d /usr/lib/llvm-22 || ! -f /usr/lib/llvm-22/lib/libPolly.a ]]; then
  echo "==> Installing the complete LLVM 22 toolchain from apt.llvm.org"
  download https://apt.llvm.org/llvm.sh "$tmp_dir/llvm.sh"
  sudo bash "$tmp_dir/llvm.sh" 22 all
fi
sudo apt-get install -y --no-install-recommends llvm-22-dev libpolly-22-dev

echo "==> Installing Go $GO_VERSION"
go_root="/opt/pulsevm/go-$GO_VERSION"
if [[ ! -x "$go_root/bin/go" ]]; then
  [[ ! -e "$go_root" ]] || fail "partial Go installation exists at $go_root"
  go_archive="$tmp_dir/go.tar.gz"
  download "https://go.dev/dl/go${GO_VERSION}.linux-${go_arch}.tar.gz" "$go_archive"
  verify_sha256 "$go_archive" "$go_sha256"
  mkdir "$tmp_dir/go"
  tar -xzf "$go_archive" --strip-components=1 -C "$tmp_dir/go"
  sudo mkdir -p /opt/pulsevm
  sudo cp -a "$tmp_dir/go" "$go_root"
fi
install_link "$go_root/bin/go" /usr/local/bin/go
install_link "$go_root/bin/gofmt" /usr/local/bin/gofmt

echo "==> Installing protoc $PROTOC_VERSION"
protoc_root="/opt/pulsevm/protoc-$PROTOC_VERSION"
if [[ ! -x "$protoc_root/bin/protoc" ]]; then
  [[ ! -e "$protoc_root" ]] || fail "partial protoc installation exists at $protoc_root"
  protoc_archive="$tmp_dir/protoc.zip"
  download "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-${protoc_arch}.zip" "$protoc_archive"
  verify_sha256 "$protoc_archive" "$protoc_sha256"
  mkdir "$tmp_dir/protoc"
  unzip -q "$protoc_archive" -d "$tmp_dir/protoc"
  sudo mkdir -p /opt/pulsevm
  sudo cp -a "$tmp_dir/protoc" "$protoc_root"
fi
install_link "$protoc_root/bin/protoc" /usr/local/bin/protoc

echo "==> Installing Rust stable and the pinned rustfmt toolchain"
user_home="$(getent passwd "$(id -u)" | cut -d: -f6)"
[[ -n "$user_home" ]] || fail "cannot determine the current user's home directory"
if [[ -r "$user_home/.cargo/env" ]]; then
  # shellcheck disable=SC1091
  source "$user_home/.cargo/env"
fi
if ! command -v rustup >/dev/null 2>&1; then
  download https://sh.rustup.rs "$tmp_dir/rustup-init.sh"
  sh "$tmp_dir/rustup-init.sh" -y --profile minimal --default-toolchain stable
  # shellcheck disable=SC1091
  source "$user_home/.cargo/env"
fi
rustup toolchain install stable --profile minimal
rustup component add clippy --toolchain stable
rustup toolchain install "$RUSTFMT_TOOLCHAIN" --profile minimal
rustup component add rustfmt --toolchain "$RUSTFMT_TOOLCHAIN"
rustup default stable

export LLVM_SYS_221_PREFIX=/usr/lib/llvm-22
export CC=gcc-12
export CXX=g++-12
export PATH="/usr/local/bin:$user_home/.cargo/bin:$PATH"

if [[ "${PULSEVM_BUILD_NODE_BINARIES:-true}" == "true" ]]; then
  echo "==> Building the pinned MetalGo node"
  checkout_clean_revision "$WORKSPACE_ROOT/metalgo" "$METALGO_REVISION"
  (cd "$WORKSPACE_ROOT/metalgo" && ./scripts/build.sh)

  echo "==> Building the checkpoint-aware network runner"
  prepare_runner_revision
  (cd "$WORKSPACE_ROOT/metal-network-runner" && ./scripts/build.sh)
fi

echo "==> Building PulseVM release plugin"
(cd "$REPO_ROOT" && cargo build --release --locked -p pulsevm)

echo "==> Verifying installed toolchain"
go version
protoc --version
rustc --version
cargo --version
cmake --version | head -1
llvm-config-22 --version
[[ -x "$WORKSPACE_ROOT/metalgo/build/metalgo" ]] || fail "MetalGo binary was not built"
[[ -x "$WORKSPACE_ROOT/metal-network-runner/bin/metal-network-runner" ]] || \
  fail "metal-network-runner binary was not built"
[[ -x "$REPO_ROOT/target/release/pulsevm" ]] || fail "PulseVM release binary was not built"

echo "Ubuntu EC2 dependencies and node binaries are ready."

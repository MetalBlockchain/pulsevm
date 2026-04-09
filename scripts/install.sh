#!/bin/bash
set -euo pipefail

REPO="MetalBlockchain/pulsevm"
PLUGIN_DIR="$HOME/.metalgo/plugins"
VM_ID="rXcAFxZvio99epp6TzEwYfexCfPAbJuBTMsjUUoiT7PkVykNs"

ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  ASSET="pulsevm-linux-amd64.tar.gz" ;;
  amd64)  ASSET="pulsevm-linux-amd64.tar.gz" ;;
  arm64) ASSET="pulsevm-linux-arm64.tar.gz" ;;
  aarch64) ASSET="pulsevm-linux-arm64.tar.gz" ;;
  *) echo "Unsupported architecture: $ARCH" && exit 1 ;;
esac

DOWNLOAD_URL=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" \
  | grep -o "https://.*${ASSET}" | head -1)

if [ -z "$DOWNLOAD_URL" ]; then
  echo "Could not find $ASSET in latest release"
  exit 1
fi

echo "Downloading $ASSET..."
TMP=$(mktemp -d)
curl -sL "$DOWNLOAD_URL" -o "$TMP/$ASSET"

echo "Extracting..."
tar -xzf "$TMP/$ASSET" -C "$TMP"

echo "Installing to $PLUGIN_DIR/$VM_ID"
mkdir -p "$PLUGIN_DIR"
mv "$TMP/pulsevm" "$PLUGIN_DIR/$VM_ID"
chmod +x "$PLUGIN_DIR/$VM_ID"

rm -rf "$TMP"
echo "Done! PulseVM installed."
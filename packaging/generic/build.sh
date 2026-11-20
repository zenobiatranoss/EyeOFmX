#!/usr/bin/env bash
# Build a distro-neutral tarball containing the prebuilt binary.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION="${VERSION:-1.0.0}"
GENERIC_ARCH="${GENERIC_ARCH:-$(uname -m)}"
OUT="${OUT:-$ROOT/dist/generic}"
BIN="$ROOT/eyeofmx"

if [[ ! -x "$BIN" ]]; then
  make -C "$ROOT" build
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
dir="$tmp/eyeofmx-$VERSION-$GENERIC_ARCH"
mkdir -p "$dir" "$OUT"

install -m 0755 "$BIN" "$dir/eyeofmx"
install -m 0644 "$ROOT/io.github.eyeofmx.desktop" \
  "$dir/io.github.eyeofmx.desktop"
install -m 0644 "$ROOT/LICENSE" "$dir/LICENSE"
install -m 0644 "$ROOT/README.md" "$dir/README.md"
cat > "$dir/INSTALL.txt" <<EOF
EyeOFmX $VERSION ($GENERIC_ARCH)
================================

This tarball contains a prebuilt binary. No Go toolchain or build step is
required.

Install system-wide:
  sudo install -m 0755 eyeofmx /usr/local/bin/eyeofmx
  sudo install -m 0644 io.github.eyeofmx.desktop \\
    /usr/share/applications/io.github.eyeofmx.desktop

Run:
  eyeofmx
  eyeofmx -check
  eyeofmx -setup-plan

GTK 3 runtime must be installed. Run as root (sudo, doas or su) for full
inspection capability; the application also works unprivileged.

If scanning engines are missing, Tools -> Install scanning tools (root) shows
the distribution-specific packages and asks for confirmation and system root
authentication before installing anything.
EOF

tarball="$OUT/eyeofmx-$VERSION-$GENERIC_ARCH.tar.gz"
tar -czf "$tarball" -C "$tmp" "$(basename "$dir")"
echo "Created $tarball"

#!/usr/bin/env bash
# Build an RPM from a prebuilt EyeOFmX binary on an rpm-capable host.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION="${VERSION:-1.0.1}"
RPM_ARCH="${RPM_ARCH:-$(uname -m)}"
OUT="${OUT:-$ROOT/dist/rpm}"
BIN="$ROOT/eyeofmx"

if [[ ! -x "$BIN" ]]; then
  make -C "$ROOT" build
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/SOURCES" "$tmp/SPECS" "$tmp/RPMS" "$tmp/BUILD" \
         "$tmp/BUILDROOT" "$tmp/SRPMS"
mkdir -p "$OUT"

install -m 0755 "$BIN" "$tmp/SOURCES/eyeofmx"
install -m 0644 "$ROOT/io.github.eyeofmx.desktop" \
  "$tmp/SOURCES/io.github.eyeofmx.desktop"
cp -a "$ROOT/assets/icons" "$tmp/SOURCES/icons"
install -m 0644 "$ROOT/LICENSE" "$tmp/SOURCES/LICENSE"
sed -e "s|@VERSION@|$VERSION|g" -e "s|@RPM_ARCH@|$RPM_ARCH|g" \
  "$ROOT/packaging/rpm/eyeofmx.spec" > "$tmp/SPECS/eyeofmx.spec"

rpmbuild --define "_topdir $tmp" -bb "$tmp/SPECS/eyeofmx.spec"
find "$tmp/RPMS" -type f -name '*.rpm' -exec cp -f {} "$OUT/" \;
echo "RPM written to $OUT"

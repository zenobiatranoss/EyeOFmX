#!/usr/bin/env bash
# Build a Debian .deb on the current Debian/Ubuntu/MX host without Docker.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION="${VERSION:-1.0.0}"
DEB_ARCH="${DEB_ARCH:-$(dpkg --print-architecture)}"
OUT="${OUT:-$ROOT/dist/debian}"
BIN="$ROOT/eyeofmx"

if [[ ! -x "$BIN" ]]; then
  make -C "$ROOT" build
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/DEBIAN" "$tmp/usr/bin" "$tmp/usr/share/applications" \
         "$tmp/usr/share/licenses/eyeofmx" "$tmp/usr/share/doc/eyeofmx"
chmod 0755 "$tmp" "$tmp/usr" "$tmp/usr/bin" "$tmp/usr/share" \
           "$tmp/usr/share/applications" "$tmp/usr/share/licenses" \
           "$tmp/usr/share/licenses/eyeofmx" "$tmp/usr/share/doc" \
           "$tmp/usr/share/doc/eyeofmx" "$tmp/DEBIAN"
mkdir -p "$OUT"

install -m 0755 "$BIN" "$tmp/usr/bin/eyeofmx"
install -m 0644 "$ROOT/io.github.eyeofmx.desktop" \
  "$tmp/usr/share/applications/io.github.eyeofmx.desktop"
install -m 0644 "$ROOT/LICENSE" "$tmp/usr/share/licenses/eyeofmx/LICENSE"
sed -e "s|@VERSION@|$VERSION|g" -e "s|@ARCH@|$DEB_ARCH|g" \
  "$ROOT/packaging/debian/control" > "$tmp/DEBIAN/control"
cat > "$tmp/usr/share/doc/eyeofmx/changelog" <<EOF
eyeofmx ($VERSION) stable; urgency=low

  * Prebuilt binary package.

 -- Zenobia <zenobia@users.noreply.github.com>  Sat, 21 Nov 2026 00:00:00 +0000
EOF

deb="$OUT/eyeofmx_${VERSION}_${DEB_ARCH}.deb"
dpkg-deb --root-owner-group --build "$tmp" "$deb"
echo "Created $deb"

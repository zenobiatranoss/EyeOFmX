#!/usr/bin/env bash
# Build single-file installers for every supported Linux family.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${VERSION:-1.0.0}"
OUT="${OUT:-$ROOT/dist}"
TARGETS="${TARGETS:-debian fedora opensuse arch alpine generic}"
ARCH="${ARCH:-$(uname -m)}"
ENGINE="${ENGINE:-docker}"

case "$ARCH" in
  x86_64|amd64)
    DEB_ARCH=amd64; RPM_ARCH=x86_64; ARCH_ARCH=x86_64; APK_ARCH=x86_64; GENERIC_ARCH=x86_64 ;;
  aarch64|arm64)
    DEB_ARCH=arm64; RPM_ARCH=aarch64; ARCH_ARCH=aarch64; APK_ARCH=aarch64; GENERIC_ARCH=aarch64 ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    echo "Set ARCH=x86_64 or ARCH=aarch64 (cross builds need binfmt/QEMU)." >&2
    exit 1 ;;
esac

if [[ "$TARGETS" == *"generic"* ]]; then
  OUT="$OUT/generic" GENERIC_ARCH="$GENERIC_ARCH" VERSION="$VERSION" \
    "$ROOT/packaging/generic/build.sh"
fi

docker_targets="${TARGETS//generic/}"
for target in $docker_targets; do
  dockerfile="$ROOT/packaging/$target/Dockerfile"
  if [[ ! -f "$dockerfile" ]]; then
    echo "No Dockerfile for target: $target" >&2
    exit 1
  fi
  mkdir -p "$OUT/$target"
  echo "==> Building $target package"

  args=(
    build
    --build-arg "VERSION=$VERSION"
    --build-arg "DEB_ARCH=$DEB_ARCH"
    --build-arg "RPM_ARCH=$RPM_ARCH"
    --build-arg "ARCH_ARCH=$ARCH_ARCH"
    --build-arg "APK_ARCH=$APK_ARCH"
    --file "$dockerfile"
    --output "type=local,dest=$OUT/$target"
    "$ROOT"
  )

  if ! DOCKER_BUILDKIT=1 "$ENGINE" "${args[@]}"; then
    echo "Failed to build $target. Docker with BuildKit is required." >&2
    exit 1
  fi
done

echo "Packages are in $OUT"

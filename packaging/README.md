# EyeOFmX prebuilt packages

Created by **Zenobia**. **For NT Protection**. These packages are made for
common Linux distributions.

This directory turns the Go source into **single-file installers** for the
major Linux families. An end user downloads one file for their distribution and
installs it with the normal package manager. No Go toolchain, no source code
and no manual build are required.

## Targets

| Directory | Output file | Install with |
|---|---|---|
| `debian/` | `eyeofmx_VERSION_amd64.deb` | `sudo apt install ./eyeofmx_VERSION_amd64.deb` |
| `fedora/` | `eyeofmx-VERSION-1.x86_64.rpm` | `sudo dnf install ./eyeofmx-VERSION-1.x86_64.rpm` |
| `opensuse/` | `eyeofmx-VERSION-1.x86_64.rpm` | `sudo zypper install ./eyeofmx-VERSION-1.x86_64.rpm` |
| `arch/` | `eyeofmx-VERSION-1-x86_64.pkg.tar.zst` | `sudo pacman -U ./eyeofmx-VERSION-1-x86_64.pkg.tar.zst` |
| `alpine/` | `eyeofmx-VERSION-r0-x86_64.apk` | `sudo apk add --allow-untrusted ./eyeofmx-VERSION-r0-x86_64.apk` |
| `generic/` | `eyeofmx-VERSION-x86_64.tar.gz` | extract, then `sudo install -m755 eyeofmx /usr/local/bin/` |

Every package contains a binary built against that distribution's GTK 3 ABI.
The generic tarball is the fallback for any other glibc or musl distribution
that provides GTK 3.

## Build everything

Requires Docker with BuildKit enabled:

```bash
VERSION=1.0.0 ./packaging/build.sh
```

Artifacts are written to `dist/<target>/`. To build only some targets:

```bash
TARGETS="debian fedora" VERSION=1.0.0 ./packaging/build.sh
```

Cross-architecture builds (`aarch64`/`arm64`) require an emulator such as
QEMU/binfmt or a native ARM builder. Set `ARCH=aarch64` when running on one.

## Build without Docker

On a matching host you can build individual packages directly:

```bash
./packaging/debian/build-local.sh          # needs dpkg-deb
./packaging/rpm/build-local.sh             # needs rpmbuild
./packaging/generic/build.sh               # needs tar + gzip
```

Arch and Alpine packages are produced by their native `makepkg` and `abuild`
tools inside the provided Dockerfiles.

## Automated releases and download site

`.github/workflows/release.yml` builds all targets when a tag like `v1.0.0` is
pushed, attaches the files to the GitHub Release, generates `site/` and deploys
it to GitHub Pages. Users then only download the file that matches their
distribution from one simple page. See `site/index.html` and `site/generate.sh`.

# Builds a Debian .deb against the Debian GTK 3 ABI.
FROM golang:1.22-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc pkg-config libgtk-3-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_CFLAGS="-Wno-deprecated-declarations" \
    go build -tags gtk_3_20 -trimpath -ldflags="-s -w" \
    -o /out/eyeofmx ./cmd/eyeofmx

FROM debian:bookworm-slim AS packager
ARG VERSION=1.0.1
ARG DEB_ARCH=amd64

RUN apt-get update && apt-get install -y --no-install-recommends dpkg-dev \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /pkg/DEBIAN /pkg/usr/bin /pkg/usr/share/applications \
        /pkg/usr/share/licenses/eyeofmx /pkg/usr/share/doc/eyeofmx /out
COPY --from=builder /out/eyeofmx /pkg/usr/bin/eyeofmx
COPY io.github.eyeofmx.desktop /pkg/usr/share/applications/io.github.eyeofmx.desktop
COPY assets/icons /pkg/usr/share/icons/hicolor/
COPY LICENSE /pkg/usr/share/licenses/eyeofmx/LICENSE
COPY packaging/debian/control /tmp/control
RUN sed -e "s|@VERSION@|${VERSION}|g" -e "s|@ARCH@|${DEB_ARCH}|g" \
        /tmp/control > /pkg/DEBIAN/control
RUN printf '%s\n' \
        'eyeofmx (VERSION) stable; urgency=low' \
        '' \
        '  * Prebuilt binary package.' \
        '' \
        ' -- Zenobia <zenobia@users.noreply.github.com>  Sat, 21 Nov 2026 00:00:00 +0000' \
        | sed "s|VERSION|${VERSION}|" > /pkg/usr/share/doc/eyeofmx/changelog
RUN dpkg-deb --root-owner-group --build /pkg \
        "/out/eyeofmx_${VERSION}_${DEB_ARCH}.deb"

FROM scratch AS export
COPY --from=packager /out/ /

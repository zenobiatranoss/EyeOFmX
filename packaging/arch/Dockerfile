FROM archlinux:base-devel AS packager
ARG VERSION=1.0.1
ARG ARCH_ARCH=x86_64

RUN pacman -Syu --noconfirm go gtk3 pkgconf \
    && pacman -Scc --noconfirm

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_CFLAGS="-Wno-deprecated-declarations" \
    go build -tags gtk_3_20 -trimpath -ldflags="-s -w" \
    -o /pkg/eyeofmx ./cmd/eyeofmx

RUN useradd -m -G wheel builder
COPY packaging/arch/PKGBUILD /pkg/PKGBUILD
COPY io.github.eyeofmx.desktop /pkg/io.github.eyeofmx.desktop
COPY assets/icons /pkg/icons
COPY LICENSE /pkg/LICENSE
RUN sed -e "s|@VERSION@|${VERSION}|g" -e "s|@ARCH_ARCH@|${ARCH_ARCH}|g" \
        /pkg/PKGBUILD > /tmp/PKGBUILD && mv /tmp/PKGBUILD /pkg/PKGBUILD
RUN mkdir -p /out && chown -R builder:builder /pkg /out

USER builder
WORKDIR /pkg
RUN makepkg -f --noconfirm

USER root
RUN cp /pkg/*.pkg.tar.zst /out/

FROM scratch AS export
COPY --from=packager /out/ /

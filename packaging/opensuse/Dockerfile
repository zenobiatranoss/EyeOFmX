ARG BASE_IMAGE=opensuse/tumbleweed:latest
FROM ${BASE_IMAGE} AS builder

RUN zypper --non-interactive install go gtk3-devel pkgconfig gcc ca-certificates \
    && zypper --non-interactive clean --all

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_CFLAGS="-Wno-deprecated-declarations" \
    go build -tags gtk_3_20 -trimpath -ldflags="-s -w" \
    -o /out/eyeofmx ./cmd/eyeofmx

FROM ${BASE_IMAGE} AS packager
ARG VERSION=1.0.1
ARG RPM_ARCH=x86_64

RUN zypper --non-interactive install rpm-build \
    && zypper --non-interactive clean --all
RUN mkdir -p /work/SOURCES /work/SPECS /work/RPMS /work/BUILD \
        /work/BUILDROOT /work/SRPMS /out
COPY --from=builder /out/eyeofmx /work/SOURCES/eyeofmx
COPY io.github.eyeofmx.desktop /work/SOURCES/io.github.eyeofmx.desktop
COPY assets/icons /work/SOURCES/icons
COPY LICENSE /work/SOURCES/LICENSE
COPY packaging/rpm/eyeofmx.spec /tmp/eyeofmx.spec
RUN sed -e "s|@VERSION@|${VERSION}|g" -e "s|@RPM_ARCH@|${RPM_ARCH}|g" \
        /tmp/eyeofmx.spec > /work/SPECS/eyeofmx.spec
RUN rpmbuild --define "_topdir /work" -bb /work/SPECS/eyeofmx.spec
RUN find /work/RPMS -type f -name '*.rpm' -exec cp -f {} /out/ \;

FROM scratch AS export
COPY --from=packager /out/ /

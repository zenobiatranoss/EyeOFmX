FROM alpine:3.20 AS packager
ARG VERSION=1.0.1
ARG APK_ARCH=x86_64

ENV PACKAGER="Zenobia <zenobia@users.noreply.github.com>"

RUN apk add --no-cache go gtk3-dev pkgconf build-base abuild \
    && adduser -D builder \
    && addgroup builder abuild \
    && mkdir -p /home/builder/.abuild /out \
    && chown -R builder:builder /home/builder /out

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_CFLAGS="-Wno-deprecated-declarations" \
    go build -tags gtk_3_20 -trimpath -ldflags="-s -w" \
    -o /pkg/eyeofmx ./cmd/eyeofmx

COPY packaging/alpine/APKBUILD /pkg/APKBUILD
COPY io.github.eyeofmx.desktop /pkg/io.github.eyeofmx.desktop
COPY assets/icons /pkg/icons
COPY LICENSE /pkg/LICENSE
RUN sed -e "s|@VERSION@|${VERSION}|g" -e "s|@APK_ARCH@|${APK_ARCH}|g" \
        /pkg/APKBUILD > /tmp/APKBUILD && mv /tmp/APKBUILD /pkg/APKBUILD
RUN chown -R builder:builder /pkg

USER builder
WORKDIR /pkg
RUN abuild-keygen -a -n && abuild -r

USER root
RUN cp /home/builder/packages/*/*.apk /out/

FROM scratch AS export
COPY --from=packager /out/ /

# EyeOFmX — native GTK 3 desktop application for Linux.
#
# The gtk_3_20 build tag works around an upstream gotk3 v0.6.4 source bug in
# gdk/gdk_since_3_22.go (missing callback import) that appears with modern Go
# toolchains. It merely pins the binding to the GTK 3.20 API level; the app
# still runs against GTK 3.24+ on every distribution without feature loss.

GO       ?= go
TAGS     ?= gtk_3_20
CGOFLAGS ?= -Wno-deprecated-declarations
BIN      ?= eyeofmx
VERSION  ?= 1.0.1
PKG_CONFIG ?= pkg-config

GTK_PACKAGES = gtk+-3.0 gdk-3.0 glib-2.0 gobject-2.0

.PHONY: all check-deps build test vet check tidy clean install run package package-deb package-rpm package-generic site

all: build

# Fails early with a clear message if the native GTK 3 development files are
# missing. Package names differ by distribution; see README.md.
check-deps:
	@command -v $(PKG_CONFIG) >/dev/null 2>&1 || { \
		echo "pkg-config is required to build EyeOFmX."; exit 1; }
	@for pkg in $(GTK_PACKAGES); do \
		$(PKG_CONFIG) --exists $$pkg || { \
			echo "Missing pkg-config package: $$pkg"; \
			echo "Install the GTK 3 development headers for your distribution (see README.md)."; \
			exit 1; \
		}; \
	done
	@echo "GTK 3 development files found."

build: check-deps
	CGO_CFLAGS="$(CGOFLAGS)" $(GO) build -tags $(TAGS) -trimpath -ldflags="-s -w" -o $(BIN) ./cmd/eyeofmx

test:
	CGO_CFLAGS="$(CGOFLAGS)" $(GO) test -tags $(TAGS) ./...

vet:
	CGO_CFLAGS="$(CGOFLAGS)" $(GO) vet -tags $(TAGS) ./...

check: test vet
	CGO_CFLAGS="$(CGOFLAGS)" $(GO) run -tags $(TAGS) ./cmd/eyeofmx -check

run: build
	./$(BIN)

tidy:
	$(GO) mod tidy

clean:
	rm -f $(BIN)

install: build
	install -m 0755 $(BIN) /usr/local/bin/$(BIN)

# Single-file installers. `make package` needs Docker with BuildKit.
# The *-deb, *-rpm and *-generic helpers build directly on a matching host.
package:
	VERSION="$(VERSION)" ./packaging/build.sh

package-deb: build
	VERSION="$(VERSION)" ./packaging/debian/build-local.sh

package-rpm: build
	VERSION="$(VERSION)" ./packaging/rpm/build-local.sh

package-generic: build
	VERSION="$(VERSION)" ./packaging/generic/build.sh

site:
	VERSION="$(VERSION)" ./site/generate.sh

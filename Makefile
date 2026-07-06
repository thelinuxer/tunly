# From-source / distro-packaging install (no pip). For pipx/PyPI use pyproject.toml.
PREFIX ?= /usr/local
DESTDIR ?=

PKGDIR  = $(DESTDIR)$(PREFIX)/share/tunly
BINDIR  = $(DESTDIR)$(PREFIX)/bin
APPDIR  = $(DESTDIR)$(PREFIX)/share/applications
ICONDIR = $(DESTDIR)$(PREFIX)/share/icons/hicolor/scalable/apps
RUNPKG  = $(PREFIX)/share/tunly

.PHONY: install uninstall deb

install:
	install -d $(PKGDIR)/tunly/data
	install -m644 src/tunly/__init__.py $(PKGDIR)/tunly/
	install -m644 src/tunly/__main__.py $(PKGDIR)/tunly/
	install -m644 src/tunly/data/* $(PKGDIR)/tunly/data/
	install -d $(BINDIR)
	sed 's#@PKGDIR@#$(RUNPKG)#' packaging/tunly.in > $(BINDIR)/tunly
	chmod 755 $(BINDIR)/tunly
	install -Dm644 src/tunly/data/tunly.desktop $(APPDIR)/tunly.desktop
	install -Dm644 src/tunly/data/tunly.svg $(ICONDIR)/tunly.svg

uninstall:
	rm -rf $(PKGDIR)
	rm -f $(BINDIR)/tunly
	rm -f $(APPDIR)/tunly.desktop
	rm -f $(ICONDIR)/tunly.svg

deb:
	sh packaging/deb/build-deb.sh

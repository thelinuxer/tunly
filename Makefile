# From-source / distro-packaging install (no pip). For pipx/PyPI use pyproject.toml.
PREFIX ?= /usr/local
DESTDIR ?=

PKGDIR  = $(DESTDIR)$(PREFIX)/share/ssh-socks-tray
BINDIR  = $(DESTDIR)$(PREFIX)/bin
APPDIR  = $(DESTDIR)$(PREFIX)/share/applications
ICONDIR = $(DESTDIR)$(PREFIX)/share/icons/hicolor/scalable/apps
RUNPKG  = $(PREFIX)/share/ssh-socks-tray

.PHONY: install uninstall deb

install:
	install -d $(PKGDIR)/ssh_socks_tray/data
	install -m644 src/ssh_socks_tray/__init__.py $(PKGDIR)/ssh_socks_tray/
	install -m644 src/ssh_socks_tray/__main__.py $(PKGDIR)/ssh_socks_tray/
	install -m644 src/ssh_socks_tray/data/* $(PKGDIR)/ssh_socks_tray/data/
	install -d $(BINDIR)
	sed 's#@PKGDIR@#$(RUNPKG)#' packaging/ssh-socks-tray.in > $(BINDIR)/ssh-socks-tray
	chmod 755 $(BINDIR)/ssh-socks-tray
	install -Dm644 src/ssh_socks_tray/data/ssh-socks-tray.desktop $(APPDIR)/ssh-socks-tray.desktop
	install -Dm644 src/ssh_socks_tray/data/ssh-socks-tray.svg $(ICONDIR)/ssh-socks-tray.svg

uninstall:
	rm -rf $(PKGDIR)
	rm -f $(BINDIR)/ssh-socks-tray
	rm -f $(APPDIR)/ssh-socks-tray.desktop
	rm -f $(ICONDIR)/ssh-socks-tray.svg

deb:
	sh packaging/deb/build-deb.sh

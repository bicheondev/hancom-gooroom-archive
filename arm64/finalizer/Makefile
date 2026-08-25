SHELL := /usr/bin/env bash
PREFIX ?= /usr/local
LIBEXECDIR ?= $(PREFIX)/libexec/hancom-gooroom-arm64

.PHONY: selftest install uninstall

selftest:
	bash tests/selftest.sh

install:
	install -d "$(DESTDIR)$(LIBEXECDIR)"
	install -m 0755 bin/*.sh "$(DESTDIR)$(LIBEXECDIR)/"
	@printf 'Installed ARM64 finalizer programs under %s\n' "$(DESTDIR)$(LIBEXECDIR)"

uninstall:
	rm -rf "$(DESTDIR)$(LIBEXECDIR)"

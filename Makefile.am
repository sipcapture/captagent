include common.am

SUBDIRS = \
	src \
	include

EXTRA_DIST = \
	conf \
	@PACKAGE_NAME@.spec \
	pkg \
	LICENSE \
	NEWS \
	README \
	README.md

ACLOCAL_AMFLAGS = -I m4

dist-local:
	cp -r pkg $(distdir)/

distclean-local:
	rm -rf autom4te.cache

.PHONY: deb
deb:
	-@if [ -d debian ]; then \
	    dpkg-buildpackage -rfakeroot -tc && \
	    rm debian; \
	else \
	    ln -s pkg/debian debian && \
	    dpkg-buildpackage -rfakeroot -tc && \
	    rm debian; \
	fi

.PHONY: deb-stable
deb-stable:
	-@if [ -d debian ]; then \
	    dpkg-buildpackage -rfakeroot -tc && \
	    rm debian; \
	else \
	    ln -s pkg/wheezy debian && \
	    dpkg-buildpackage -rfakeroot -tc && \
	    rm debian; \
	fi

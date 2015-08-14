include common.am

SUBDIRS = \
	src \
	include

EXTRA_DIST = \
	conf \
	@PACKAGE_NAME@.spec

ACLOCAL_AMFLAGS = -I m4

distclean-local:
	rm -rf autom4te.cache

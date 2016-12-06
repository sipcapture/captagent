include common.am

SUBDIRS = \
	src \
	include

EXTRA_DIST = \
	conf \
	README.md \
	@PACKAGE_NAME@.spec \
	@PACKAGE_NAME@.spec.in \
	pkg/debian/@PACKAGE_NAME@.init.in \
	pkg/el/captagent.sysconfig \
	pkg/el/7/captagent.service

ACLOCAL_AMFLAGS = -I m4

distclean-local:
	rm -rf autom4te.cache

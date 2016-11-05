include $(top_srcdir)/modules.am

SUBDIRS = \
	. \
	captureplan

noinst_HEADERS = socket_tzsp.h
#
socket_tzsp_la_SOURCES = socket_tzsp.c
socket_tzsp_la_CFLAGS = -Wall ${MODULE_CFLAGS}
socket_tzsp_la_LDFLAGS = -module -avoid-version
socket_tzsp_la_LIBADD = ${PTHREAD_LIBS} ${EXPAT_LIBS} ${tzsp_LIBS} ${UV_LIBS}
socket_tzsp_laconfdir = $(confdir)
socket_tzsp_laconf_DATA = $(top_srcdir)/conf/socket_tzsp.xml

mod_LTLIBRARIES = socket_tzsp.la

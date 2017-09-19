include $(top_srcdir)/modules.am

SUBDIRS = \
	. \
	captureplan

noinst_HEADERS = socket_collector.h
#
socket_collector_la_SOURCES = socket_collector.c
socket_collector_la_CFLAGS = -Wall ${MODULE_CFLAGS}
socket_collector_la_LDFLAGS = -module -avoid-version
socket_collector_la_LIBADD = ${PTHREAD_LIBS} ${EXPAT_LIBS} ${collector_LIBS} ${UV_LIBS}
socket_collector_laconfdir = $(confdir)
socket_collector_laconf_DATA = $(top_srcdir)/conf/socket_collector.xml

mod_LTLIBRARIES = socket_collector.la

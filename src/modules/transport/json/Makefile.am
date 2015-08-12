include $(top_srcdir)/modules.am

SUBDIRS = .
noinst_HEADERS = transport_json.h
#
transport_json_la_SOURCES = transport_json.c
transport_json_la_CFLAGS = -Wall ${MODULE_CFLAGS}
transport_json_la_LDFLAGS = -module -avoid-version
transport_json_la_LIBADD = ${PTHREAD_LIBS} ${EXPAT_LIBS} ${JSON_LIBS}
transport_json_laconfdir = $(confdir)
transport_json_laconf_DATA = $(top_srcdir)/conf/transport_json.xml

mod_LTLIBRARIES = transport_json.la

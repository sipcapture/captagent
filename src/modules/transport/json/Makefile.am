include $(top_srcdir)/modules.am

SUBDIRS = .
noinst_HEADERS = output_json.h
#
output_json_la_SOURCES = output_json.c
output_json_la_CFLAGS = -Wall ${MODULE_CFLAGS}
output_json_la_LDFLAGS = -module -avoid-version
output_json_la_LIBADD = ${PTHREAD_LIBS} ${EXPAT_LIBS} ${JSON_LIBS}
output_json_laconfdir = $(confdir)
output_json_laconf_DATA = $(top_srcdir)/conf/output_json.xml

mod_LTLIBRARIES = output_json.la

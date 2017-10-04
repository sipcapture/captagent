include $(top_srcdir)/modules.am

SUBDIRS = \
	. \
	captureplan

noinst_HEADERS = parser_diameter.h protocol_diameter.h
#
protocol_diameter_la_SOURCES = protocol_diameter.c parser_diameter.c
protocol_diameter_la_CFLAGS = -Wall ${MODULE_CFLAGS}
protocol_diameter_la_LDFLAGS = -module -avoid-version
protocol_diameter_la_LIBADD = ${PTHREAD_LIBS} ${EXPAT_LIBS}
protocol_diameter_laconfdir = $(confdir)
protocol_diameter_laconf_DATA = $(top_srcdir)/conf/protocol_diameter.xml

mod_LTLIBRARIES = protocol_diameter.la

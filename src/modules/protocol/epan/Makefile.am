include $(top_srcdir)/modules.am

SUBDIRS = \
	.

noinst_HEADERS =
#
protocol_epan_la_SOURCES = protocol_epan.c
protocol_epan_la_CFLAGS = -Wall ${MODULE_CFLAGS}
protocol_epan_la_LDFLAGS = -module -avoid-version
protocol_epan_la_LIBADD = ${PTHREAD_LIBS} ${EXPAT_LIBS} ${PCAP_LIBS}
protocol_epan_laconfdir = $(confdir)
protocol_epan_laconf_DATA = $(top_srcdir)/conf/protocol_epan.xml

mod_LTLIBRARIES = protocol_epan.la


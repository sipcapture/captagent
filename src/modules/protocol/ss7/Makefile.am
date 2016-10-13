include $(top_srcdir)/modules.am

SUBDIRS = \
	.

noinst_HEADERS =
#
protocol_ss7_la_SOURCES = protocol_ss7.c
protocol_ss7_la_CFLAGS = -Wall ${MODULE_CFLAGS}
protocol_ss7_la_LDFLAGS = -module -avoid-version
protocol_ss7_la_LIBADD = ${PTHREAD_LIBS} ${EXPAT_LIBS} ${PCAP_LIBS}
protocol_ss7_laconfdir = $(confdir)
protocol_ss7_laconf_DATA = $(top_srcdir)/conf/protocol_ss7.xml

mod_LTLIBRARIES = protocol_ss7.la


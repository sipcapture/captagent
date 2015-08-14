include $(top_srcdir)/modules.am

SUBDIRS = \
	. \
	captureplan

noinst_HEADERS = parser_sip.h protocol_sip.h
#
protocol_sip_la_SOURCES = protocol_sip.c parser_sip.c
protocol_sip_la_CFLAGS = -Wall ${MODULE_CFLAGS}
protocol_sip_la_LDFLAGS = -module -avoid-version
protocol_sip_la_LIBADD = ${PTHREAD_LIBS} ${EXPAT_LIBS} ${PCAP_LIBS}
protocol_sip_laconfdir = $(confdir)
protocol_sip_laconf_DATA = $(top_srcdir)/conf/protocol_sip.xml

mod_LTLIBRARIES = protocol_sip.la

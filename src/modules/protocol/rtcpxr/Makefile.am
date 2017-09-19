include $(top_srcdir)/modules.am

SUBDIRS = \
	. \
	captureplan

noinst_HEADERS = parser_rtcpxr.h protocol_rtcpxr.h
#
protocol_rtcp_la_SOURCES = protocol_rtcpxr.c parser_rtcpxr.c
protocol_rtcp_la_CFLAGS = -Wall ${MODULE_CFLAGS}
protocol_rtcp_la_LDFLAGS = -module -avoid-version
protocol_rtcp_la_LIBADD = ${PTHREAD_LIBS} ${EXPAT_LIBS}
protocol_rtcp_laconfdir = $(confdir)
protocol_rtcp_laconf_DATA = $(top_srcdir)/conf/protocol_rtcpxr.xml

mod_LTLIBRARIES = protocol_rtcpxr.la

include $(top_srcdir)/modules.am

SUBDIRS = \
	. \
	captureplan

noinst_HEADERS = parser_rtcpxr.h protocol_rtcpxr.h
#
protocol_rtcpxr_la_SOURCES = protocol_rtcpxr.c parser_rtcpxr.c
protocol_rtcpxr_la_CFLAGS = -Wall ${MODULE_CFLAGS}
protocol_rtcpxr_la_LDFLAGS = -module -avoid-version
protocol_rtcpxr_la_LIBADD = ${PTHREAD_LIBS} ${EXPAT_LIBS}
protocol_rtcpxr_laconfdir = $(confdir)
protocol_rtcpxr_laconf_DATA = $(top_srcdir)/conf/protocol_rtcpxr.xml

mod_LTLIBRARIES = protocol_rtcpxr.la

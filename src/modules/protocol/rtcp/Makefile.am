include $(top_srcdir)/modules.am

SUBDIRS = .
noinst_HEADERS = parser_rtcp.h protocol_rtcp.h
#
protocol_rtcp_la_SOURCES = protocol_rtcp.c parser_rtcp.c
protocol_rtcp_la_CFLAGS = -Wall ${MODULE_CFLAGS}
protocol_rtcp_la_LDFLAGS = -module -avoid-version
protocol_rtcp_la_LIBADD = ${PTHREAD_LIBS} ${EXPAT_LIBS}
protocol_rtcp_laconfdir = $(confdir)
protocol_rtcp_laconf_DATA = $(top_srcdir)/conf/protocol_rtcp.xml

mod_LTLIBRARIES = protocol_rtcp.la

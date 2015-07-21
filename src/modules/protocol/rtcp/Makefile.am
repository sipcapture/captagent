include $(top_srcdir)/modules.am

SUBDIRS = .
#
protocol_rtcp_la_SOURCES = protocol_rtcp.c parser_rtcp.c
protocol_rtcp_la_CFLAGS = -Wall ${MODULE_CFLAGS}
protocol_rtcp_la_LDFLAGS = -module -avoid-version
protocol_rtcp_la_LIBADD = ${PTHREAD_LIBS} ${EXPAT_LIBS}

mod_LTLIBRARIES = protocol_rtcp.la

install: install-am
	rm -f $(moddir)/protocol_rtcp.a
	rm -f $(moddir)/protocol_rtcp.la

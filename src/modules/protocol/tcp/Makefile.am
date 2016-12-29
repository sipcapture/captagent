include $(top_srcdir)/modules.am

SUBDIRS = .
noinst_HEADERS = protocol_tcp.h localapi.h 
#
protocol_tcp_la_SOURCES = protocol_tcp.c localapi.c
protocol_tcp_la_CFLAGS = -Wall ${MODULE_CFLAGS} ${EXPAT_LIBS}
protocol_tcp_la_LDFLAGS = -module -avoid-version
protocol_tcp_laconfdir = $(confdir)
protocol_tcp_laconf_DATA = $(top_srcdir)/conf/protocol_tcp.xml


include_HEADERS =
mod_LTLIBRARIES = protocol_tcp.la

include $(top_srcdir)/modules.am

SUBDIRS = \
	.

noinst_HEADERS = protocol_tcp.h localapi.h uthash.h tls_ssl.h structures.h define.h hash_structure.h
#
protocol_tcp_la_SOURCES = protocol_tcp.c localapi.c tls_ssl.c
protocol_tcp_la_CFLAGS = -Wall ${MODULE_CFLAGS} ${EXPAT_LIBS}
protocol_tcp_la_LDFLAGS = -module -avoid-version
protocol_tcp_laconfdir = $(confdir)
protocol_tcp_laconf_DATA = $(top_srcdir)/conf/protocol_tcp.xml

mod_LTLIBRARIES = protocol_tcp.la

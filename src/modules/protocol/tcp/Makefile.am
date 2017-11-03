include $(top_srcdir)/modules.am

SUBDIRS = \
	.

noinst_HEADERS = protocol_tcp.h localapi.h uthash.h parser_tls.h structures.h define.h hash_structure.h decription.h
#
protocol_tcp_la_SOURCES = protocol_tcp.c localapi.c parser_tls.c decription.c
protocol_tcp_la_CFLAGS = -Wall ${MODULE_CFLAGS} ${EXPAT_LIBS} -I/usr/include/openssl -lcrypto
protocol_tcp_la_LDFLAGS = -module -avoid-version
protocol_tcp_la_LM      = -lm
protocol_tcp_laconfdir = $(confdir)
protocol_tcp_laconf_DATA = $(top_srcdir)/conf/protocol_tcp.xml

mod_LTLIBRARIES = protocol_tcp.la

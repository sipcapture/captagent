include $(top_srcdir)/modules.am

SUBDIRS = \
	. \
	captureplan

noinst_HEADERS = protocol_tls.h localapi.h uthash.h parser_tls.h define.h decryption.h
#
protocol_tls_la_SOURCES  = protocol_tls.c localapi.c parser_tls.c decryption.c
protocol_tls_la_CFLAGS   = -Wall ${MODULE_CFLAGS}
protocol_tls_la_LDFLAGS  = -I/usr/include/openssl -module -avoid-version
protocol_tls_la_LIBADD   = ${PTHREAD_LIBS} ${EXPAT_LIBS} ${GCRYPT_LIBS} ${CRYPTO_LIBS} -lm
protocol_tls_laconfdir   = $(confdir)
protocol_tls_laconf_DATA = $(top_srcdir)/conf/protocol_tls.xml

mod_LTLIBRARIES = protocol_tls.la

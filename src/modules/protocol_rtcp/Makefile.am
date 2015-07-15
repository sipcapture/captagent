#
#
protocol_rtcp_la_SOURCES = protocol_rtcp.c parser_rtcp.c 
protocol_rtcp_la_CFLAGS = -Wall ${MODULE_CFLAGS}
protocol_rtcp_la_LDFLAGS = -module -avoid-version 
protocol_rtcp_la_LIBADD = ${PTHREAD_LIBS} ${EXPAT_LIBS}

mod_LTLIBRARIES = protocol_rtcp.la

moddir = $(libdir)/captagent/modules

AM_CPPFLAGS=${AP_INCLUDES}
AM_CFLAGS=${AM_CFLAGS}

install: install-am
	rm -f $(libdir)/captagent/modules/protocol_rtcp.a
	rm -f $(libdir)/captagent/modules/protocol_rtcp.la
 	
CLEANFILES=         *.la *.lo *.o *.so *.slo .libs/*

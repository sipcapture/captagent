#
#
protocol_sip_la_SOURCES = protocol_sip.c parser_sip.c 
protocol_sip_la_CFLAGS = -Wall ${MODULE_CFLAGS}
protocol_sip_la_LDFLAGS = -module -avoid-version 
protocol_sip_la_LIBADD = ${PTHREAD_LIBS} ${EXPAT_LIBS} ${PCAP_LIBS}

mod_LTLIBRARIES = protocol_sip.la

moddir = $(libdir)/captagent/modules

AM_CPPFLAGS=${AP_INCLUDES}
AM_CFLAGS=${AM_CFLAGS}

install: install-am
	rm -f $(libdir)/captagent/modules/protocol_sip.a
	rm -f $(libdir)/captagent/modules/protocol_sip.la
 	
CLEANFILES=         *.la *.lo *.o *.so *.slo .libs/*

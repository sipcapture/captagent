#
#
transport_json_la_SOURCES = transport_json.c
transport_json_la_CFLAGS = -Wall ${MODULE_CFLAGS}
transport_json_la_LDFLAGS = -module -avoid-version 
transport_json_la_LIBADD = ${PTHREAD_LIBS} ${EXPAT_LIBS} ${JSON_LIBS}

mod_LTLIBRARIES = transport_json.la

moddir = $(libdir)/captagent/modules

AM_CPPFLAGS=${AP_INCLUDES}
AM_CFLAGS=${AM_CFLAGS}

install: install-am
	rm -f $(libdir)/captagent/modules/transport_json.a
	rm -f $(libdir)/captagent/modules/transport_json.la
 	
CLEANFILES=         *.la *.lo *.o *.so *.slo .libs/*

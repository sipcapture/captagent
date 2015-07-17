#
#
transport_hep_la_SOURCES = transport_hep.c
transport_hep_la_CFLAGS = -Wall ${MODULE_CFLAGS}
transport_hep_la_LDFLAGS = -module -avoid-version 
transport_hep_la_LIBADD = ${PTHREAD_LIBS} ${EXPAT_LIBS} ${PCAP_LIBS}

mod_LTLIBRARIES = transport_hep.la

moddir = $(libdir)/captagent/modules

AM_CPPFLAGS=${AP_INCLUDES}
AM_CFLAGS=${AM_CFLAGS}

install: install-am
	rm -f $(libdir)/captagent/modules/transport_hep.a
	rm -f $(libdir)/captagent/modules/transport_hep.la
 	
CLEANFILES=         *.la *.lo *.o *.so *.slo .libs/*
DISTCLEANFILES = Makefile.in

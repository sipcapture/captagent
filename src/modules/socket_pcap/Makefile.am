#
#
socket_pcap_la_SOURCES = socket_pcap.c ipreasm.c 
socket_pcap_la_CFLAGS = -Wall ${MODULE_CFLAGS} ${LUA_CFLAGS}
socket_pcap_la_LDFLAGS = -module -avoid-version 
socket_pcap_la_LIBADD = ${PTHREAD_LIBS} ${EXPAT_LIBS} ${PCAP_LIBS} ${LUA_LIBS}

mod_LTLIBRARIES = socket_pcap.la

moddir = $(libdir)/captagent/modules

AM_CPPFLAGS=${AP_INCLUDES}
AM_CFLAGS=${AM_CFLAGS}

install: install-am
	rm -f $(libdir)/captagent/modules/socket_pcap.a
	rm -f $(libdir)/captagent/modules/socket_pcap.la
 	
CLEANFILES=         *.la *.lo *.o *.so *.slo .libs/*
DISTCLEANFILES = Makefile.in

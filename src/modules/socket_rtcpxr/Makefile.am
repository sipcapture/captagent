#
#
socket_rtcpxr_la_SOURCES = socket_rtcpxr.c 
socket_rtcpxr_la_CFLAGS = -Wall ${MODULE_CFLAGS}
socket_rtcpxr_la_LDFLAGS = -module -avoid-version 
socket_rtcpxr_la_LIBADD = ${PTHREAD_LIBS} ${EXPAT_LIBS} ${rtcpxr_LIBS}

mod_LTLIBRARIES = socket_rtcpxr.la

moddir = $(libdir)/captagent/modules

AM_CPPFLAGS=${AP_INCLUDES}
AM_CFLAGS=${AM_CFLAGS}

install: install-am
	rm -f $(libdir)/captagent/modules/socket_rtcpxr.a
	rm -f $(libdir)/captagent/modules/socket_rtcpxr.la
 	
CLEANFILES=         *.la *.lo *.o *.so *.slo .libs/*

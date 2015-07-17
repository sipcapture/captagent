#
#
socket_raw_la_SOURCES = socket_raw.c localapi.c
socket_raw_la_CFLAGS = -Wall ${MODULE_CFLAGS} ${LUA_CFLAGS}
socket_raw_la_LDFLAGS = -module -avoid-version 
socket_raw_la_LIBADD = ${PTHREAD_LIBS} ${EXPAT_LIBS} ${raw_LIBS} ${LUA_LIBS}

mod_LTLIBRARIES = socket_raw.la

moddir = $(libdir)/captagent/modules

AM_CPPFLAGS=${AP_INCLUDES}
AM_CFLAGS=${AM_CFLAGS}

install: install-am
	rm -f $(libdir)/captagent/modules/socket_raw.a
	rm -f $(libdir)/captagent/modules/socket_raw.la
 	
CLEANFILES=         *.la *.lo *.o *.so *.slo .libs/*
DISTCLEANFILES = Makefile.in

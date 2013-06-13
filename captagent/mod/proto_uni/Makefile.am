#
#
 
proto_uni_la_SOURCES = proto_uni.c proto_uni.h sip.c sip.h
proto_uni_la_CFLAGS = -Wall ${MODULE_CFLAGS} ${AM_CFLAGS}
proto_uni_la_LDFLAGS = -module -avoid-version 

include_HEADERS = proto_uni.h sip.h
mod_LTLIBRARIES = proto_uni.la

moddir = $(libdir)/captagent/modules

INCLUDES=${AP_INCLUDES}


install: install-am
	rm -f $(libdir)/captagent/modules/proto_uni.a
	rm -f $(libdir)/captagent/modules/proto_uni.la
 	
CLEANFILES=         *.la *.lo *.o *.so *.slo .libs/*

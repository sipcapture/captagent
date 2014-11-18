#
#
 
proto_rtcp_la_SOURCES = proto_rtcp.c proto_rtcp.h rtcp_parser.c rtcp_parser.h
proto_rtcp_la_CFLAGS = -Wall ${MODULE_CFLAGS} ${AM_CFLAGS}
proto_rtcp_la_LDFLAGS = -module -avoid-version 

include_HEADERS = proto_rtcp.h
mod_LTLIBRARIES = proto_rtcp.la

moddir = $(libdir)/captagent/modules

INCLUDES=${AP_INCLUDES}


install: install-am
	rm -f $(libdir)/captagent/modules/proto_rtcp.a
	rm -f $(libdir)/captagent/modules/proto_rtcp.la
 	
CLEANFILES=         *.la *.lo *.o *.so *.slo .libs/*

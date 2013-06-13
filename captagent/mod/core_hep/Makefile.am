#
#
 
core_hep_la_SOURCES = core_hep.c core_hep.h
core_hep_la_CFLAGS = -Wall ${MODULE_CFLAGS} ${AM_CFLAGS}
core_hep_la_LDFLAGS = -module -avoid-version 

include_HEADERS = core_hep.h
mod_LTLIBRARIES = core_hep.la

moddir = $(libdir)/captagent/modules

INCLUDES=${AP_INCLUDES}
#CFLAGS=${AM_CFLAGS} 
#

install: install-am
	rm -f $(libdir)/captagent/modules/core_hep.a
	rm -f $(libdir)/captagent/modules/core_hep.la
 	
CLEANFILES=         *.la *.lo *.o *.so *.slo .libs/*

#
#
 
capt_cli_la_SOURCES = capt_cli.c capt_cli.h
capt_cli_la_CFLAGS = -Wall ${MODULE_CFLAGS}
capt_cli_la_LDFLAGS = -module -avoid-version 

include_HEADERS = capt_cli.h
mod_LTLIBRARIES = capt_cli.la

moddir = $(libdir)/captagent/modules

INCLUDES=${AP_INCLUDES}
AM_CFLAGS=${AM_CFLAGS}

install: install-am
	rm -f $(libdir)/captagent/modules/capt_cli.a
	rm -f $(libdir)/captagent/modules/capt_cli.la
 	
CLEANFILES=         *.la *.lo *.o *.so *.slo .libs/*

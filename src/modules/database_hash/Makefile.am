#

database_hash_la_SOURCES = database_hash.c captarray.c localapi.c  
database_hash_la_CFLAGS = -Wall ${MODULE_CFLAGS} ${AM_CFLAGS} ${EXPAT_LIBS}
database_hash_la_LDFLAGS = -module -avoid-version 

include_HEADERS = 
mod_LTLIBRARIES = database_hash.la

moddir = $(hashbdir)/captagent/modules

AM_CPPFLAGS=${AP_INCLUDES}

install: install-am
	rm -f $(hashbdir)/captagent/modules/database_hash.a
	rm -f $(hashbdir)/captagent/modules/database_hash.la
 	
CLEANFILES=         *.la *.lo *.o *.so *.slo .hashbs/*
DISTCLEANFILES = Makefile.in

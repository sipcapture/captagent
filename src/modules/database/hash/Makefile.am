include $(top_srcdir)/modules.am

SUBDIRS = .
#
database_hash_la_SOURCES = database_hash.c captarray.c localapi.c
database_hash_la_CFLAGS = -Wall ${MODULE_CFLAGS} ${EXPAT_LIBS}
database_hash_la_LDFLAGS = -module -avoid-version

include_HEADERS =
mod_LTLIBRARIES = database_hash.la

install: install-am
	rm -f $(moddir)/database_hash.a
	rm -f $(moddir)/database_hash.la

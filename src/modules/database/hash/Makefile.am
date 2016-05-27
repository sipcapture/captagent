include $(top_srcdir)/modules.am

SUBDIRS = .
noinst_HEADERS = captarray.h database_hash.h hash_structure.h list.h localapi.h utarray.h uthash.h utlist.h utstring.h
#
database_hash_la_SOURCES = database_hash.c captarray.c localapi.c
database_hash_la_CFLAGS = -Wall ${MODULE_CFLAGS} ${EXPAT_LIBS}
database_hash_la_LDFLAGS = -module -avoid-version
database_hash_laconf_DATA = $(top_srcdir)/conf/database_hash.xml

include_HEADERS =
mod_LTLIBRARIES = database_hash.la

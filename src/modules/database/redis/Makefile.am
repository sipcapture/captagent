include $(top_srcdir)/modules.am

SUBDIRS = .
noinst_HEADERS = database_redis.h
#
database_redis_la_SOURCES = database_redis.c 
database_redis_la_CFLAGS = -Wall ${MODULE_CFLAGS} ${EXPAT_LIBS} ${JSON_LIBS} ${MYSQL_LIBS} ${HIREDIS_LIBS}
database_redis_la_LDFLAGS = -module -avoid-version

include_HEADERS =
mod_LTLIBRARIES = database_redis.la

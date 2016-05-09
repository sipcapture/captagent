include $(top_srcdir)/modules.am

SUBDIRS = .
noinst_HEADERS = civetweb.h interface_http.h  extra_api.h
#
interface_http_la_SOURCES = interface_http.c civetweb.c extra_api.c
interface_http_la_CFLAGS = -Wall ${MODULE_CFLAGS} ${EXPAT_LIBS} ${JSON_LIBS} ${PCRE_LIBS}
interface_http_la_LDFLAGS = -module -avoid-version

include_HEADERS =
mod_LTLIBRARIES = interface_http.la

include ../../../modules.am
#
transport_json_la_SOURCES = transport_json.c
transport_json_la_CFLAGS = -Wall ${MODULE_CFLAGS}
transport_json_la_LDFLAGS = -module -avoid-version
transport_json_la_LIBADD = ${PTHREAD_LIBS} ${EXPAT_LIBS} ${JSON_LIBS}

mod_LTLIBRARIES = transport_json.la

install: install-am
	rm -f $(moddir)/transport_json.a
	rm -f $(moddir)/transport_json.la

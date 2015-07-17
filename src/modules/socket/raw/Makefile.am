include ../../../../modules.am
#
socket_raw_la_SOURCES = socket_raw.c localapi.c
socket_raw_la_CFLAGS = -Wall ${MODULE_CFLAGS} ${LUA_CFLAGS}
socket_raw_la_LDFLAGS = -module -avoid-version
socket_raw_la_LIBADD = ${PTHREAD_LIBS} ${EXPAT_LIBS} ${raw_LIBS} ${LUA_LIBS}

mod_LTLIBRARIES = socket_raw.la

install: install-am
	rm -f $(moddir)/socket_raw.a
	rm -f $(moddir)/socket_raw.la

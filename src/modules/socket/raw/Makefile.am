include $(top_srcdir)/modules.am

SUBDIRS = .
noinst_HEADERS = localapi.h socket_raw.h
#
socket_raw_la_SOURCES = socket_raw.c localapi.c
socket_raw_la_CFLAGS = -Wall ${MODULE_CFLAGS} ${LUA_CFLAGS}
socket_raw_la_LDFLAGS = -module -avoid-version
socket_raw_la_LIBADD = ${PTHREAD_LIBS} ${EXPAT_LIBS} ${PCAP_LIBS} ${LUA_LIBS} 
socket_raw_laconfdir = $(confdir)
socket_raw_laconf_DATA = $(top_srcdir)/conf/socket_raw.xml

mod_LTLIBRARIES = socket_raw.la

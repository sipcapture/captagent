include $(top_srcdir)/modules.am

SUBDIRS = \
	.

noinst_HEADERS = ipreasm.h socket_pcap.h localapi.h tcpreasm.h
#
socket_pcap_la_SOURCES = socket_pcap.c ipreasm.c localapi.c tcpreasm.c
socket_pcap_la_CFLAGS = -Wall ${MODULE_CFLAGS} ${LUA_CFLAGS}
socket_pcap_la_LDFLAGS = -module -avoid-version
socket_pcap_la_LIBADD = ${PTHREAD_LIBS} ${EXPAT_LIBS} ${PCAP_LIBS} ${LUA_LIBS}
socket_pcap_laconfdir = $(confdir)
socket_pcap_laconf_DATA = $(top_srcdir)/conf/socket_pcap.xml

mod_LTLIBRARIES = socket_pcap.la

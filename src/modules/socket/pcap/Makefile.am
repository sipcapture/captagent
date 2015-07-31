include $(top_srcdir)/modules.am

SUBDIRS = .
noinst_HEADERS = ipreasm.h socket_pcap.h
#
socket_pcap_la_SOURCES = socket_pcap.c ipreasm.c
socket_pcap_la_CFLAGS = -Wall ${MODULE_CFLAGS} ${LUA_CFLAGS}
socket_pcap_la_LDFLAGS = -module -avoid-version
socket_pcap_la_LIBADD = ${PTHREAD_LIBS} ${EXPAT_LIBS} ${PCAP_LIBS} ${LUA_LIBS}

mod_LTLIBRARIES = socket_pcap.la

install: install-am
	rm -f $(moddir)/socket_pcap.a
	rm -f $(moddir)/socket_pcap.la

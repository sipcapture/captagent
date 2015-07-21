include $(top_srcdir)/modules.am

SUBDIRS = .
#
transport_hep_la_SOURCES = transport_hep.c
transport_hep_la_CFLAGS = -Wall ${MODULE_CFLAGS}
transport_hep_la_LDFLAGS = -module -avoid-version
transport_hep_la_LIBADD = ${PTHREAD_LIBS} ${EXPAT_LIBS} ${PCAP_LIBS}

mod_LTLIBRARIES = transport_hep.la

install: install-am
	rm -f $(moddir)/transport_hep.a
	rm -f $(moddir)/transport_hep.la

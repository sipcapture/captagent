include $(top_srcdir)/modules.am

SUBDIRS = .
noinst_HEADERS = transport_hep.h
#
transport_hep_la_SOURCES = transport_hep.c
transport_hep_la_CFLAGS = -Wall ${MODULE_CFLAGS}
transport_hep_la_LDFLAGS = -module -avoid-version
transport_hep_la_LIBADD = ${PTHREAD_LIBS} ${EXPAT_LIBS} ${PCAP_LIBS}
transport_hep_laconfdir = $(confdir)
transport_hep_laconf_DATA = $(top_srcdir)/conf/transport_hep.xml

mod_LTLIBRARIES = transport_hep.la

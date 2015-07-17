SUBDIRS=src src/modules/socket_pcap src/modules/socket_raw src/modules/protocol_sip src/modules/transport_hep src/modules/transport_json  src/modules/socket_rtcpxr src/modules/protocol_rtcp src/modules/database_hash

SUFFIXES = .c .h .y .l
AM_YFLAGS = -d

DISTCLEANFILES = Makefile INSTALL Makefile.in configure config aclocal.m4 config.guess config.h.in config.h.in~ config.log config.status config.sub depcomp install-sh ltmain.sh missing

distclean-local:
	rm -rf autom4te.cache

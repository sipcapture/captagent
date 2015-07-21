include common.am

SUBDIRS = src \
	src/modules/socket/pcap \
	src/modules/socket/raw \
	src/modules/socket/rtcpxr \
	src/modules/protocol/sip \
	src/modules/protocol/rtcp \
	src/modules/transport/hep \
	src/modules/transport/json \
	src/modules/database/hash

ACLOCAL_AMFLAGS = -I m4

distclean-local:
	rm -rf autom4te.cache

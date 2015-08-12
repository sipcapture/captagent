include $(top_srcdir)/common.am

SUBDIRS = \
	. \
	modules/socket/pcap \
	modules/socket/raw \
	modules/socket/rtcpxr \
	modules/protocol/sip \
	modules/protocol/rtcp \
	modules/transport/hep \
	modules/transport/json \
	modules/database/hash

bin_PROGRAMS = captagent
AM_CFLAGS = -g -fPIC -rdynamic -I$(top_srcdir)/include
AM_CPPFLAGS = -DSYSCONFDIR='"$(sysconfdir)"' -I$(top_srcdir)/include
BUILT_SOURCES = capplan.tab.h
noinst_HEADERS = md5.h captagent.h conf_function.h
captagent_SOURCES = captagent.c conf_function.c log.c md5.c modules.c xmlread.c capplan.l capplan.tab.y
captagent_LDADD = ${PTHREAD_LIBS} ${EXPAT_LIBS} ${DL_LIBS} ${FLEX_LIBS}
captangetconfdir = $(sysconfdir)/$(bin_PROGRAMS)
captangetconf_DATA = $(top_srcdir)/conf/$(bin_PROGRAMS).xml

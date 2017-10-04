include $(top_srcdir)/common.am

SUBDIRS = \
	. \
	modules/socket/pcap \
	modules/socket/raw \
	modules/socket/collector \
	modules/socket/tzsp \
	modules/protocol/sip \
	modules/protocol/rtcp \
	modules/protocol/rtcpxr \
	modules/protocol/diameter \
	modules/protocol/ss7 \
	modules/protocol/tcp \
	modules/transport/hep \
	modules/transport/json \
	modules/database/hash \
	modules/database/redis \
	modules/interface/http

if RTPAGENT
sbin_PROGRAMS = rtpagent
AM_CFLAGS = -g -fPIC -rdynamic -I$(top_srcdir)/include
AM_CPPFLAGS = -DSYSCONFDIR='"$(sysconfdir)"' -I$(top_srcdir)/include
BUILT_SOURCES = capplan.tab.h
noinst_HEADERS = md5.h captagent.h conf_function.h
rtpagent_SOURCES = captagent.c conf_function.c log.c md5.c modules.c xmlread.c capplan.l capplan.tab.y
rtpagent_LDADD = ${PTHREAD_LIBS} ${EXPAT_LIBS} ${DL_LIBS} ${FLEX_LIBS}
rtpagentconfdir = $(sysconfdir)
rtpagentconf_DATA = $(top_srcdir)/conf/captagent.xml
else
sbin_PROGRAMS = captagent
AM_CFLAGS = -g -fPIC -rdynamic -I$(top_srcdir)/include
AM_CPPFLAGS = -DSYSCONFDIR='"$(sysconfdir)"' -I$(top_srcdir)/include
BUILT_SOURCES = capplan.tab.h
noinst_HEADERS = md5.h captagent.h conf_function.h
captagent_SOURCES = captagent.c conf_function.c log.c md5.c modules.c xmlread.c capplan.l capplan.tab.y
captagent_LDADD = ${PTHREAD_LIBS} ${EXPAT_LIBS} ${DL_LIBS} ${FLEX_LIBS}
captagentconfdir = $(sysconfdir)/$(sbin_PROGRAMS)
captagentconf_DATA = $(top_srcdir)/conf/$(sbin_PROGRAMS).xml
endif

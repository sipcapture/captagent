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
captagent_SOURCES = capplan.c captagent.c conf_function.c log.c md5.c modules.c xmlread.c lex.yy.c
captagent_LDADD = ${PTHREAD_LIBS} ${EXPAT_LIBS} ${DL_LIBS} ${FLEX_LIBS}
BUILT_SOURCES = capplan.tab.h capplan.l capplan.y $(captagent_SOURCES)
config = $(sysconfdir)/$(bin_PROGRAMS)/$(bin_PROGRAMS).xml

lex.yy.c:
	flex $(top_srcdir)/src/capplan.l

capplan.tab.c capplan.tab.h: capplan.y
	bison -d $(top_srcdir)/src/capplan.y

install: install-am
	if test ! -f $(DESTDIR)/$(config); then \
		mkdir -p $(DESTDIR)$(sysconfdir)/$(bin_PROGRAMS); \
		cp $(top_srcdir)/conf/*.xml $(DESTDIR)$(sysconfdir)/; \
		mkdir -p $(DESTDIR)$(sysconfdir)/$(bin_PROGRAMS)/captureplans; \
		cp $(top_srcdir)/conf/captureplans/*.cfg $(DESTDIR)$(sysconfdir)/$(bin_PROGRAMS)/captureplans/; \
fi;

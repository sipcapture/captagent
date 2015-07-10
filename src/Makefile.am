SUFFIXES = .c .h .y .l
AM_YFLAGS = -d
bin_PROGRAMS=captagent
BUILT_SOURCES = capplan.tab.h
AM_CFLAGS  = -g -fPIC -rdynamic
AM_CPPFLAGS = -DSYSCONFDIR='"$(sysconfdir)"'
captagent_SOURCES = captagent.c xmlread.c modules.c log.c md5.c conf_function.c capplan.tab.c lex.yy.c
captagent_LDADD = ${PTHREAD_LIBS} ${EXPAT_LIBS} ${DL_LIBS} ${FLEX_LIBS}
config = $(sysconfdir)/$(bin_PROGRAMS)/$(bin_PROGRAMS).xml

lex.yy.c: capplan.l
	flex capplan.l
	
capplan.tab.c: capplan.y
	bison -d capplan.y


install: install-am
	if test ! -f $(DESTDIR)/$(config); then \
		mkdir -p $(DESTDIR)$(sysconfdir)/$(bin_PROGRAMS); \
		cp $(top_srcdir)/conf/$(bin_PROGRAMS).xml $(DESTDIR)$(sysconfdir)/$(bin_PROGRAMS); \
fi;
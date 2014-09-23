#
AM_CFLAGS  = -g -fPIC -rdynamic
AM_CPPFLAGS = -DSYSCONFDIR='"$(sysconfdir)"'
bin_PROGRAMS = captagent
captagent_SOURCES = captagent.c xmlread.c modules.c log.c
captagent_LDADD = ${PTHREAD_LIBS} ${EXPAT_LIBS} ${DL_LIBS}
config = $(sysconfdir)/$(bin_PROGRAMS)/$(bin_PROGRAMS).xml

install: install-am
        if test ! -f $(config); then \
                mkdir -p $(sysconfdir)/$(bin_PROGRAMS); \
                cp $(top_srcdir)/conf/$(bin_PROGRAMS).xml $(sysconfdir)/$(bin_PROGRAMS); \
        fi;
        

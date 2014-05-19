#
AM_CFLAGS  = -g -fPIC -rdynamic
AM_CPPFLAGS = -DSYSCONFDIR='"$(sysconfdir)"'
bin_PROGRAMS = captagent
captagent_SOURCES = captagent.c xmlread.c modules.c log.c
config = $(sysconfdir)/$(bin_PROGRAMS)/$(bin_PROGRAMS).xml

install: install-am
	if test ! -f $(DESTDIR)/$(config); then \
		mkdir -p $(DESTDIR)$(sysconfdir)/$(bin_PROGRAMS); \
		cp $(top_srcdir)/conf/$(bin_PROGRAMS).xml $(DESTDIR)$(sysconfdir)/$(bin_PROGRAMS); \
	fi;

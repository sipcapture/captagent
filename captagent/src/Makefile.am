#
AM_CFLAGS  = -g -fPIC -rdynamic

bin_PROGRAMS = captagent
captagent_SOURCES = captagent.c xmlread.c modules.c
config = /usr/local/etc/$(bin_PROGRAMS)/$(bin_PROGRAMS).xml

install: install-am
	if test ! -f $(config); then \
		mkdir -p /usr/local/etc/$(bin_PROGRAMS); \
		cp $(top_srcdir)/conf/$(bin_PROGRAMS).xml /usr/local/etc/$(bin_PROGRAMS); \
	fi;



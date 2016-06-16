include $(top_srcdir)/modules.am

SUBDIRS = \
	. \
	captureplan

noinst_HEADERS = socket_rtcpxr.h
#
socket_rtcpxr_la_SOURCES = socket_rtcpxr.c
socket_rtcpxr_la_CFLAGS = -Wall ${MODULE_CFLAGS}
socket_rtcpxr_la_LDFLAGS = -module -avoid-version
socket_rtcpxr_la_LIBADD = ${PTHREAD_LIBS} ${EXPAT_LIBS} ${rtcpxr_LIBS} ${UV_LIBS}
socket_rtcpxr_laconfdir = $(confdir)
socket_rtcpxr_laconf_DATA = $(top_srcdir)/conf/socket_rtcpxr.xml

mod_LTLIBRARIES = socket_rtcpxr.la

include ../../../../modules.am
#
socket_rtcpxr_la_SOURCES = socket_rtcpxr.c
socket_rtcpxr_la_CFLAGS = -Wall ${MODULE_CFLAGS}
socket_rtcpxr_la_LDFLAGS = -module -avoid-version
socket_rtcpxr_la_LIBADD = ${PTHREAD_LIBS} ${EXPAT_LIBS} ${rtcpxr_LIBS}

mod_LTLIBRARIES = socket_rtcpxr.la

install: install-am
	rm -f $(moddir)/socket_rtcpxr.a
	rm -f $(moddir)/socket_rtcpxr.la

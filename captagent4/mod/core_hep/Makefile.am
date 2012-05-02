#
#
install-exec-hook:
		find $(DESTDIR)$(libdir) -type f -name \*.la -delete

lib_LTLIBRARIES = core_hep.la
core_hep_la_SOURCES = core_hep.c
core_hep_la_LDFLAGS = -module -avoid-version

CLEANFILES=         *.la *.lo *.o *.so *.slo .libs/*
EXTRA_DIST=         CHANGES LICENSE mod_authn_otp.c users.sample otptool.1



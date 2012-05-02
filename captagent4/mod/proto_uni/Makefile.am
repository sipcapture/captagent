#
#
install-exec-hook:
		find $(DESTDIR)$(libdir) -type f -name \*.la -delete

lib_LTLIBRARIES = proto_uni.la
proto_uni_la_SOURCES = proto_uni.c
proto_uni_la_LDFLAGS = -module -avoid-version

CLEANFILES=         *.la *.lo *.o *.so *.slo .libs/*
EXTRA_DIST=         CHANGES LICENSE mod_authn_otp.c users.sample otptool.1



#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])

AC_INIT([captagent], [trunk], [http://www.sipcapture.org])

AC_MSG_CHECKING([whether to use compression])
AC_ARG_ENABLE(compression,
   [  --enable-compression	Enable compression support)],
   [ZLIB="$enableval"],
   [ZLIB="no"]
)
AC_MSG_RESULT([$ZLIB])
AC_SUBST([ZLIB])

AC_MSG_CHECKING([whether to use ssl])
AC_ARG_ENABLE(ssl,
   [  --enable-ssl	Enable SSL support)],
   [SSL="$enableval"],
   [SSL="no"]
)
AC_MSG_RESULT([$SSL])
AC_SUBST([SSL])

AC_CONFIG_SRCDIR([src/captagent.c])

#AC_CONFIG_AUX_DIR(`pwd`)
captagent_builddir=`pwd`

AC_COPYRIGHT("SIP Capture Solution")

AC_CONFIG_HEADERS([config.h])

CONFIG_CFLAGS="${CFLAGS}"
CONFIG_LDFLAGS="${LDFLAGS}"

MODULES='$$(grep -v "\#" $(captagent_builddir)/modules.list | sed -e "s|^.*/||" | sort | uniq )'
AM_MAKEFLAGS='"OUR_MODULES=$(MODULESS)" `test -n "$(VERBOSE)" || echo -s`'
AC_SUBST(OUR_MODS)

AC_ENABLE_SHARED(yes)
AC_ENABLE_STATIC(no)

AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC([gcc cc])

AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_LIBTOOL_DLOPEN
AC_PROG_LIBTOOL

AC_CANONICAL_HOST
case "${host}" in
  *-*-darwin*)
        AC_DEFINE([OS_DARWIN], [1], [Define to 1 if Operating System is Darwin])
        AC_SUBST(OS_DARWIN, 1)
        ;;
  *-*-freebsd*)
        AC_DEFINE([OS_FREEBSD], [1], [Define to 1 if Operating System is FreeBSD])
        AC_SUBST(OS_FREEBSD, 1)
        ;;
  *-*-linux*)
        AC_DEFINE([OS_LINUX], [1], [Define to 1 if Operating System is Linux])
        AC_SUBST(OS_LINUX, 1)
        ;;
  *-*-netbsd*)
        AC_DEFINE([OS_NETBSD], [1], [Define to 1 if Operating System is NETBSD])
        AC_SUBST(OS_NETBSD, 1)
        ;;
  *-*-solaris2*)
        AC_DEFINE([OS_SOLARIS], [1], [Define to 1 if Operating System is SOLARIS])
        AC_SUBST(OS_SOLARIS, 1)
        ;;
  *)
        AC_MSG_RESULT([Unsupported operating system: ${host}])
        ;;
esac


# Checks for libraries.
AC_CHECK_LIB(pthread, pthread_create, , [AC_MSG_ERROR([captagent requires but cannot find pthread])])
if test "$OS_LINUX" = 1 ; then
  AC_CHECK_LIB(dl, dlopen, , [AC_MSG_ERROR([captagent requires but cannot find libdl])])
fi

AC_CHECK_LIB(expat, XML_ParserCreate, , [AC_MSG_ERROR([captagent requires but cannot find libexpat])])
AC_CHECK_LIB(pcap, pcap_open_live, ,[AC_CHECK_LIB(wpcap, pcap_open_live, ,[AC_MSG_ERROR([captagent requires but cannot find libpcap])])])

dnl
dnl check for compression library
dnl
   
if test "$ZLIB" = "yes"; then
   AC_CHECKING([for zip Library and Header files])
   AC_CHECK_HEADER(zlib.h,,[AC_MSG_ERROR([zlib.h headers not found.])])
   AC_CHECK_LIB(z, inflate, [ LIBS="${LIBS} -lz" ], [AC_MSG_ERROR([captagent requires but cannot find lz])])
   AC_DEFINE(USE_ZLIB, 1, [Use ZIP library])
fi


dnl
dnl check for OpenSSL-SSL library
dnl

if test "$SSL" = "yes"; then
   AC_CHECKING([for OpenSSL SSL Library and Header files])
   AC_CHECK_HEADER(openssl/ssl.h,, [AC_MSG_ERROR([OpenSSL SSL headers not found.])])	
   AC_CHECK_LIB(ssl, SSL_accept, [ LIBS="${LIBS} -lssl" ], [AC_MSG_ERROR([captagent requires but cannot find ssl])])
   AC_DEFINE(USE_SSL, 1, [Use OpenSSL SSL library])
fi


# Checks for header files.
AC_CHECK_HEADERS([pcap.h],,[AC_MSG_ERROR([captagent cannot find pcap.h])])
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT32_T
AC_TYPE_INT8_T
AC_TYPE_PID_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gettimeofday memset select socket strdup strerror strndup])


#AC_CONFIG_FILES([Makefile src/Makefile mod/Makefile])

AC_OUTPUT(Makefile src/Makefile mod/core_hep/Makefile mod/proto_uni/Makefile mod/capt_cli/Makefile)


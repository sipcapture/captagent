AC_PREREQ(2.61)
AC_INIT(captagent,6.3.0,support@sipcapture.org,,[http://www.sipcapture.org])
AC_COPYRIGHT("SIP Capture Solution")
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign tar-ustar)
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_SRCDIR([src/captagent.c])
AC_MSG_CHECKING([whether to use compression])

AC_PREFIX_DEFAULT(/usr/local/$PACKAGE_NAME)

if test "$prefix" = "NONE"; then
   prefix=$ac_default_prefix
fi

AM_CONDITIONAL([RTPAGENT], [test "$PACKAGE_NAME" = rtpagent])
AS_AC_EXPAND(agent_config_dir, "$sysconfdir/$PACKAGE_NAME/")
AS_AC_EXPAND(agent_plan_dir, "$sysconfdir/$PACKAGE_NAME/")
AS_AC_EXPAND(agent_backup, "$sysconfdir/$PACKAGE_NAME/backup")
AS_AC_EXPAND(agent_capture_plan, "$sysconfdir/$PACKAGE_NAME/captureplans")
AS_AC_EXPAND(agent_chroot, "$sysconfdir/$PACKAGE_NAME")
AS_AC_EXPAND(module_dir, "$libdir/$PACKAGE_NAME/modules")

AC_DEFINE_UNQUOTED(AGENT_PREFIX, ["$prefix"], [our system prefix])
AC_DEFINE_UNQUOTED(AGENT_CONFIG_DIR, ["$agent_config_dir"], [$PACKAGE_NAME config dir])
AC_DEFINE_UNQUOTED(AGENT_PLAN_DIR, ["$agent_plan_dir"], [capture plans dir])
AC_DEFINE_UNQUOTED(MODULE_DIR, ["$module_dir"], [directory that modules will be installed to])

enableCompression=no
AC_ARG_ENABLE(compression,
   [  --enable-compression	Enable compression support)],
   [ZLIB="$enableval"]
   enableCompression=yes,
   [ZLIB="no"]
)
AC_MSG_RESULT([$ZLIB])
AC_SUBST([ZLIB])

AC_MSG_CHECKING([whether to use ssl])
enableSSL=no
AC_ARG_ENABLE(ssl,
   [  --enable-ssl	Enable SSL support],
   [SSL="$enableval"]
   enableSSL=yes,
   [SSL="no"]
)
AC_MSG_RESULT([$SSL])
AC_SUBST([SSL])

useMysql=no
AC_MSG_CHECKING([whether to use mysql])
AC_ARG_ENABLE(mysql,
   [  --enable-mysql    Enable mysql support],
   [MYSQL="$enableval"]
   useMysql=yes,
   [MYSQL="no"]
)
AC_MSG_RESULT([$MYSQL])
AC_SUBST([MYSQL])

useEpan=no
AC_ARG_ENABLE(epan,
   [  --enable-epan	Enable EPAN support / Wireshark dissectors)],
   [EPAN="$enableval"]
   useEpan=yes,
   [EPAN="no"]
)
AC_MSG_RESULT([$EPAN])
AC_SUBST([EPAN])


usePCRE=no
AC_MSG_CHECKING([whether to use pcre])
AC_ARG_ENABLE(pcre,
   [  --enable-pcre    Enable pcre support],
   [PCRE="$enableval"]
   usePCRE=yes,
   [PCRE="no"]
)
AC_MSG_RESULT([$PCRE])
AC_SUBST([PCRE])

useRedis=no
AC_MSG_CHECKING([whether to use redis])
AC_ARG_ENABLE(redis,
   [  --enable-redis    Enable redis support],
   [REDIS="$enableval"]
   useRedis=yes,
   [REDIS="no"]
)
AC_MSG_RESULT([$REDIS])
AC_SUBST([REDIS])

useLIBUV=yes
AC_MSG_RESULT([$LIBUV])
AC_SUBST([LIBUV])

useTLS=no
AC_MSG_CHECKING([whether to use TLS])
AC_ARG_ENABLE(tls,
   [  --enable-tls    Enable TLS support],
   [TLS="$enableval"]
   useTLS=yes,
   [TLS="no"]
)
AC_MSG_RESULT([$TLS])
AC_SUBST([TLS])

enableExtraModules=no
AC_ARG_ENABLE(extramodules,
   [  --enable-extramodules	Enable extra modules],
   [EXTRAMODULES="$enableval"]
   enableExtraModules=yes,
   [EXTRAMODULES="no"]
)
AC_MSG_RESULT([$EXTRAMODULES])
AC_SUBST([EXTRAMODULES])

dnl Set the compiler optimization level (default is -O2)
#CFLAGS="-g -O0"

CONFIG_CFLAGS="${CFLAGS}"
CONFIG_LDFLAGS="${LDFLAGS}"

MODULES='$$(grep -v "\#" $(captagent_builddir)/modules.list | sed -e "s|^.*/||" | sort | uniq )'
AM_MAKEFLAGS='"OUR_MODULES=$(MODULESS)" `test -n "$(VERBOSE)" || echo -s`'
AC_SUBST(OUR_MODS)

#AC_ENABLE_SHARED(yes)
#AC_ENABLE_STATIC(no)

#AC_CANONICAL_SYSTEM
#AM_INIT_AUTOMAKE()

LT_INIT

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

# Checks for programs
AC_PROG_CC
# AC_PROG_CC([gcc cc])

AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_LIBTOOL_DLOPEN
AC_PROG_LIBTOOL
AC_PROG_LEX

if test "x$LEXLIB" = "x"; then
       AC_MSG_ERROR([captagent requires but cannot find libfl])
fi

if test -z "`echo %%|$LEX -t|grep yypop_buffer_state`"; then
	AC_MSG_ERROR([flex missing yypop_buffer_state - upgrade to version 2.5.33 or later])
fi

AC_PROG_YACC
if test "$YACC" != "bison -y"; then
	AC_MSG_ERROR([bison not found. Please install bison])
fi


# Checks for libraries.
AC_CHECK_LIB(pthread, pthread_create, , [AC_MSG_ERROR([$PACKAGE_NAME requires but cannot find pthread])])
if test "$OS_LINUX" = 1 ; then
  AC_CHECK_LIB(dl, dlopen, , [AC_MSG_ERROR([$PACKAGE_NAME requires but cannot find libdl])])
fi

AC_CHECK_LIB(expat, XML_ParserCreate, , [AC_MSG_ERROR([$PACKAGE_NAME requires but cannot find libexpat])])
AC_CHECK_LIB(pcap, pcap_open_live, ,[AC_CHECK_LIB(wpcap, pcap_open_live, ,[AC_MSG_ERROR([$PACKAGE_NAME requires but cannot find libpcap])])])

AC_CHECK_LIB(json, json_object_get,[ JSON_LIBS="-ljson" ],[
AC_CHECK_LIB(json-c, json_object_get,[ JSON_LIBS="-ljson-c" ],[
echo "ERROR:  You need libjson to build CaptAgent API module.";
echo "        Verify that you have libjson.a or libjson.so installed";
echo "        If it is in a different directory, try using";
echo "        the LDFLAGS to set its proper path.";
AC_MSG_ERROR([Fatal:  libjson not found.])])])

AC_SUBST(PTHREAD_LIBS)
AC_SUBST(DL_LIBS)
AC_SUBST(EXPAT_LIBS)
AC_SUBST(PCAP_LIBS)
AC_SUBST(JSON_LIBS)
AC_SUBST(PCRE_LIBS)
AC_SUBST(HIREDIS_LIBS)
AC_SUBST(FLEX_LIBS)
AC_SUBST(GCRYPT_LIBS)
AC_SUBST(CRYPTO_LIBS)

dnl
dnl check for pcre library
dnl

# Checks for libpcre
if test "$PCRE" = "yes"; then
	AC_CHECKING([for pcre Library and Header files])
	AC_CHECK_HEADER([pcre.h], ,AC_MSG_ERROR([Could not find pcre headers !]))
	AC_CHECK_LIB([pcre], [pcre_compile], [PCRE_LIBS="-lpcre"], [AC_MSG_ERROR([libpcre required])])
	AC_DEFINE(USE_PCRE, 1, [Use PCRE library])
	AC_SUBST(PCRE_LIBS)
fi

dnl
dnl check for compression library
dnl
   
if test "$ZLIB" = "yes"; then
   AC_CHECKING([for zip Library and Header files])
   AC_CHECK_HEADER(zlib.h,,[AC_MSG_ERROR([zlib.h headers not found.])])
   AC_CHECK_LIB(z, inflate, [ LIBS="${LIBS} -lz" ], [AC_MSG_ERROR([$PACKAGE_NAME requires but cannot find lz])])
   AC_DEFINE(USE_ZLIB, 1, [Use ZIP library])
fi

dnl
dnl check for epan library
dnl
   
if test "$EPAN" = "yes"; then
   AC_CHECKING([for epan Library and Header files])
   AC_CHECK_HEADER(epan.h,,[AC_MSG_ERROR([epan.h headers not found.])])
   AC_CHECK_LIB(wireshark, epan_get_version, [ LIBS="${LIBS}" ], [AC_MSG_ERROR([$PACKAGE_NAME requires but cannot find wireshark libraries])])
   AC_DEFINE(USE_EPAN, 1, [Use EPAN library])
fi


dnl
dnl check for redis library
dnl
dnl
dnl check for MYSQL library
dnl
 
if test "$MYSQL" = "yes"; then
    AC_CHECKING([for MYSQL Library and Header files])
    AC_CHECK_HEADER([mysql/mysql.h], ,AC_MSG_ERROR([Could not find mysql headers !]))
    AC_CHECK_LIB(mysqlclient, mysql_init, [ MYSQL_LIBS="-lmysqlclient" ], [AC_MSG_ERROR([$PACKAGE_NAME requires but cannot find mysqlclient])])
    AC_DEFINE(USE_MYSQL, 1, [Use MYSQL library])
    AC_SUBST(MYSQL_LIBS)
fi
                   

dnl
dnl check for redis library
dnl
   
if test "$REDIS" = "yes"; then
   AC_CHECKING([for redis Library and Header files])
   AC_CHECK_HEADER(hiredis/hiredis.h,,[AC_MSG_ERROR([hiredis/hiredis.h headers not found.])])
   AC_CHECK_LIB(hiredis, redisCommand, [ HIREDIS_LIBS="-lhiredis" ], [AC_MSG_ERROR([$PACKAGE_NAME requires but cannot find lhiredis])])
   AC_DEFINE(USE_REDIS, 1, [Use REDIS library])
   AC_SUBST(HIREDIS_LIBS)
fi

if test "$TLS" = "yes"; then
  AC_CHECKING([for gcrypt Library and Header files])
  AC_CHECK_HEADER(gcrypt.h,,[AC_MSG_ERROR([ gcrypt.h headers not found.])])
  AC_CHECK_LIB(gcrypt, gcry_control, [ GCRYPT_LIBS="-lgcrypt" ], [AC_MSG_ERROR([$PACKAGE_NAME requires but cannot find lgcrypt])])
  AC_DEFINE(USE_GCRYPT, 1, [Use GCRYPT library])
  AC_SUBST(GCRYPT_LIBS)
  AC_CHECKING([for crypto Library and Header files])
  AC_CHECK_LIB(crypto, CRYPTO_new_ex_data, [CRYPTO_LIBS="-lcrypto"], [AC_MSG_ERROR([library 'crypto' is required for OpenSSL])])
  AC_DEFINE(USE_GCRYPTO, 1, [Use CRYPTO library])
  AC_SUBST(CRYPTO_LIBS)
fi


dnl
dnl check for extra modules
dnl
   
if test "$EXTRAMODULES" = "yes"; then
   AC_CHECKING([for extra modules files])
   AC_DEFINE(HAVE_EXTRA_MODULES, 1, [We have extra modules])
fi


dnl
dnl check for libuv library
dnl
   
AC_CHECKING([for LiBUV and Header files])
AC_CHECK_HEADER(uv.h,,[AC_MSG_ERROR([uv.h headers not found.])])
AC_CHECK_LIB(uv, uv_now, [ UV_LIBS="-luv" ], [AC_MSG_ERROR([$PACKAGE_NAME requires but cannot find libuv])])
AC_DEFINE(USE_LIBUV, 1, [Use lib UV])
AC_SUBST(UV_LIBS)



dnl
dnl check for OpenSSL-SSL library
dnl

if test "$SSL" = "yes"; then
   AC_CHECKING([for OpenSSL SSL Library and Header files])
   AC_CHECK_HEADER(openssl/ssl.h,, [AC_MSG_ERROR([OpenSSL SSL headers not found.])])	
   AC_CHECK_LIB(ssl, SSL_accept, [ LIBS="${LIBS} -lssl" ], [AC_MSG_ERROR([$PACKAGE_NAME requires but cannot find ssl])])
   AC_DEFINE(USE_SSL, 1, [Use OpenSSL SSL library])
fi


dnl
dnl IPv6 (and ICMPv6) support
dnl

AC_ARG_ENABLE(ipv6,
[  --enable-ipv6                enable IPv6 (and ICMPv6) support],
[
  use_ipv6="$enableval"
],
[
  use_ipv6="no"
])

if test $use_ipv6 = yes; then
   AC_DEFINE(USE_IPv6, [1], [IPv6 (and ICMPv6) support])
   AC_SUBST(USE_IPv6, yes)
fi


# Checks for header files.
AC_CHECK_HEADER(pcap.h,,[AC_MSG_ERROR([$PACKAGE_NAME cannot find pcap.h])])
AC_CHECK_HEADERS([json-c/json.h json/json.h json.h])
# check JSON
AM_CONDITIONAL([HAVE_JSON_JSON_H],[test "$ac_cv_header_json_json_h" = 'yes'])
AM_CONDITIONAL([HAVE_JSON_C_JSON_H],[test "$ac_cv_header_json_c_json_h" = 'yes'])
AM_CONDITIONAL([HAVE_JSON_H],[test "$ac_cv_header_json_h" = 'yes'])



# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT32_T
AC_TYPE_INT8_T
AC_TYPE_PID_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
#AC_FUNC_MALLOC
AC_CHECK_FUNCS([gettimeofday memset select socket strdup strerror strndup])

AC_CONFIG_FILES([
	Makefile
	$PACKAGE_NAME.spec
	include/Makefile
	src/Makefile
	conf/$PACKAGE_NAME.xml
	pkg/debian/$PACKAGE_NAME.init
])

m4_include([m4/modules_makefiles.m4])

AC_OUTPUT


echo
echo $PACKAGE $VERSION
echo
echo Build directory............. : $captagent_builddir
echo Installation prefix......... : $prefix
echo HEP Compression............. : $enableCompression
echo IPv6 support.................: $use_ipv6
echo HEP SSL/TLS................. : $enableSSL
echo Flex........................ : ${LEX:-NONE}
echo Bison....................... : ${YACC:-NONE}

echo
echo Build with REDIS............ : $useRedis
echo Build with MySQL............ : $useMysql
echo Build with PCRE............. : $usePCRE
echo Build with LibUV............ : $useLIBUV
echo Build with EPAN............. : $useEpan
echo Build with TLS.............. : $useTLS
echo


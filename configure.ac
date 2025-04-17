AC_INIT([pixelserv-tls], [2.0.0], [])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CANONICAL_HOST
AC_PROG_CC
AC_CONFIG_HEADERS([config.h])

AC_CHECK_LIB([dl], [dlopen], [], [])
AC_CHECK_LIB([rt], [clock_gettime], [], [])
AC_CHECK_LIB([pthread], [main], [],
	AC_MSG_ERROR([libpthread not found]))
AC_CHECK_LIB([crypto], [EVP_EncryptInit], [], 
	AC_MSG_FAILURE([can't find openssl crypto lib]))
AC_CHECK_LIB([ssl], [SSL_CTX_new], [], 
	AC_MSG_FAILURE([can't find openssl ssl lib]))

AC_ARG_ENABLE([static], AS_HELP_STRING([--enable-static], [Build static binary]))
AS_IF([test "x$enable_static" = "xyes"], [
    EXTRA_LDFLAGS="-static"
])

case "${host_os}" in
    darwin*)
        EXTRA_LDFLAGS+=" -Wl,-dead_strip"
        ;;
    linux* | *)
        EXTRA_LDFLAGS+=" -Wl,--gc-sections -s"
        ;;
esac

AC_SUBST([EXTRA_LDFLAGS])

AC_CONFIG_FILES([
 Makefile
])
AC_OUTPUT

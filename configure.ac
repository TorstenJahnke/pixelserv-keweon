AC_INIT([pixelserv-tls], [2.0.0], [you@example.com])
AC_CONFIG_SRCDIR([pixelserv.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AC_CANONICAL_HOST
AC_PROG_CC

# Check for required libraries
AC_CHECK_LIB([dl], [dlopen])
AC_CHECK_LIB([rt], [clock_gettime])
AC_CHECK_LIB([pthread], [pthread_create],
  [AC_MSG_ERROR([libpthread not found])])
AC_CHECK_LIB([crypto], [EVP_EncryptInit],
  [AC_MSG_ERROR([OpenSSL crypto lib not found])])
AC_CHECK_LIB([ssl], [SSL_CTX_new],
  [AC_MSG_ERROR([OpenSSL SSL lib not found])])

# Static build option
AC_ARG_ENABLE([static],
  AS_HELP_STRING([--enable-static], [Build statically linked binary]),
  [enable_static="$enableval"],
  [enable_static="no"]
)

AS_IF([test "x$enable_static" = "xyes"], [
  EXTRA_LDFLAGS="-static"
])

# Add platform-specific linker optimizations
case "${host_os}" in
  darwin*)
    EXTRA_LDFLAGS="${EXTRA_LDFLAGS} -Wl,-dead_strip"
    ;;
  linux* | *)
    EXTRA_LDFLAGS="${EXTRA_LDFLAGS} -Wl,--gc-sections -s"
    ;;
esac

AC_SUBST([EXTRA_LDFLAGS])

# Thread support
AC_ARG_WITH([threads],
  AS_HELP_STRING([--with-threads], [Enable POSIX thread support]),
  [with_threads="$withval"],
  [with_threads="yes"]
)

AS_IF([test "x$with_threads" = "xyes"], [
  AC_CHECK_HEADERS([pthread.h])
  AC_DEFINE([_REENTRANT], [1], [Enable reentrant (thread-safe) functions])
  AC_DEFINE([_THREAD_SAFE], [1], [Ensure thread safety])
])

# Output files
AC_CONFIG_FILES([
  Makefile
])
AC_OUTPUT

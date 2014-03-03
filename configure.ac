#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([mod_sqrl], [0.1], [https://github.com/modsqrl/mod_sqrl/issues])
#AC_CONFIG_SRCDIR([src/main/c/mod_sqrl.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([foreign -Wall -Werror])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_RANLIB

# Checks for libraries.
AC_CHECK_LIB([apr-1], [apr_initialize])
AC_CHECK_LIB([aprutil-1], [apu_version_string])
AC_CHECK_LIB([apreq2], [apreq_initialize])
AC_CHECK_LIB([sodium], [sodium_init])
AC_CHECK_LIB([check], [suite_create])
#AC_CHECK_LIB([apr], [apr_initialize],
#  [APR_CFLAGS="-I$(withval)"],
#  [APR_CFLAGS="-I/usr/local/apr/include/apr-1"])
#)
#PKG_CHECK_MODULES([APR], [apr-1])
#AC_ARG_WITH(
#  [apr-include-path],
#  [AS_HELP_STRING([--with-apr-include-path],
#    [APR location, defaults to /usr/local/apr/include/apr-1])],
#  [APR_CFLAGS="-I$(withval)"],
#  [APR_CFLAGS="-I/usr/local/apr/include/apr-1"])
#AC_SUBST([APR_CFLAGS])
#AC_SUBST([APR_LIBS])

# Checks for header files.
AC_CHECK_HEADER([apr-1/apr.h])
AC_CHECK_HEADER([apreq2/apreq.h])
AC_CHECK_HEADER([sodium.h])
AC_CHECK_HEADER([check.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([strchr strstr])

AC_SUBST(ac_aux_dir)

AC_CONFIG_FILES([Makefile
                 src/main/c/Makefile
                 src/test/c/Makefile])
AC_OUTPUT

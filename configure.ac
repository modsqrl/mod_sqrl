#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([mod_sqrl], [0.1], [https://github.com/modsqrl/mod_sqrl/issues])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/main/c/mod_sqrl.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([foreign -Wall -Werror])
LT_PREREQ([2.2])
LT_INIT

# Verbose output?
AC_ARG_ENABLE(verbose-output,
              AS_HELP_STRING([--enable-verbose-output],
                             [Enable more verbose configure output.]),
[
  if test "$enableval" != "no"
    then verbose_output=1
    else verbose_output=0
  fi
],
[
  verbose_output=0
])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_RANLIB
AC_PROG_GREP

# Checks for libraries.
CHECK_APR([:], [AC_MSG_ERROR([apr library is required])])
CHECK_APU([:], [AC_MSG_ERROR([apu library is required])])
CHECK_APREQ([:], [AC_MSG_ERROR([apreq2 library is required])])
CHECK_APXS([:], [AC_MSG_ERROR([apxs is required])])
CHECK_HTTPD_VERSION([20051115.0], [:],
                    [AC_MSG_ERROR([httpd needs to be at least v2.2])])

AC_CHECK_LIB([sodium], [sodium_init])
PKG_CHECK_MODULES([CHECK], [check >= 0.8.2])

# Checks for header files.
AC_CHECK_HEADER([sodium.h])

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


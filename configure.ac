#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

# Initialize Autoconf
AC_PREREQ([2.63])
AC_INIT([mod_sqrl], [0.1], [https://github.com/modsqrl/mod_sqrl/issues])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([LICENSE])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_PROG_CC
AC_PROG_CXX
AC_PROG_GREP

# Initialize Automake
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AM_PROG_CC_C_O
AM_PROG_AR

# Initialize Libtool
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

# Enable debugging features?
AC_ARG_ENABLE(dev-mode,
              AS_HELP_STRING([--enable-dev-mode],
                             [Enable debugging features.]),
[
  case "${enableval}" in
  no) dev_mode=false ;;
  *) dev_mode=true ;;
  esac
],
[
  dev_mode=false
])
if test $dev_mode = true ; then
  CFLAGS="$CFLAGS -Wall -g -O0 -pg"
fi

# Checks for libraries.
CHECK_APR([:], [AC_MSG_ERROR([apr library is required])])
CHECK_APU([:], [AC_MSG_ERROR([apu library is required])])
CHECK_APREQ([:], [AC_MSG_ERROR([apreq2 library is required])])
CHECK_APXS([:], [AC_MSG_ERROR([apxs is required])])
CHECK_HTTPD_VERSION([20051115.0], [:],
                    [AC_MSG_ERROR([httpd needs to be at least v2.2])])

AC_CHECK_LIB([sodium], [sodium_init])
PKG_CHECK_MODULES([CHECK], [check >= 0.8.2], [:],
                  [AC_MSG_NOTICE([Unit tests cannot be run without check])])

# Checks for header files.
AC_CHECK_HEADER([sodium.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([strchr strstr])


AC_SUBST(ac_aux_dir)

AC_CONFIG_FILES([Makefile
                 libsqrl/Makefile libsqrl/src/Makefile libsqrl/test/Makefile
                 apache2/Makefile apache2/src/Makefile])

AC_OUTPUT


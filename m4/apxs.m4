dnl Check for APXS
dnl CHECK_APXS([ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]])
dnl Sets:
dnl   APXS
dnl   APXS_CFLAGS
dnl   APXS_LIBS
dnl   APXS_SBINDIR
dnl   APXS_PROGNAME
dnl   APXS_LIBEXECDIR
dnl   APXS_HTTPD

APXS=""
APXS_CFLAGS=""
APXS_LIBS=""
APXS_SBINDIR=""
APXS_PROGNAME=""
APXS_LIBEXECDIR=""
APXS_HTTPD=""

AC_DEFUN([CHECK_APXS],
[dnl

# User configuration
AC_ARG_WITH(apxs,
            [AS_HELP_STRING([[--with-apxs=FILE]],
                            [FILE is the path to apxs; defaults to "apxs".])],
[
  if test "$withval" = "yes"; then
    APXS=apxs
  else
    APXS="$withval"
  fi
])

AC_MSG_CHECKING([for apxs config script])

# If the user didn't specify apxs, try to find it on our own
if test -z "$APXS"; then
#  for i in /usr/local/apache24/bin \
  for i in /usr/local/apache22/bin \
           /usr/local/apache2/bin \
           /usr/local/apache/bin \
           /usr/local/sbin \
           /usr/local/bin \
           /usr/sbin \
           /usr/bin;
  do
    if test -f "$i/apxs2"; then
      APXS="$i/apxs2"
      break
    elif test -f "$i/apxs"; then
      APXS="$i/apxs"
      break
    fi
  done
fi

# Ensure apxs was found
if test -n "$APXS" -a "$APXS" != "no" -a -x "$APXS" ; then
  AC_MSG_RESULT([$APXS])
else
  AC_MSG_RESULT([no])
  AC_MSG_ERROR([couldn't find APXS])
fi


# Query apxs for compilation, linking, and directory information
APXS_CFLAGS="-I`$APXS -q INCLUDEDIR`"
APXS_LIBDIR="`$APXS -q LIBDIR`"
if test -n "$APXS_LIBDIR"; then
  APXS_LIBS="-L${APXS_LIBDIR}"
else
  APXS_LIBS=""
fi
APXS_LIBS="${APXS_LIBS} `$APXS -q LIBS` `$APXS -q EXTRA_LIBS`"
APXS_SBINDIR="`$APXS -q SBINDIR`"
APXS_PROGNAME="`$APXS -q PROGNAME`"
APXS_LIBEXECDIR="`$APXS -q LIBEXECDIR`"
if test "xx$APXS_LIBEXECDIR" = "xx"; then
  APXS_LIBEXECDIR="`$APXS -q LIBDIR`/modules"
fi
APXS_HTTPD="$APXS_SBINDIR/$APXS_PROGNAME"

AC_SUBST(APXS)
AC_SUBST(APXS_CFLAGS)
AC_SUBST(APXS_LIBS)
AC_SUBST(APXS_SBINDIR)
AC_SUBST(APXS_PROGNAME)
AC_SUBST(APXS_LIBEXECDIR)
AC_SUBST(APXS_HTTPD)

if test -z "${APXS}"; then
    AC_MSG_NOTICE([*** apxs not found.])
    ifelse([$2], , , $2)
else
    AC_MSG_NOTICE([using apxs $APXS])
    ifelse([$1], , , $1) 
fi 

])


dnl Check for APXS
dnl CHECK_HTTPD_VERSION(MIN-VERSION [, ACTION-IF-GOOD [, ACTION-IF-BAD]])

AC_DEFUN([CHECK_HTTPD_VERSION],
[dnl

GOOD_VERSION="bad"
APXS_INCLUDE="`${APXS} -q INCLUDEDIR`"
if test -r $APXS_INCLUDE/httpd.h ; then
  AC_MSG_CHECKING([httpd is at least $1])
  AC_EGREP_CPP(VERSION_OK,
  [
#include "$APXS_INCLUDE/ap_mmn.h"
#if AP_MODULE_MAGIC_AT_LEAST($1,0)
VERSION_OK
#endif
  ],

  [GOOD_VERSION="good"],
  [GOOD_VERSION="bad"])
  AC_MSG_RESULT([$GOOD_VERSION])
else
  AC_MSG_NOTICE([httpd.h was not found])
fi

if test $GOOD_VERSION == "good" ; then
  ifelse([$2], , , $2)
else
  ifelse([$3], , , $3)
fi

])


dnl Check for APREQ Libraries
dnl CHECK_APREQ(ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND])
dnl Sets:
dnl  APREQ_CFLAGS
dnl  APREQ_LDFLAGS
dnl  APREQ_LIBS
dnl  APREQ_LINK_LD

APREQ_CONFIG=""
APREQ_CFLAGS=""
APREQ_INCLUDEDIR=""
APREQ_LDFLAGS=""
APREQ_LDADD=""
APREQ_LINKLD=""
AC_DEFUN([CHECK_APREQ],
[dnl

AC_ARG_WITH(
    apreq,
    [AC_HELP_STRING([--with-apreq=PATH],[Path to apreq prefix or config script])],
    [test_paths="${with_apreq}"],
    [test_paths="/usr /usr/local /opt"])

AC_MSG_CHECKING([for libapreq config script])

for x in ${test_paths}; do
    dnl # Determine if the script was specified and use it directly
    if test ! -d "$x" -a -e "$x"; then
        APREQ_CONFIG=$x
        apreq_path=no
        break
    fi

    dnl # Try known config script names/locations
    for APREQ_CONFIG in apreq2-config ; do
        if test -e "${x}/bin/${APREQ_CONFIG}"; then
            apreq_path="${x}/bin"
            break
        elif test -e "${x}/${APREQ_CONFIG}"; then
            apreq_path="${x}"
            break
        else
            apreq_path=""
        fi
    done
    if test -n "$apreq_path"; then
        break
    fi
done

if test -n "${apreq_path}"; then
    if test "${apreq_path}" != "no"; then
        APREQ_CONFIG="${apreq_path}/${APREQ_CONFIG}"
    fi
    AC_MSG_RESULT([${APREQ_CONFIG}])
    APREQ_VERSION="`${APREQ_CONFIG} --package-version`"
    if test "$verbose_output" -eq 1; then AC_MSG_NOTICE(apreq VERSION: $APREQ_VERSION); fi
    APREQ_CFLAGS="`${APREQ_CONFIG} --includes`"
    if test "$verbose_output" -eq 1; then AC_MSG_NOTICE(apreq CFLAGS: $APREQ_CFLAGS); fi
    APREQ_INCLUDEDIR="`${APREQ_CONFIG} --includedir`"
    if test "$verbose_output" -eq 1; then AC_MSG_NOTICE(apreq INCLUDEDIR: $APREQ_INCLUDEDIR); fi
    APREQ_LDFLAGS="`${APREQ_CONFIG} --libs`"
    if test "$verbose_output" -eq 1; then AC_MSG_NOTICE(apreq LDFLAGS: $APREQ_LDFLAGS); fi
    APREQ_LDADD="`${APREQ_CONFIG} --link-libtool`"
    if test "$verbose_output" -eq 1; then AC_MSG_NOTICE(apreq LDADD: $APREQ_LDADD); fi
    APREQ_LINKLD="`${APREQ_CONFIG} --link-ld`"
    if test "$verbose_output" -eq 1; then AC_MSG_NOTICE(apreq LINKLD: $APREQ_LINKLD); fi
else
    AC_MSG_RESULT([no])
fi

AC_SUBST(APREQ_CONFIG)
AC_SUBST(APREQ_VERSION)
AC_SUBST(APREQ_CFLAGS)
AC_SUBST(APREQ_INCLUDEDIR)
AC_SUBST(APREQ_LDFLAGS)
AC_SUBST(APREQ_LDADD)
AC_SUBST(APREQ_LINKLD)

if test -z "${APREQ_VERSION}"; then
    AC_MSG_NOTICE([*** apreq library not found.])
    ifelse([$2], , AC_MSG_ERROR([apreq library is required]), $2)
else
    AC_MSG_NOTICE([using apreq v${APREQ_VERSION}])
    ifelse([$1], , , $1) 
fi 
])


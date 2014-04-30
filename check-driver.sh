#!/bin/bash

DEBUG=""
BASE_DIR=$(dirname $0)
XSLT_EXE=xsltproc
TEST_EXE=
TEST_NAME=
LOG_FILE=
TRS_FILE=
COLOR_TESTS=no
EXPECT_FAILURE=no
ENABLE_HARD_ERRORS=no
CHECK_XML_FILE=
CHECK_XSL_FILE=

# Help doc
usage () {
  echo "check-driver --test-name path --log-file path --trs-file path [--color-tests {yes|no}] [--expect-failure {yes|no}] [--enable-hard-errors {yes|no}] [--check-xml-file path] [--check-xsl-file path] -- test_exe"
}

# Process arguments
if [ -n "${DEBUG}" ] ; then
  echo $0 $@
fi
while test $# -gt 0 ; do
  case $1 in
    --test-name)
      TEST_NAME="$2"
      shift;;
    --log-file)
      LOG_FILE="$2"
      shift;;
    --trs-file)
      TRS_FILE="$2"
      shift;;
    --color-tests)
      COLOR_TESTS="$2"
      shift;;
    --expect-failure)
      EXPECT_FAILURE="$2"
      shift;;
    --enable-hard-errors)
      ENABLE_HARD_ERRORS="$2"
      shift;;
    --check-xml-file)
      CHECK_XML_FILE="$2"
      shift;;
    --check-xsl-file)
      CHECK_XSL_FILE="$2"
      shift;;
    --)
      TEST_EXE="$2"
      shift; break;;
    *)
      echo "Unknown argument: $1"
      usage ; exit 1
      ;;
  esac
  shift
done

# Validate arguments
if [ -z "${TEST_EXE}" ] ; then
  usage ; exit 2
fi
if [ -z "${TEST_NAME}" ] ; then
  usage ; exit 3
fi
if [ -z "${LOG_FILE}" ] ; then
  usage ; exit 4
fi
if [ -z "${TRS_FILE}" ] ; then
  usage ; exit 5
fi
if [ "${COLOR_TESTS}" != "yes" ] ; then
  COLOR_TESTS=no
fi
if [ "${EXPECT_FAILURE}" != "yes" ] ; then
  EXPECT_FAILURE=no
fi
if [ "${ENABLE_HARD_ERRORS}" != "yes" ] ; then
  ENABLE_HARD_ERRORS=no
fi
if [ -z "${CHECK_XML_FILE}" ] ; then
  CHECK_XML_FILE=${TEST_NAME}.xml
fi
if [ -z "${CHECK_XSL_FILE}" ] ; then
  CHECK_XSL_FILE="${BASE_DIR}/check2trs.xslt"
fi

# Debug
if [ -n "${DEBUG}" ] ; then
  echo "BASE_DIR = ${BASE_DIR}"
  echo "TEST_EXE = ${TEST_EXE}"
  echo "TEST_NAME = ${TEST_NAME}"
  echo "LOG_FILE = ${LOG_FILE}"
  echo "TRS_FILE = ${TRS_FILE}"
  echo "COLOR_TESTS = ${COLOR_TESTS}"
  echo "EXPECT_FAILURE = ${EXPECT_FAILURE}"
  echo "ENABLE_HARD_ERRORS = ${ENABLE_HARD_ERRORS}"
  echo "CHECK_XML_FILE = ${CHECK_XML_FILE}"
  echo "CHECK_XSL_FILE = ${CHECK_XSL_FILE}"
fi

# run check
CK_VERBOSITY=verbose CK_XML_LOG_FILE_NAME="${CHECK_XML_FILE}" "${TEST_EXE}" > "${LOG_FILE}"

# Translate check's xml to automake's trs
"$XSLT_EXE" -o "${TRS_FILE}" "${CHECK_XSL_FILE}" "${CHECK_XML_FILE}"


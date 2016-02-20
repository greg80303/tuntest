dnl Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([TunTest], [1.0], [g.rutz@cablelabs.com])
AC_CONFIG_SRCDIR([src/tuntest.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign parallel-tests color-tests])
AC_CONFIG_MACRO_DIR([m4])
AC_LANG_CPLUSPLUS
AX_CXX_COMPILE_STDCXX_11

# Checks for programs.
AC_PROG_CC
AC_PROG_AWK
AC_PROG_INSTALL
AC_PROG_MKDIR_P

LT_INIT

m4_ifndef([PKG_PROG_PKG_CONFIG],
  [m4_fatal([Could not locate the pkg-config autoconf
    macros. These are usually located in /usr/share/aclocal/pkg.m4.
    If your macros are in a different location, try setting the
    environment variable AL_OPTS="-I/other/macro/dir" before running
    ./autogen.sh or autoreconf again.])])
PKG_PROG_PKG_CONFIG

# Checks for libraries.
AC_CHECK_LIB([pthread], [pthread_create], [], [AC_MSG_ERROR([Unable to find libpthread])])

PKG_CHECK_MODULES([NL], [libnl-3.0], [], [AC_MSG_ERROR([Could not find libnl-3.0])])
AC_SUBST(NL_CFLAGS)
AC_SUBST(NL_LIBS)
PKG_CHECK_MODULES([NLROUTE], [libnl-route-3.0], [], [AC_MSG_ERROR([Could not find libnl-route-3.0])])
AC_SUBST(NLROUTE_CFLAGS)
AC_SUBST(NLROUTE_LIBS)

# Checks for header files.
AC_CHECK_HEADERS()

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.


# Common variables
com_incdir='-I${top_srcdir}/inc -I/usr/include/libnl3'
AC_SUBST([com_incdir])

AC_CONFIG_FILES(
  Makefile \
  src/Makefile \
)

AC_OUTPUT


AC_PREREQ(2.61)

AC_INIT([xdmcpd], [0.1], [redchrom@gmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for libraries.
PKG_CHECK_MODULES(DEPS, glib-2.0 >= 2.12.0 xdmcp >= 1.0.0 gio-2.0 >= 2.12.0)
CFLAGS="$CFLAGS $DEPS_CFLAGS"
LIBS="$LIBS $DEPS_LIBS"

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_TIME
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([fcntl.h stdlib.h sys/socket.h unistd.h netdb.h netinet/in.h sys/time.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIGNAL
AC_TYPE_SIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([socket bzero gethostname gettimeofday memset select uname \
				setenv strchr])
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_FORK

AC_CONFIG_FILES([
				 Makefile
				 src/Makefile
				 ])

AC_OUTPUT

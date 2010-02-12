#!/bin/sh
make distclean
find . -name Makefile.in -delete
rm -rf configure aclocal.m4 autom4te.cache depcomp install-sh missing INSTALL intltool-*

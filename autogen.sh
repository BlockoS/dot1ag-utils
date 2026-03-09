#!/bin/sh
set -e

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

# Check for autoconf, automake and aclocal
err=0
(aclocal --version) < /dev/null > /dev/null 2>&1 || { echo 1>&2 "aclocal must be installed"; err=1; }
(automake --version) < /dev/null > /dev/null 2>&1 || { echo 1>&2 "automake must be installed"; err=1; }
(autoconf --version) < /dev/null > /dev/null 2>&1 || { echo 1>&2 "autoconf must be installed"; err=1; }
(autoreconf --version) < /dev/null > /dev/null 2>&1 || { echo 1>&2 "autoreconf must be installed"; err=1; }
if [ $err -ne 0 ]; then
	exit 1;
fi

rm -rf autom4te.cache

autoreconf -if --verbose $srcdir

exit 0

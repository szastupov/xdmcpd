#/bin/sh
autoreconf -i
./configure CFLAGS="-ggdb -Wall -pipe"

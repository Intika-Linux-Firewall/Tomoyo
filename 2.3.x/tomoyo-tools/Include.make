CC              := gcc
INSTALL         := install
SBINDIR         := /sbin
USRSBINDIR      := /usr/sbin
USRLIBDIR       := /usr/lib
MAN8            := /usr/share/man/man8
CFLAGS          := -Wall -O2 ${shell $(CC) -Wno-pointer-sign -S -o /dev/null -x c - < /dev/null > /dev/null 2>&1 && echo "-Wno-pointer-sign"}

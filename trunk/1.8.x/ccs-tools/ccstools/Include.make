CC              := gcc
INSTALL         := install
SBINDIR         := /sbin
USRSBINDIR      := /usr/sbin
USRLIBDIR       := /usr/lib
LIBEXECDIR      := /usr/lib/ccs
MAN8            := /usr/share/man/man8
NO_POINTER_SIGN := ${shell $(CC) -Wno-pointer-sign -S -o /dev/null -x c - < /dev/null > /dev/null 2>&1 && echo "-Wno-pointer-sign"}

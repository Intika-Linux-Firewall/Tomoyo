INSTALL         := install
ETCDIR          := /etc
BINDIR          := /bin
SBINDIR         := /sbin
LIBDIR          := /lib
USRBINDIR       := /usr/bin
USRSBINDIR      := /usr/sbin
LIBEXECDIR      := /usr/lib/ccs
USRLIBDIR       := /usr/lib
SHAREDIR        := /usr/share/keyutils
INCLUDEDIR      := /usr/include
USRSHAREDIR     := /usr/share/ccs
MAN8            := /usr/share/man/man8

CC              := gcc

NO_POINTER_SIGN := ${shell $(CC) -Wno-pointer-sign -S -o /dev/null -x c - < /dev/null > /dev/null 2>&1 && echo "-Wno-pointer-sign"}

CFLAGS          += $(NO_POINTER_SIGN)

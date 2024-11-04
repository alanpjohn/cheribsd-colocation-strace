# $FreeBSD$

.include <bsd.own.mk>

LIB=		colocatedstrace
SRCS=		colocatedstrace.c
SHLIB_MAJOR=	1
MAN=

# For libc_private.h
CFLAGS+=	-I${SRCTOP}/lib/libc/include

WARNS?=		5

.include <bsd.lib.mk>

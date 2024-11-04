#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/capsicum.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <capv.h>
#include <err.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "libc_private.h"

__thread static void * __capability target = NULL;

__attribute__((constructor))
static void libcolocatedstrace_init(void)
{
    int error;

    error = cap_enter();
    if (error != 0)
        err(1, "cap_enter");
}

static int
init_maybe(void)
{
    void * __capability *capv;
    int capc, error;

    if (__predict_true(target != NULL))
        return (0);

    capvfetch(&capc, &capv);
    if (capc <= CAPV_SYSCALL_LOG || capv[CAPV_SYSCALL_LOG] == NULL) {
        warn("%s: null capability %d", __func__, CAPV_SYSCALL_LOG);
        errno = ENOLINK;
        return (-1);
    }

    error = cosetup(COSETUP_COCALL);
    if (error != 0) {
        warn("%s: cosetup", __func__);
        return (-1);
    }
    target = capv[CAPV_SYSCALL_LOG];

    return (0);
}

#define	CAPFROMFD(FDCAP, S)				\
	{						\
		int _error;				\
		_error = capfromfd((void *)FDCAP, S);	\
		if (_error != 0)			\
			err(1, "capfromfd");		\
	}

/*
 * XXX: For AT_FDCWD case we probably want to call the native syscall instead of cocall.
 */
// static uintcap_t
// fd2c(int fd)
// {
// 	uintcap_t fdcap;

// 	if (fd == AT_FDCWD)
// 		return ((uintcap_t)fd);

// 	CAPFROMFD(&fdcap, fd);
// 	return (fdcap);
// }

static int
log_syscall(int op, uintcap_t a0, uintcap_t a1, uintcap_t a2, uintcap_t a3, uintcap_t a4)
{
    capv_answerback_t in;
    capv_syscall_t out;
    ssize_t received;
    int error;

    error = init_maybe();
    if (error != 0)
        return (error);

    // if (op == SYS_write) {
    //     a1 = fd2c(a1);
    // }

    memset(&out, 0, sizeof(out));
    out.len = sizeof(out);
    out.op = op;
    out.arg[0] = a0;
    out.arg[1] = a1;
    out.arg[2] = a2;
    out.arg[3] = a3;
    out.arg[4] = a4;
    out.arg[5] = 0;
    out.arg[6] = 0;
    out.arg[7] = 0;

    received = cocall(target, &out, out.len, &in, sizeof(in));

    if (received < 0) {
		warn("%s: cocall", __func__);
        return (received);
	}

	return (0);
}

ssize_t write(int fd, const void *buf, size_t count)
{
    int error;

    error = log_syscall(SYS_write, fd, (uintcap_t)buf, count, 0, 0);
    if (error != 0)
        warn("%s: log_syscall", __func__);

    return (syscall(SYS_write, fd, buf, count, 0, 0));
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
{
    int error;

    error = log_syscall(SYS_writev, fd, (uintcap_t)iov, iovcnt, 0, 0);
    if (error != 0)
        warn("%s: log_syscall", __func__);

    return (syscall(SYS_writev, fd, iov, iovcnt, 0, 0));
}

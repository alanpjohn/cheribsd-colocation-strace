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

// __attribute__((constructor))
// static void libcolocatedstrace_init(void)
// {
//     int error;

//     error = cap_enter();
//     if (error != 0)
//         err(1, "cap_enter");
// }

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
log_syscall(int op, uintcap_t a0, uintcap_t a1, uintcap_t a2, uintcap_t a3, uintcap_t a4, uintcap_t a5)
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
    out.arg[5] = a5;
    out.arg[6] = 0;
    out.arg[7] = 0;

    received = cocall(target, &out, out.len, &in, sizeof(in));

    if (received < 0) {
		warn("%s: cocall", __func__);
        return (received);
	}

	return (0);
}

/*
Overloading the write syscall
Syscall number: 4
*/
ssize_t write(int fd, const void *buf, size_t count)
{
    int error;

    error = log_syscall(SYS_write, fd, (uintcap_t)buf, count, 0, 0, 0);
    if (error != 0)
        warn("%s: log_syscall", __func__);

    return (syscall(SYS_write, fd, buf, count, 0, 0));
}

/*
Overloading the writev syscall
Syscall number: 121
*/
ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
{
    int error;

    error = log_syscall(SYS_writev, fd, (uintcap_t)iov, iovcnt, 0, 0, 0);
    if (error != 0)
        warn("%s: log_syscall", __func__);

    return (syscall(SYS_writev, fd, iov, iovcnt, 0, 0));
}

/*
Overloading the read syscall
Syscall number: 3
*/
ssize_t
read(int fd, void *buf, size_t nbytes)
{
    int error;

    error = log_syscall(SYS_read, fd, (uintcap_t)buf, nbytes, 0, 0, 0);
    if (error != 0)
        warn("%s: log_syscall", __func__);

    return (syscall(SYS_read, fd, buf, nbytes, 0, 0));
}

/*
Overloading the fstatat syscall
Syscall number: 552
*/
int
fstatat(int fd, const char *path, struct stat *sb, int flag)
{
    int error;

    error = log_syscall(SYS_fstatat, fd, (uintcap_t)path, (uintcap_t)sb, flag, 0, 0);
    if (error != 0)
        warn("%s: log_syscall", __func__);

    return (syscall(SYS_fstatat, fd, path, sb, flag, 0));
}

/*
Overloading the fchmodat syscall
Syscall number: 490
*/
int
fchmodat(int fd, const char *path, mode_t mode, int flag)
{
    int error;

    error = log_syscall(SYS_fchmodat, fd, (uintcap_t)path, mode, flag, 0, 0);
    if (error != 0)
        warn("%s: log_syscall", __func__);

    return (syscall(SYS_fchmodat, fd, path, mode, flag, 0));
}

/*
Overloading the fchownat syscall
Syscall number: 491
*/
int
fchownat(int fd, const char *path, uid_t owner, gid_t group, int flag)
{
    int error;

    error = log_syscall(SYS_fchownat, fd, (uintcap_t)path, owner, group, flag, 0);
    if (error != 0)
        warn("%s: log_syscall", __func__);

    return (syscall(SYS_fchownat, fd, path, owner, group, flag));
}

/*
Overloading the utimensat syscall
Syscall number: 547
*/
int
utimensat(int fd, const char *path, const struct timespec times[2], int flag)
{
    int error;

    error = log_syscall(SYS_utimensat, fd, (uintcap_t)path, (uintcap_t)times, flag, 0, 0);
    if (error != 0)
        warn("%s: log_syscall", __func__);

    return (syscall(SYS_utimensat, fd, path, times, flag, 0));
}

/*
Overloading the openat syscall
Syscall number: 499
*/
int
__sys_openat(int fd, const char *path, int flags, int mode)
{
    int error;

    error = log_syscall(SYS_openat, fd, (uintcap_t)path, flags, mode, 0, 0);
    if (error != 0)
        warn("%s: log_syscall", __func__);

    return (syscall(SYS_openat, fd, path, flags, mode, 0));
}

/*
Overloading the pathconf syscall
Syscall number: 191
*/
long
pathconf(const char *path, int name)
{
    int error;

    error = log_syscall(SYS_pathconf, (uintcap_t)path, name, 0, 0, 0, 0);
    if (error != 0)
        warn("%s: log_syscall", __func__);

    return (syscall(SYS_pathconf, path, name, 0, 0, 0));
}

/*
Overloading the lpathconf syscall
Syscall number: 513
*/
long
lpathconf(const char *path, int name)
{
    int error;

    error = log_syscall(SYS_lpathconf, (uintcap_t)path, name, 0, 0, 0, 0);
    if (error != 0)
        warn("%s: log_syscall", __func__);

    return (syscall(SYS_lpathconf, path, name, 0, 0, 0));
}

/*
Overloading the fchdir syscall
Syscall number: 13
*/
int fchdir(int fd)
{
    int error;

    error = log_syscall(SYS_fchdir, fd, 0, 0, 0, 0, 0);
    if (error != 0)
        warn("%s: log_syscall", __func__);

    return (syscall(SYS_fchdir, fd, 0, 0, 0, 0));
}


/*
Overloading the getcwd syscall
Syscall number: 326
*/
int __getcwd(char *buf, size_t size);

int __getcwd(char *buf, size_t size)
{
    int error;

    error = log_syscall(SYS___getcwd, (uintcap_t)buf, size, 0, 0, 0, 0);
    if (error != 0)
        warn("%s: log_syscall", __func__);

    return (syscall(SYS___getcwd, buf, size, 0, 0, 0));
}

/*
Overloading the mkdir syscall
Syscall number: 136
*/
int mkdir(const char *path, mode_t mode)
{
    int error;

    error = log_syscall(SYS_mkdir, (uintcap_t)path, mode, 0, 0, 0, 0);
    if (error != 0)
        warn("%s: log_syscall", __func__);

    return (syscall(SYS_mkdir, path, mode, 0, 0, 0));
}

/*
Overloading the rmdir syscall
Syscall number: 137
*/
int rmdir(const char *path)
{
    int error;

    error = log_syscall(SYS_rmdir, (uintcap_t)path, 0, 0, 0, 0, 0);
    if (error != 0)
        warn("%s: log_syscall", __func__);

    return (syscall(SYS_rmdir, path, 0, 0, 0, 0));
}

/*
Overloading the bind syscall
Syscall number: 104
*/
int bind(int s, const struct sockaddr *addr, socklen_t addrlen)
{
    int error;

    error = log_syscall(SYS_bind, s, (uintcap_t)addr, addrlen, 0, 0, 0);
    if (error != 0)
        warn("%s: log_syscall", __func__);

    return (syscall(SYS_bind, s, addr, addrlen, 0, 0));
}

/*
Overloading the connect syscall
Syscall number: 98
*/
int connect(int s, const struct sockaddr *addr, socklen_t addrlen)
{
    int error;

    error = log_syscall(SYS_connect, s, (uintcap_t)addr, addrlen, 0, 0, 0);
    if (error != 0)
        warn("%s: log_syscall", __func__);

    return (syscall(SYS_connect, s, addr, addrlen, 0, 0));
}

/*
Overloading the accept syscall
Syscall number: 30
*/
int accept(int s, struct sockaddr *addr, socklen_t *addrlen)
{
    int error;

    error = log_syscall(SYS_accept, s, (uintcap_t)addr, (uintcap_t)addrlen, 0, 0, 0);
    if (error != 0)
        warn("%s: log_syscall", __func__);

    return (syscall(SYS_accept, s, addr, addrlen, 0, 0));
}

/*
Overloading the accept4 syscall
Syscall number: 541
*/  
int
accept4(int s, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    int error;

    error = log_syscall(SYS_accept4, s, (uintcap_t)addr, (uintcap_t)addrlen, flags, 0, 0);
    if (error != 0)
        warn("%s: log_syscall", __func__);

    return (syscall(SYS_accept4, s, addr, addrlen, flags, 0));
}
/*
Overloading the fork syscall
Syscall number: 2
*/
pid_t fork(void)
{
    int error;

    error = log_syscall(SYS_fork, 0, 0, 0, 0, 0, 0);
    if (error != 0)
        warn("%s: log_syscall", __func__);

    return (syscall(SYS_fork, 0, 0, 0, 0, 0));
}

/*
Overloading the execve syscall
Syscall number: 50
*/
int execve(const char *path, char *const argv[], char *const envp[])
{
    int error;

    error = log_syscall(SYS_execve, (uintcap_t)path, (uintcap_t)argv, (uintcap_t)envp, 0, 0, 0);
    if (error != 0)
        warn("%s: log_syscall", __func__);

    return (syscall(SYS_execve, path, argv, envp, 0, 0));
}

/*
Overloading the close syscall
Syscall number: 6
*/
int close(int fd)
{
    int error;

    error = log_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    if (error != 0)
        warn("%s: log_syscall", __func__);

    return (syscall(SYS_close, fd, 0, 0, 0, 0));
}

/*
Overloading the access syscall
Syscall number: 33
*/
int access(const char *path, int mode)
{
    int error;

    error = log_syscall(SYS_access, (uintcap_t)path, mode, 0, 0, 0, 0);
    if (error != 0)
        warn("%s: log_syscall", __func__);

    return (syscall(SYS_access, path, mode, 0, 0, 0));
}


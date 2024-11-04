#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/auxv.h>
#include <sys/capsicum.h>
#include <sys/param.h>
#include <sys/procctl.h>
#include <sys/queue.h>
#include <sys/sbuf.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <assert.h>
#include <capv.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysdecode.h>
#include <unistd.h>


static bool Cflag = false, kflag = false, vflag = false;

static void
usage(void)
{
	fprintf(stderr, "usage: colocatedstrace command [args ...]\n");
	exit(0);
}

static void
sigchld_handler(int dummy __unused)
{
	exit(0);
}

static void answerback(capv_answerback_t *out)
{
	struct sbuf sb;
	int error;

	memset(out, 0, sizeof(*out));
	out->len = sizeof(*out);
	out->op = 0;
	sbuf_new(&sb, out->answerback, sizeof(out->answerback), SBUF_FIXEDLEN);

	sbuf_printf(&sb, "colocatedstrace");
	sbuf_printf(&sb, ", pid %d", getpid());
	if (kflag)
		sbuf_printf(&sb, " (slow)");

	error = sbuf_finish(&sb);
	if (error != 0)
		err(1, "sbuf_finish");
}

static void
enable_opportunistic_colocation(void)
{
	int error, arg;

	arg = PROC_CHERI_OPPORTUNISTIC_ENABLE;
	error = procctl(P_PID, 0, PROC_CHERI_COLOCATION_CTL, &arg);
	if (error != 0)
		err(1, "procctl");
}

int
main(int argc, char **argv)
{
    capv_syscall_t in;
    union {
        capv_answerback_t answerback;
        capv_syscall_t syscall;
    } outbuf;
    capv_syscall_t *out = &outbuf.syscall;

    struct sigaction sa;
    void * __capability public;
    void * __capability cookie;
    void * __capability *capv = NULL;

    char *ld_preload;
    char *tmp = NULL;
    // const char *path;
    // uintcap_t fdcap;
    ssize_t received;
    pid_t pid;
    int capc, ch, error;

    while ((ch = getopt(argc, argv, "Ckv")) != -1) {
		switch (ch) {
		case 'C':
			Cflag = true;
			break;
		case 'k':
			kflag = true;
			break;
		case 'v':
			vflag = true;
			break;
		case '?':
		default:
			usage();
		}
	}

    argc -= optind;
	argv += optind;
	if (argc < 1)
		usage();

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigchld_handler;
	sa.sa_flags = SA_NOCLDSTOP;
	sigfillset(&sa.sa_mask);

	error = sigaction(SIGCHLD, &sa, NULL);
	if (error != 0)
		err(1, "sigaction");

	error = cosetup(COSETUP_COACCEPT);
	if (error != 0)
		err(1, "cosetup");

	error = coregister(NULL, &public);
	if (error != 0)
		err(1, "coregister");

	capvfetch(&capc, &capv);
	error = capvset(&capc, &capv, CAPV_SYSCALL_LOG, public);
	if (error != 0)
		err(1, "capvset");

    ld_preload = getenv("LD_PRELOAD");
	if (ld_preload != NULL) {
		asprintf(&tmp, "%s:%s", ld_preload, "/usr/lib/libcolocatedstrace.so");
	} else {
		asprintf(&tmp, "%s", "/usr/lib/libcolocatedstrace.so");
	}
	error = setenv("LD_PRELOAD", tmp, 1);
	if (error != 0)
		err(1, "setenv");


    pid = vfork();
	if (pid < 0)
		err(1, "vfork");

	if (pid == 0) {
		/*
		 * Child, will coexecvec(2) the new command.
		 */
		enable_opportunistic_colocation();
		coexecvpc(0, argv[0], argv, capv, capc);

		/*
		 * Shouldn't have returned.
		 */
		err(1, "%s", argv[0]);
	}

	if (!Cflag) {
		error = cap_enter();
		if (error != 0)
			err(1, "cap_enter");
	}

	memset(out, 0, sizeof(*out));

	for (;;) {
		if (kflag)
			received = coaccept_slow(&cookie, out, out->len, &in, sizeof(in));
		else
			received = coaccept(&cookie, out, out->len, &in, sizeof(in));
		if (received < 0) {
			warn("%s", kflag ? "coaccept_slow" : "coaccept");
			memset(out, 0, sizeof(*out));
			continue;
		}

		if (vflag) {
			printf("%s: op %d, len %zd from pid %d -> pid %d%s\n",
			    getprogname(), in.op, in.len, pid, getpid(), kflag ? " (slow)" : "");
		}

		answerback(&outbuf.answerback);

		if (vflag) {
			printf("%s: returning to pid %d <- pid %d: op %d, len %zd %s\n",
			    getprogname(), pid, getpid(), out->op, out->len, kflag ? " (slow)" : "");
		}
	}
}

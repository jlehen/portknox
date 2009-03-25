#define	_ISOC99_SOURCE
#define	_BSD_SOURCE
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <tcpd.h>
#include <unistd.h>
#include "conf.h"
#include "faststring.h"
#include "util.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif

#define	TIMEOUT_WHEEL_SIZE	5

struct task {
	struct task *next;
	unsigned int tick;
	void (*func)(void *);
	void *arg; 
};

static struct janitor *janitors;
static struct task *timeout_wheel[TIMEOUT_WHEEL_SIZE];
static struct task *tasks_todo;
static unsigned int curtick;
static int mustquit = 0;
static sigset_t alrm_sigset;

void
quit(int s __attribute__ ((unused)))
{

	mustquit = 1;
}

void
run(void *p)
{
	char *cmd, *sp;
	char **argv, **ap;
	int asize;
	struct janitor *jp;
	pid_t pid;

	fprintf(stderr, "DEBUG: gonna run '%s'\n", (char *)p);
	pid = fork();
	if (pid == -1) {
		warn("Can't fork");
		return;
	}
	if (pid > 0) {
		myfree(p);
		return;
	}

	sp = cmd = p;
	asize = 16;
	ap = argv = mymalloc(asize * sizeof (*argv), "argument list");
	while (cmd != NULL) {
		sp = strsep(&cmd, " ");
		if (*sp == '\0')
			continue;
		*ap++ = sp;
		if (ap - argv == asize) {
			asize += 16;
			argv = myrealloc(argv, asize * sizeof (*argv),
			    "argument list");
		}
	}
	*ap = NULL;

	for (jp = janitors; jp != NULL; jp = jp->next)
		close(jp->sock);

	if (execvp(argv[0], argv) == -1)
		warn("Can't exec %s", argv[0]);
	exit(255);
}

char *
expand(const char *cmd, const char *ip)
{
	faststring *str;
	const char *p;

	str = faststring_alloc(512);
	p = cmd;
	while (*p != '\0') {
		if (*p != '%') {
			faststring_strncat(str, p++, 1);
			continue;
		}
		p++;
		switch (*p) {
		case '\0':
			faststring_strcat(str, "%");
			return faststring_export(str);
		case '%':
			faststring_strcat(str, "%");
			break;
		case 'h':
			faststring_strcat(str, ip);
			break;
		default:
			faststring_strcat(str, "%");
			faststring_strncat(str, p, 1);
			break;
		}
		p++;
	}
	return faststring_export(str);
}

void
schedule(int timeout, void (*func)(void *), void *arg)
{
	struct task *task, *cur, *last;
	int slot;

	task = mymalloc(sizeof (*task), "struct task");
	task->tick = curtick + timeout;
	task->func = func;
	task->arg = arg;

	slot = task->tick % TIMEOUT_WHEEL_SIZE;
	/*
	fprintf(stderr, "DEBUG: schedule task, tick %d, timeout %d, expire %d, slot %d\n", curtick, timeout, task->tick, slot);
	*/
	sigprocmask(SIG_BLOCK, &alrm_sigset, NULL);

	cur = timeout_wheel[slot];
	last = NULL;
	while (1) {
		if (cur == NULL)
			break;
		if (cur->tick > task->tick)
			break;
		last = cur;
		cur = cur->next;
	}
	/*
	fprintf(stderr, "DEBUG: schedule, cur %p, last %p\n", cur, last);
	*/
	if (last == NULL)
		timeout_wheel[slot] = task;
	else
		last->next = task;
	task->next = cur;

	sigprocmask(SIG_UNBLOCK, &alrm_sigset, NULL);
}

void
tick()
{
	struct task *prevtask, *task;
	struct janitor *jp;
	int slot;

	alarm(1);
	curtick++;

	/*
	 * Extract actions to perform on this tick.
	 */
	slot = curtick % TIMEOUT_WHEEL_SIZE;
	task = timeout_wheel[slot];
	prevtask = NULL;
	fprintf(stderr, "DEBUG: alarm, curtick %d, wheel slot %d, first task %p\n", curtick, slot, task);
	while (task != NULL) {
		if (task->tick > curtick)
			break;
		prevtask = task;
		task = task->next;
	}
	fprintf(stderr, "DEBUG: alarm, prev task %p, next task %p\n", prevtask, task);
	if (prevtask != NULL) {
		prevtask->next = NULL;
		tasks_todo = timeout_wheel[slot];
		timeout_wheel[slot] = task;
	}

	/*
	 * Rotate janitor's usage wheel.
	 */
	for (jp = janitors; jp != NULL; jp = jp->next) {
		slot = curtick % jp->uswheelsz;

		jp->uscur -= jp->uswheel[slot];
		jp->uswheel[slot] = 0;
		fprintf(stderr, "DEBUG: alarm, janitor %p, usage slot %d emptied, total usage: %d\n",
		    jp, slot, jp->uscur);
	}

}

void
tend(struct janitor *janitor)
{
	struct sockaddr_in sin;
	socklen_t sinlen;
	int i, slot, error;
	char buf[1], ip[NI_MAXHOST];
	char *cmd;
	struct action *action;

	/*
	 * Get IP address.
	 */
	fprintf(stderr, "DEBUG: activity on janitor %p\n", janitor);
	sinlen = sizeof (sin);
	if (janitor->addrinfo->ai_protocol == IPPROTO_TCP) {
		i = accept(janitor->sock, (struct sockaddr *)&sin,
		    (socklen_t *)&sinlen);
		if (i == -1) {
			warn("Could not accept connection");
			return;
		}
		if (shutdown(i, SHUT_RDWR) == -1)
			warn("Could not shutdown connection");
		if (close(i) == -1)
			warn("Could not close socket");
	} else {
		i = recvfrom(janitor->sock, buf, 1, 0,
		    (struct sockaddr *)&sin, (socklen_t *)&sinlen);
		if (i == -1) {
			warn("Could not receive datagram");
			return;
		}
	}

	error = getnameinfo((struct sockaddr *)&sin, sizeof (sin),
	    ip, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
	if (error != 0) {
		warnx("Could not resolve hostname: %s", gai_strerror(error));
		return;
	}

	/*
	 * Check max usage.
	 */
	sigprocmask(SIG_BLOCK, &alrm_sigset, NULL);
	slot = curtick % janitor->uswheelsz;
	if (janitor->uscur == janitor->usmax) {
		warnx("Max usage reached, can't fulfill request from %s", ip);
		return;
	}
	janitor->uswheel[slot]++;
	janitor->uscur++;
	fprintf(stderr, "DEBUG: current usage slot %d: %d, total usage: %d/%d\n",
		slot, janitor->uswheel[slot], janitor->uscur, janitor->usmax);
	sigprocmask(SIG_UNBLOCK, &alrm_sigset, NULL);

	/*
	 * Perform and schedule actions.
	 */
	for (action = janitor->actions; action != NULL; action = action->next) {
		cmd = expand(action->cmd, ip);
		if (action->timeout == 0)
			run(cmd);
		else
			schedule(action->timeout + 1, run, cmd);
	}
}

int
main(int ac, char *av[])
{
	struct sigaction sa;
	struct janitor *jp, *jpnext;
	struct task *nexttask, *curtask;
	struct action *nextaction, *curaction;
	int jcount, i, fdmax;
	fd_set fds_, fds;

	sa.sa_handler = &quit;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGQUIT, &sa, NULL) == -1)
		err(2, "sigaction");

	jcount = read_conf("portknox.conf", &janitors);

	fdmax = 0;
	for (jp = janitors; jp != NULL; jp = jp->next) {
		if (jp->sock > fdmax)
			fdmax = jp->sock;
	}

	sigemptyset(&alrm_sigset);
	sigaddset(&alrm_sigset, SIGALRM);

	/* Timeout wheel. */
	for (i = 0; i < TIMEOUT_WHEEL_SIZE; i++)
		timeout_wheel[i] = NULL;

	sa.sa_handler = &tick;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGALRM, &sa, NULL) == -1)
		err(2, "sigaction");

	alarm(1);

	/* Main loop. */
	FD_ZERO(&fds_);
	for (jp = janitors; jp != NULL; jp = jp->next)
		FD_SET(jp->sock, &fds_);

	while (!mustquit) {
		/* Handle callouts. */
		sigprocmask(SIG_BLOCK, &alrm_sigset, NULL);
		curtask = tasks_todo;
		while (curtask != NULL) {
			nexttask = curtask->next;
			(*curtask->func)(curtask->arg);
			myfree(curtask);
			curtask = nexttask;
		}
		tasks_todo = NULL;
		sigprocmask(SIG_UNBLOCK, &alrm_sigset, NULL);

		fds = fds_;
		i = select(fdmax + 1, &fds, NULL, NULL, NULL);
		if (i == -1) {
			if (errno == EINTR)
				continue;
			err(2, "select");
		}
		for (jp = janitors; jp != NULL; jp = jp->next) {
			if (FD_ISSET(jp->sock, &fds)) {
				fprintf(stderr, "DEBUG: activity on fd %d\n",
				    jp->sock);
				tend(jp);
			}
		}
	}

	alarm(0);
	for (jp = janitors; jp != NULL; jp = jpnext) {
		jpnext = jp->next;
		myfree(jp->ip);
		myfree(jp->port);
		myfree(jp->proto);
		for (curaction = jp->actions; curaction != NULL;
		    curaction = nextaction) {
			nextaction = curaction->next;
			myfree(curaction->cmd);
			myfree(curaction);
		}
		/*
		myfree(jp->addrinfo->ai_addr);
		myfree(jp->addrinfo->ai_canonname);
		*/
		myfree(jp->addrinfo);
		myfree(jp);
	}
	for (curtask = tasks_todo; curtask != NULL; curtask = nexttask) {
		nexttask = curtask->next;
		myfree(curtask->arg);
		myfree(curtask);
	}
	for (i = 0; i < TIMEOUT_WHEEL_SIZE; i++) {
		for (curtask = timeout_wheel[i]; curtask != NULL;
		    curtask = nexttask) {
			nexttask = curtask->next;
			myfree(curtask->arg);
			myfree(curtask);
		}
	}
	exit(0);
}

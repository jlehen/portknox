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
#include <unistd.h>
#include "conf.h"
#include "faststring.h"
#include "freebsdqueue.h"
#include "util.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif

#define	TIMEOUT_WHEEL_SIZE	5

struct task {
	SLIST_ENTRY(task) next;
	unsigned int tick;
	void (*func)(void *);
	void *arg; 
};

SLIST_HEAD(tasklist, task);

static struct janitorlist janitors;
static struct tasklist timeout_wheel[TIMEOUT_WHEEL_SIZE];
static struct tasklist tasks_todo;
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

	SLIST_FOREACH(jp, &janitors, next)
		close(jp->sock);

	if (execvp(argv[0], argv) == -1)
		warn("Can't exec %s", argv[0]);
	exit(255);
}

char *
expand(const char *cmd, const char *ip, unsigned count)
{
	faststring *str;
	const char *p;
	char *countstr;

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
		case 'n':
			(void)asprintf(&countstr, "%u", count);
			if (countstr == NULL)
				err(2, "String expansion");
			faststring_strcat(str, countstr);
			myfree(countstr);
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
	struct task *task, *tp, *prevtp;
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

	prevtp = NULL;
	SLIST_FOREACH(tp, &timeout_wheel[slot], next) {
		if (tp == NULL)
			break;
		if (tp->tick > task->tick)
			break;
		prevtp = tp;
	}
	/*
	fprintf(stderr, "DEBUG: schedule, cur %p, prev %p\n", tp, prevtp);
	*/
	if (prevtp == NULL)
		SLIST_FIRST(&timeout_wheel[slot]) = task;
	else
		SLIST_NEXT(prevtp, next) = task;
	SLIST_NEXT(task, next) = tp;

	sigprocmask(SIG_UNBLOCK, &alrm_sigset, NULL);
}

void
tick()
{
	struct task *prevtp, *tp;
	struct janitor *jp;
	int slot;

	alarm(1);
	curtick++;

	/*
	 * Extract actions to perform on this tick.
	 */
	slot = curtick % TIMEOUT_WHEEL_SIZE;
	prevtp = NULL;
	fprintf(stderr, "DEBUG: alarm, curtick %d, wheel slot %d, first task %p\n", curtick, slot, SLIST_FIRST(&timeout_wheel[slot]));
	SLIST_FOREACH(tp, &timeout_wheel[slot], next) {
		if (tp->tick > curtick)
			break;
		prevtp = tp;
	}
	fprintf(stderr, "DEBUG: alarm, prev task %p, next task %p\n", prevtp, tp);
	if (prevtp != NULL) {
		SLIST_NEXT(prevtp, next) = NULL;
		SLIST_FIRST(&tasks_todo) = SLIST_FIRST(&timeout_wheel[slot]);
		SLIST_FIRST(&timeout_wheel[slot]) = tp;
	}

	/*
	 * Rotate janitor's usage wheel.
	 */
	SLIST_FOREACH(jp, &janitors, next) {
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
	SLIST_FOREACH(action, &janitor->actions, next) {
		cmd = expand(action->cmd, ip, janitor->count);
		if (action->timeout == 0)
			run(cmd);
		else
			schedule(action->timeout + 1, run, cmd);
	}
	janitor->count++;
}

int
main(int ac, char *av[])
{
	struct sigaction sa;
	struct janitor *jp, *tmpjp;
	struct task *tp, *tmptp;
	struct action *action, *tmpaction;
	int jcount, i, s, fdmax;
	struct addrinfo *ai;
	fd_set fds_, fds;

	sa.sa_handler = &quit;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGQUIT, &sa, NULL) == -1)
		err(2, "sigaction");

	jcount = read_conf("portknox.conf", &janitors);

	fdmax = 0;
	SLIST_FOREACH(jp, &janitors, next) {
		ai = jp->addrinfo;
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (s == -1)
			err(2, "socket");
		if (!strcmp(jp->proto, "tcp")) {
			i = 1;
			if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &i,
			    sizeof (i)) == -1)
				err(2, "setsockopt");
		}
		if (bind(s, ai->ai_addr, ai->ai_addrlen) == -1)
			err(2, "bind");
		if (!strcmp(jp->proto, "tcp"))
			if (listen(s, 5) == -1)
				err(2, "listen");
		jp->sock = s;

		if (s > fdmax)
			fdmax = s;
	}

	sigemptyset(&alrm_sigset);
	sigaddset(&alrm_sigset, SIGALRM);

	/* Timeout wheel. */
	for (i = 0; i < TIMEOUT_WHEEL_SIZE; i++)
		SLIST_FIRST(&timeout_wheel[i]) = NULL;

	sa.sa_handler = &tick;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGALRM, &sa, NULL) == -1)
		err(2, "sigaction");

	alarm(1);

	/* Main loop. */
	FD_ZERO(&fds_);
	SLIST_FOREACH(jp, &janitors, next)
		FD_SET(jp->sock, &fds_);

	while (!mustquit) {
		/* Handle callouts. */
		sigprocmask(SIG_BLOCK, &alrm_sigset, NULL);
		SLIST_FOREACH_SAFE(tp, &tasks_todo, next, tmptp) {
			(*tp->func)(tp->arg);
			myfree(tp);
		}
		SLIST_FIRST(&tasks_todo) = NULL;
		sigprocmask(SIG_UNBLOCK, &alrm_sigset, NULL);

		fds = fds_;
		i = select(fdmax + 1, &fds, NULL, NULL, NULL);
		if (i == -1) {
			if (errno == EINTR)
				continue;
			err(2, "select");
		}
		SLIST_FOREACH(jp, &janitors, next) {
			if (FD_ISSET(jp->sock, &fds)) {
				fprintf(stderr, "DEBUG: activity on fd %d\n",
				    jp->sock);
				tend(jp);
			}
		}
	}

	alarm(0);
	SLIST_FOREACH_SAFE(jp, &janitors, next, tmpjp) {
		myfree(jp->ip);
		myfree(jp->port);
		myfree(jp->proto);
		SLIST_FOREACH_SAFE(action, &jp->actions, next, tmpaction) {
			myfree(action->cmd);
			myfree(action);
		}
		/*
		myfree(jp->addrinfo->ai_addr);
		myfree(jp->addrinfo->ai_canonname);
		*/
		myfree(jp->addrinfo);
		myfree(jp);
	}
	SLIST_FOREACH_SAFE(tp, &tasks_todo, next, tmptp) {
		myfree(tp->arg);
		myfree(tp);
	}
	for (i = 0; i < TIMEOUT_WHEEL_SIZE; i++) {
		SLIST_FOREACH_SAFE(tp, &timeout_wheel[i], next, tmptp) {
			myfree(tp->arg);
			myfree(tp);
		}
	}
	exit(0);
}

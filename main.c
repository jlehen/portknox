#define	_ISOC99_SOURCE
#define	_BSD_SOURCE
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <assert.h>
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
#include "faststring.h"
#include "util.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif

#define	TIMEOUT_WHEEL_SIZE	5

struct janitor {
	struct janitor *next;
	int line;
	char *ip;			
	char *port;
	char *proto;
	int timeout;
	int sock;
	char *add;
	char *delete;
	struct addrinfo *addrinfo;
};

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
	cur = timeout_wheel[slot];
	last = NULL;
	while (1) {
		if (cur == NULL)
			break;
		if (task->tick < cur->tick)
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
}

void
tick()
{
	struct task *task, *nexttask;
	int slot;

	slot = curtick % TIMEOUT_WHEEL_SIZE;
	task = timeout_wheel[slot];
	nexttask = task == NULL ? NULL : task->next;
	/*
	fprintf(stderr, "DEBUG: alarm, curtick %d, wheel slot %d, first task %p, second task %p\n", curtick, slot, task, nexttask);
	*/
	while (nexttask != NULL) {
		nexttask = task->next;
		if (task->tick > curtick)
			break;
		task = nexttask;
	}
	/*
	fprintf(stderr, "DEBUG: alarm, task %p, next task %p\n", task, nexttask);
	*/
	if (task != NULL) {
		task->next = NULL;
		tasks_todo = timeout_wheel[slot];
		timeout_wheel[slot] = nexttask;
	}
	curtick++;
	alarm(1);
}

void
await(struct janitor *janitor)
{
	int s, error;
	struct addrinfo hints, *ai;

	hints.ai_family = AF_INET;
	if (!strcmp(janitor->proto, "tcp"))
		hints.ai_socktype = SOCK_STREAM;
	else if (!strcmp(janitor->proto, "udp"))
		hints.ai_socktype = SOCK_DGRAM;
	else
		errx(1, "%s: Unknown protocol", janitor->proto);
	hints.ai_protocol = 0;
	hints.ai_flags = /*AI_ADDRCONFIG|*/AI_PASSIVE|AI_NUMERICHOST|AI_NUMERICSERV;
	hints.ai_addrlen = 0;
	hints.ai_addr = NULL;
	hints.ai_canonname = NULL;
	hints.ai_next = NULL;
	error = getaddrinfo(janitor->ip, janitor->port, &hints, &ai);
	if (error != 0)
		errx(1, "%s:%s/%s: %s", janitor->ip, janitor->port,
		    janitor->proto, gai_strerror(error));
	assert(ai->ai_next == NULL);
	janitor->addrinfo = ai;

	s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (s == -1)
		err(2, "socket");
	if (!strcmp(janitor->proto, "tcp")) {
		error = 1;
		if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &error,
		    sizeof (error)) == -1)
			err(2, "setsockopt");
	}
	if (bind(s, ai->ai_addr, ai->ai_addrlen) == -1)
		err(2, "bind");
	if (!strcmp(janitor->proto, "tcp"))
		if (listen(s, 5) == -1)
			err(2, "listen");
	janitor->sock = s;
}

void
tend(struct janitor *janitor)
{
	struct sockaddr_in sin;
	socklen_t sinlen;
	int i, error;
	char buf[1], ip[NI_MAXHOST];
	char *cmd;

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

	cmd = expand(janitor->delete, ip);
	fprintf(stderr, "DEBUG: Exec DELETE: %s\n", cmd);
	schedule(janitor->timeout + 1, run, cmd);
	cmd = expand(janitor->add, ip);
	fprintf(stderr, "DEBUG: Exec ADD: %s\n", cmd);
	run(cmd);
}

int
read_conf(const char *filename, struct janitor **jlist)
{
#define	EAT_BLANKS(p)	    do { while (isblank(*p)) { p++; } } while (0)
	FILE *f;
	char line[1024];
	char *linep, *linep2;
	struct janitor *prev, *cur;
	int linecount, jcount;
	char timeoutunit;

	/*
	 * Memory allocation in this routine is not checked.  It shouldn't
	 * fail since we're in the beginning of the program.
	 */

	f = fopen(filename, "r");
	if (f == NULL)
		err(1, "%s", filename);
	*jlist = prev = cur = NULL;
	linecount = 0;
	jcount = 0;
	while (1) {
		linecount++;
		if (fgets(line, sizeof (line), f) == NULL) {
			if (ferror(f))
				err(1, "%s", filename);
			break;
		}
		linep = line;
		while (*linep != '\n')
			linep++;
		*linep = '\0';
		linep = line;

		EAT_BLANKS(linep);
		if (*linep == '\0' || *linep == '#')
			continue;
		if (!strncmp(linep, "ADD:", 4)) {
			if (cur == NULL || cur->add != NULL)
				errx(1, "%s(%d): unexpected \"ADD\"",
				    filename, linecount);
			linep += 4;
			EAT_BLANKS(linep);
			cur->add = strdup(linep);
			fprintf(stderr, "DEBUG:    ADD: '%s'\n", cur->add);
			continue;
		}
		if (!strncmp(linep, "DELETE:", 7)) {
			if (cur == NULL || cur->delete != NULL)
				errx(1, "%s(%d): unexpected \"DELETE\"",
				    filename, linecount);
			linep += 7;
			EAT_BLANKS(linep);
			cur->delete = strdup(linep);
			fprintf(stderr, "DEBUG:    DELETE: '%s'\n", cur->delete);
			continue;
		}

		/* New janitor. */

		if (cur != NULL) {
			if (cur->add == NULL)
				errx(1, "%s(%d): missing ADD", filename,
				    linecount);
			if (cur->delete == NULL)
				errx(1, "%s(%d): missing DELETE", filename,
				    linecount);
		}

		cur = mymalloc(sizeof (*cur), "struct janitor");
		cur->add = cur->delete = NULL;
		cur->next = NULL;
		jcount++;

		linep2 = strchr(linep, ':');
		if (linep2 == NULL)
			errx(1, "%s(%d): \"ip:port/proto timeout\" expected",
			    filename, linecount);
		*linep2 = '\0';
		cur->ip = strdup(linep);
		linep = linep2 + 1;

		linep2 = strchr(linep, '/');
		if (linep2 == NULL)
			errx(1, "%s(%d): \"ip:port/proto timeout\" expected",
			    filename, linecount);
		*linep2 = '\0';
		cur->port = strdup(linep);
		linep = linep2 + 1;

		linep2 = strpbrk(linep, " \t");
		if (linep2 == NULL)
			errx(1, "%s(%d): \"ip:port/proto timeout\" expected",
			    filename, linecount);
		*linep2 = '\0';
		cur->proto = strdup(linep);
		linep = linep2 + 1;
		EAT_BLANKS(linep);

		linep2 = strpbrk(linep, " \tsmhdw"); /* Can't return NULL */
		if (linep2 == NULL)
			errx(1, "%s(%d): \"ip:port/proto timeout\" expected",
			    filename, linecount);
		timeoutunit = *linep2;
		*linep2 = '\0';
		cur->timeout = (int)strtol(linep, NULL, 10);
		if ((cur->timeout == 0 && errno == EINVAL) ||
		    ((cur->timeout == LONG_MIN || cur->timeout == LONG_MAX) &&
		    errno == ERANGE))
			err(1, "%s(%d): bad timeout", filename, linecount);
		switch (timeoutunit) {
		case 'w':
			cur->timeout *= 7;
		case 'd':
			cur->timeout *= 24;
		case 'h':
			cur->timeout *= 60;
		case 'm':
			cur->timeout *= 60;
		}

		await(cur);
		fprintf(stderr, "DEBUG: new janitor %p on fd %d (%s:%s/%s)\n",
		    cur, cur->sock, cur->ip, cur->port, cur->proto);

		if (*jlist == NULL) {
			*jlist = prev = cur;
			continue;
		}
		prev->next = cur;
		prev = cur;
	}
	fclose(f);
	return jcount;
#undef EAT_BLANKS
}

int
main(int ac, char *av[])
{
	struct sigaction sa;
	struct janitor *jlist, *jp, *jpnext;
	struct task *nexttask, *curtask;
	sigset_t sigset;
	int jcount, i, fdmax;
	fd_set fds_, fds;

	sa.sa_handler = &quit;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGQUIT, &sa, NULL) == -1)
		err(2, "sigaction");

	jcount = read_conf("portknox.conf", &jlist);
	janitors = jlist;

	/* Sockets. */
	fdmax = 0;
	for (jp = jlist; jp != NULL; jp = jp->next) {
		if (jp->sock > fdmax)
			fdmax = jp->sock;
	}

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
	for (jp = jlist; jp != NULL; jp = jp->next)
		FD_SET(jp->sock, &fds_);
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGALRM);
	while (!mustquit) {
		/* Handle callouts. */
		sigprocmask(SIG_BLOCK, &sigset, NULL);
		curtask = tasks_todo;
		while (curtask != NULL) {
			nexttask = curtask->next;
			(*curtask->func)(curtask->arg);
			myfree(curtask);
			curtask = nexttask;
		}
		tasks_todo = NULL;
		sigprocmask(SIG_UNBLOCK, &sigset, NULL);

		fds = fds_;
		i = select(fdmax + 1, &fds, NULL, NULL, NULL);
		if (i == -1) {
			if (errno == EINTR)
				continue;
			err(2, "select");
		}
		for (jp = jlist; jp != NULL; jp = jp->next) {
			if (FD_ISSET(jp->sock, &fds)) {
				fprintf(stderr, "DEBUG: activity on fd %d\n",
				    jp->sock);
				tend(jp);
			}
		}
	}
	alarm(0);
	for (jp = jlist; jp != NULL; jp = jpnext) {
		jpnext = jp->next;
		myfree(jp->ip);
		myfree(jp->port);
		myfree(jp->proto);
		myfree(jp->add);
		myfree(jp->delete);
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

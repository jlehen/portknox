/*-
 * Copyright (c) 2009 Jeremie LE HEN
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: main.c,v 1.32 2010/11/10 07:38:23 jlh Exp $
 */

#define	_ISOC99_SOURCE
#define	_BSD_SOURCE
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include "conf.h"
#include "faststring.h"
#include "freebsdqueue.h"
#include "log.h"
#include "util.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif

#ifdef SNOOP
#include <pcap.h>
#endif

#define	TIMEOUT_WHEEL_SIZE	59

static struct janitorlist janitors;
static struct tasklist timeout_wheel[TIMEOUT_WHEEL_SIZE];
static struct tasklist tasks_todo;
static unsigned int curtick;
static int mustquit = 0;
static int daemonized = 0;
static int debug = 0;
static sigset_t alrm_sigset;

static void
usage(const char *basename)
{

	fprintf(stderr,
	    "Usage: %s [-c configfile] [-dEhS] [-p pidfile] [-s facility]\n"
	    "Options:\n"
	    "  -c	Set config file (defaults to \"portknox.conf\").\n"
	    "  -d	Debug mode (don't fork and log on stderr as well).\n"
	    "  -E	Show configuration file example.\n"
	    "  -h	Show this help.\n"
	    "  -p	Set pid file (defaults to \"portknox.pid\").\n"
	    "  -s	Set syslog facility.\n"
	    "  -S	Show configuration file syntax.\n"
	    "Valid facilities: auth, daemon, securiry, user, local0 "
	    "... local7.\n",
	    basename);
}

static void
mylog(int status, int prio, const struct janitor *j, const char *errstr,
    const char *fmt, ...)
{
	va_list ap;
	int i;
	char errbuf[128];	/* Should be enough */
	static int warns = 0;

	va_start(ap, fmt);
	i = vsnprintf(errbuf, sizeof (errbuf), fmt, ap);
	va_end(ap);
	if (j != NULL && errstr != NULL)
		syslog(prio, "(janitor %d) %s: %s", j->id, errbuf, errstr);
	else if (j != NULL && errstr == NULL)
		syslog(prio, "(janitor %d) %s", j->id, errbuf);
	else if (j == NULL && errstr != NULL)
		syslog(prio, "%s: %s", errbuf, errstr);
	else /* j == NULL && errstr == NULL */
		syslog(prio, "%s", errbuf);
	if (i >= (int)sizeof (errbuf))
		syslog(prio, "previous message has been truncated");

	if (daemonized || debug) {
		if (status >= 0)
			exit(status);
		return;
	}

	if (status >= 0)
		err(status, "Error occured, check system log");
	if (warns++ == 0)
		warn("Warning occured, check system log");
}

#define	e(s, j, fmt, ...)	\
    mylog(s, LOG_ERR, j, strerror(errno), fmt, ## __VA_ARGS__)
#define	ex(s, j, fmt, ...)	\
    mylog(s, LOG_ERR, j, NULL, fmt, ## __VA_ARGS__)
#define	w(j, fmt, ...)		\
    mylog(-1, LOG_WARNING, j, strerror(errno), fmt, ## __VA_ARGS__)
#define	wx(j, fmt, ...)		\
    mylog(-1, LOG_WARNING, j, NULL, fmt, ## __VA_ARGS__)
#define n(j, fmt, ...)		\
    mylog(-1, LOG_NOTICE, j, strerror(errno), fmt, ## __VA_ARGS__)
#define	nx(j, fmt, ...)		\
    mylog(-1, LOG_NOTICE, j, NULL, fmt, ## __VA_ARGS__)
#define	i(j, fmt, ...)		\
    mylog(-1, LOG_INFO, j, strerror(errno), fmt, ## __VA_ARGS__)
#define	ix(j, fmt, ...)		\
    mylog(-1, LOG_INFO, j, NULL, fmt, ## __VA_ARGS__)

void
quit(int s)
{

	nx(NULL, "Received signal %s", s);
	mustquit = 1;
}

uint16_t
hash(const char *s)
{
	uint16_t h;
	uint16_t a, b;

	h = 0xB73F;
	a = 0x82;
	b = 0x53 << 8;
	while (*s) {
		h = (h << 5) + *s++;
		a = h >> 7;
		b = h << 11;
		h = (h ^ b) >> 2 ^ a;
	}
	return h;
}

/*
 * Fork and split command into argument vector in child, then exec.
 */
void
run(char **argv)
{
	struct janitor *jp;
	pid_t pid;

	pid = fork();
	if (pid == -1) {
		warn("Can't fork");
		return;
	}
	if (pid > 0)
		return;

	SLIST_FOREACH(jp, &janitors, next)
		close(jp->sock);

	if (execvp(argv[0], argv) == -1)
		w(NULL, "Can't exec '%s'", argv[0]);
	exit(127);
}

/*
 * Call run() and free argument.
 */
void
runcallout(void *p)
{
	char **ap;

	run(p);
	for (ap = p; *ap != NULL; ap++)
		myfree(*ap);
	myfree(p);
}

/*
 * Expand escape characters in string:
 *     %h -> src ip
 *     %n -> tending count
 */
char **
expand(int argc, char **argv, const char *ip, const struct janitor *j)
{
	faststring *str;
	char *p;
	char *countstr;
	char **res, **rp;

	res = mymalloc(argc * sizeof (*argv), "argv array");
	for (rp = res; *argv != NULL; argv++, rp++) {
		str = faststring_alloc(32);
		p = *argv;
		while (*p != '\0') {
			if (*p != '%') {
				faststring_strncat(str, p++, 1);
				continue;
			}
			p++;
			switch (*p) {
			case '\0':
				faststring_strcat(str, "%");
				*rp = faststring_export(str);
				continue;
			case '%':
				faststring_strcat(str, "%");
				break;
			case 'h':
				faststring_strcat(str, ip);
				break;
			case 'n':
				(void)asprintf(&countstr, "%u", j->usecount);
				if (countstr == NULL)
					e(2, j, "Command string expansion");
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
		*rp = faststring_export(str);
	 }
	 *rp = NULL;
	 return res;
}

/*
 * Schedule a task!
 */
void
schedule(struct task *task)
{
	struct task *tp;
	int slot;

	/*
	 * Insert in timeout wheel.
	 */
	task->tick = curtick + task->timeout;
	slot = task->tick % TIMEOUT_WHEEL_SIZE;

	LIST_FOREACH(tp, &timeout_wheel[slot], ticklist) {
		if (tp == NULL)
			break;
		if (tp->tick > task->tick)
			break;
	}
	if (tp == NULL)
		LIST_INSERT_HEAD(&timeout_wheel[slot], task, ticklist);
	else
		LIST_INSERT_BEFORE(tp, task, ticklist);
}

/*
 * Execute callouts and rotate janitors' usage wheel.
 */
void
tick()
{
	struct task *prevtp, *tp;
	struct janitor *jp;
	int slot;
	int i;

	alarm(1);
	curtick++;

	/*
	 * Extract actions to perform on this tick.
	 */
	slot = curtick % TIMEOUT_WHEEL_SIZE;
	prevtp = NULL;
	i = 0;
	LIST_FOREACH(tp, &timeout_wheel[slot], ticklist) {
		if (tp->tick > curtick)
			break;
		prevtp = tp;
		i++;
	}
	if (prevtp != NULL) {
		LIST_NEXT(prevtp, ticklist) = NULL;
		LIST_FIRST(&tasks_todo) = LIST_FIRST(&timeout_wheel[slot]);
		LIST_FIRST(&timeout_wheel[slot]) = tp;
	}

	/*
	 * Rotate janitor's usage wheel.
	 */
	SLIST_FOREACH(jp, &janitors, next) {
		slot = curtick % jp->uswheelsz;

		jp->uscur -= jp->uswheel[slot];
		jp->uswheel[slot] = 0;
	}

}

/*
 * Tend the incoming connection:
 *     - Check max usage;
 *     - Handle dup requests;
 *     - Update usage wheel;
 *     - Perform immediate actions and schedule delayed actions.
 */
void
tend(struct janitor *janitor)
{
	struct sockaddr_in sin;
	socklen_t sinlen;
	int i, slot, error;
	char buf[1], ipstr[NI_MAXHOST];
	uint32_t ip;
	char **argv;
	struct action *action;
	struct ushashbucket *ushbucket;
	struct task *task;
	uint16_t hval;
#ifdef SNOOP
	const u_char *pkt;
	struct in_addr inaddr;
	struct pcap_pkthdr *pkthdr;
#endif

	/* Shutdown warnings. */
	ip = 0;
	ushbucket = NULL;

	/*
	 * Get IP address.
	 */
	switch (janitor->type) {
	case LISTENING_JANITOR:
		sinlen = sizeof (sin);
		if (janitor->u.listen.addrinfo->ai_protocol == IPPROTO_TCP) {
			i = accept(janitor->sock, (struct sockaddr *)&sin,
			    (socklen_t *)&sinlen);
			if (i == -1) {
				w(janitor, "Could not accept connection");
				return;
			}
			if (shutdown(i, SHUT_RDWR) == -1)
				w(janitor, "Could not shutdown connection");
			if (close(i) == -1)
				w(janitor, "Could not close socket");
		} else {
			i = recvfrom(janitor->sock, buf, 1, 0,
			    (struct sockaddr *)&sin, (socklen_t *)&sinlen);
			if (i == -1) {
				w(janitor, "Could not receive datagram");
				return;
			}
		}

		ip = sin.sin_addr.s_addr;
		error = getnameinfo((struct sockaddr *)&sin, sizeof (sin),
		    ipstr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
		if (error != 0) {
			wx(janitor, "Could not resolve hostname: %s",
			    gai_strerror(error));
			return;
		}
		break;
#ifdef SNOOP
	case SNOOPING_JANITOR:
		/* Cannot return 0. */
		if (-1 == pcap_next_ex(janitor->u.snoop.pcap, &pkthdr, &pkt)) {
			wx(janitor, "Could snoop packet: %s",
			    pcap_geterr(janitor->u.snoop.pcap));
			return;
		}
/* Ethernet header len + offset in IP header */
#define	SRCIP_OFFSET	14 + 12
		memcpy(&inaddr, pkt + SRCIP_OFFSET, sizeof (inaddr));
		ip = inaddr.s_addr;
		strcpy(ipstr, inet_ntoa(inaddr));
		break;
#endif
	}

	/*
	 * Check usage wheel and usage hash for dup requests.
	 */
	sigprocmask(SIG_BLOCK, &alrm_sigset, NULL);
	if (janitor->uscur == janitor->usmax) {
		nx(janitor, "Max usage reached, can't fulfill request from %s",
		    ipstr);
		return;
	}

	switch (janitor->dup) {
	case DUP_EXEC:
		ushbucket = NULL;
		break;

	case DUP_IGNORE:
	case DUP_RESET:
		hval = hash(ipstr);
		slot = hval % janitor->ushashsz;

		LIST_FOREACH(ushbucket, &janitor->ushash[slot], slotlist)
			if (ushbucket->ip == ip)
				break;

		if (ushbucket == NULL) {
			ushbucket = mymalloc(sizeof (*ushbucket),
			    "usage hash bucket");
			ushbucket->ip = ip;
			ushbucket->hash = hval;
			TAILQ_INIT(&ushbucket->tasks);
			LIST_INSERT_HEAD(&janitor->ushash[slot], ushbucket,
			    slotlist);
			break;
		}

		if (janitor->dup == DUP_IGNORE) {
			ix(janitor, "Ignore duplicate request from %s", ipstr);
			sigprocmask(SIG_UNBLOCK, &alrm_sigset, NULL);
			return;
		}
		/* janitor->dup == DUP_RESET */
		ix(janitor, "Resetting after duplicate request from %s", ipstr);
		TAILQ_FOREACH(task, &ushbucket->tasks, siblinglist) {
			LIST_REMOVE(task, ticklist);
			schedule(task);
		}

		return;
	}

	/*
	 * From here onward, DUP_EXEC or no pending tasks for IP address.
	 */
	ix(janitor, "Tending %s", ipstr);

	slot = curtick % janitor->uswheelsz;
	janitor->uswheel[slot]++;
	janitor->uscur++;

	/* Perform and schedule actions.  */
	SLIST_FOREACH(action, &janitor->actions, next) {
		argv = expand(action->argc, action->argv, ipstr, janitor);
		if (action->timeout == 0)
			runcallout(argv);
		else {
			task = mymalloc(sizeof (*task), "struct task");
			task->ushashbucket = ushbucket;
			task->janitor = janitor;
			task->tick = 0;
			task->timeout = action->timeout + 1;
			task->func = runcallout;
			task->arg = argv;

			/*
			 * Insert in usage hash.
			 */
			if (ushbucket != NULL)
				/* Actions sorted by timeout janitor. */
				TAILQ_INSERT_TAIL(&ushbucket->tasks, task,
				    siblinglist);

			schedule(task);
		}
	}

	sigprocmask(SIG_UNBLOCK, &alrm_sigset, NULL);
	janitor->usecount++;
}

int
main(int ac, char *av[])
{
	const char *configfile, *pidfile;
	char **ap;
	struct sigaction sa;
	struct janitor *jp, *tmpjp;
	struct task *tp, *tmptp;
	struct action *action, *tmpaction;
	int opt, jcount, i, s, fdmax, slot;
	struct addrinfo *ai;
	fd_set fds_, fds;
	FILE *pidfh;
	char pid[16];
#ifdef SNOOP
	pcap_t *pcapp;
	char pcaperr[PCAP_ERRBUF_SIZE];
#endif

	configfile = "portknox.conf";
	pidfile = "portknox.pid";
	while (1) {
		opt = getopt(ac, av, ":c:dEhp:s:S");
		if (opt == -1)
			break;
		switch (opt) {
		case 'c':
			configfile = optarg;
			break;
		case 'd':
			debug = 1;
			setDebug();
			break;
		case 'E':
			show_conf_example();
			exit(0);
			break;
		case 'h':
			usage(basename(av[0]));
			exit(0);
			break;
		case 'p':
			pidfile = optarg;
			break;
		case 's':
			setLogFacility(optarg);
			break;
		case 'S':
			show_conf_syntax();
			exit(0);
			break;
		case ':':
			fprintf(stderr, "Unknown option '%c'", optopt);
			usage(basename(av[0]));
			exit(1);
			break;
		}
	}

	openLog(basename(av[0]));

	sa.sa_handler = &quit;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGQUIT, &sa, NULL) == -1)
		e(2, NULL, "sigaction");
	if (sigaction(SIGTERM, &sa, NULL) == -1)
		e(2, NULL, "sigaction");
	if (sigaction(SIGINT, &sa, NULL) == -1)
		e(2, NULL, "sigaction");

	jcount = read_conf(configfile, &janitors);

	fdmax = 0;
	SLIST_FOREACH(jp, &janitors, next) {
		switch (jp->type) {
		case LISTENING_JANITOR:
			ai = jp->u.listen.addrinfo;
			s = socket(ai->ai_family, ai->ai_socktype,
			    ai->ai_protocol);
			if (s == -1)
				e(2, jp, "socket");
			if (!strcmp(jp->u.listen.proto, "tcp")) {
				i = 1;
				if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &i,
				    sizeof (i)) == -1)
					e(2, jp, "setsockopt");
			}
			if (bind(s, ai->ai_addr, ai->ai_addrlen) == -1)
				e(2, jp, "bind");
			if (!strcmp(jp->u.listen.proto, "tcp"))
				if (listen(s, 5) == -1)
					e(2, jp, "listen");
			jp->sock = s;
			break;
#ifdef SNOOP
		case SNOOPING_JANITOR:
			pcapp = pcap_open_live(jp->u.snoop.iface, 1518, 0, 50,
			    pcaperr);
			if (pcapp == NULL)
				ex(2, jp, "pcap_open_live(%s): %s",
				    jp->u.snoop.iface, pcaperr);
			if (pcap_datalink(pcapp) != DLT_EN10MB)
				ex(2, jp, "%s is not ethernet",
				    jp->u.snoop.iface);
			if (-1 == pcap_compile(pcapp, &jp->u.snoop.bpfpg,
			    jp->u.snoop.filter, 0, 0))
				ex(2, jp, "Couldn't compile BPF filter: %s",
				    jp->u.snoop.filter);
			if (-1 == pcap_setfilter(pcapp, &jp->u.snoop.bpfpg))
				ex(2, jp, "pcap_setfilter: %s",
				    pcap_geterr(pcapp));
			if (-1 == pcap_setdirection(pcapp, PCAP_D_IN))
				ex(2, jp, "pcap_setdirection: %s", pcaperr);
			/*
			if (-1 == pcap_setnonblock(pcapp, 1, pcaperr))
				errx(2, "pcap_setnonblock: %s", pcaperr);
			*/
			jp->u.snoop.pcap = pcapp;
			jp->sock = pcap_get_selectable_fd(pcapp);
			break;
#endif
		}
		if (jp->sock > fdmax)
			fdmax = jp->sock;
	}

	sigemptyset(&alrm_sigset);
	sigaddset(&alrm_sigset, SIGALRM);

	/* Timeout wheel. */
	for (i = 0; i < TIMEOUT_WHEEL_SIZE; i++)
		LIST_INIT(&timeout_wheel[i]);
	LIST_INIT(&tasks_todo);

	sa.sa_handler = &tick;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGALRM, &sa, NULL) == -1)
		e(2, NULL, "sigaction");

	pidfh = fopen(pidfile, "w");
	if (pidfh == NULL)
		e(2, NULL, "Cannot open '%s'", pidfile);
	if (debug == 0) {
		daemon(1, 0);
		daemonized = 1;
	}
	i = snprintf(pid, sizeof (pid), "%li\n", (long int)getpid());
	fputs(pid, pidfh);
	fclose(pidfh);

	alarm(1);

	/* Main loop. */
	FD_ZERO(&fds_);
	SLIST_FOREACH(jp, &janitors, next)
		FD_SET(jp->sock, &fds_);

	while (!mustquit) {
		/* Handle callouts. */
		sigprocmask(SIG_BLOCK, &alrm_sigset, NULL);
		LIST_FOREACH_SAFE(tp, &tasks_todo, ticklist, tmptp) {
			(*tp->func)(tp->arg);
			
			jp = tp->janitor;
			/* Remove task from usage hash once performed. */
			if (jp->dup == DUP_IGNORE || jp->dup == DUP_RESET) {
				TAILQ_REMOVE(&tp->ushashbucket->tasks, tp,
				    siblinglist);
				if (TAILQ_EMPTY(&tp->ushashbucket->tasks)) {
					slot = tp->ushashbucket->hash %
					    jp->ushashsz;
					LIST_REMOVE(tp->ushashbucket, slotlist);
					myfree(tp->ushashbucket);
				}
			}

			myfree(tp);
		}
		LIST_INIT(&tasks_todo);
		sigprocmask(SIG_UNBLOCK, &alrm_sigset, NULL);

		fds = fds_;
		i = select(fdmax + 1, &fds, NULL, NULL, NULL);
		if (i == -1) {
			if (errno == EINTR)
				continue;
			e(2, NULL, "select");
		}
		SLIST_FOREACH(jp, &janitors, next) {
			if (FD_ISSET(jp->sock, &fds))
				tend(jp);
		}
	}

	alarm(0);
	nx(NULL, "Exiting");
	LIST_FOREACH_SAFE(tp, &tasks_todo, ticklist, tmptp) {
		myfree(tp->ushashbucket);
		myfree(tp->arg);
		myfree(tp);
	}
	for (i = 0; i < TIMEOUT_WHEEL_SIZE; i++) {
		LIST_FOREACH_SAFE(tp, &timeout_wheel[i], ticklist, tmptp) {
			myfree(tp->ushashbucket);
			myfree(tp->arg);
			myfree(tp);
		}
	}
	SLIST_FOREACH_SAFE(jp, &janitors, next, tmpjp) {
		switch (jp->type) {
		case LISTENING_JANITOR:
			myfree(jp->u.listen.ip);
			myfree(jp->u.listen.port);
			myfree(jp->u.listen.proto);
			myfree(jp->u.listen.addrinfo);
			shutdown(jp->sock, SHUT_RDWR);
			close(jp->sock);
			break;
#ifdef SNOOP
		case SNOOPING_JANITOR:
			myfree(jp->u.snoop.iface);
			myfree(jp->u.snoop.filter);
			pcap_close(jp->u.snoop.pcap);
			break;
#endif
		}
		SLIST_FOREACH_SAFE(action, &jp->actions, next, tmpaction) {
			for (ap = action->argv; *ap != NULL; ap++)
				myfree(*ap);
			myfree(action->argv);
			myfree(action);
		}
		/*
		 * No need to free hash buckets and tasks from hash,
		 * they've been above.
		 */
		myfree(jp->ushash);
		/*
		 * TODO: 
		 * for (i = 0; i < janitor->ushashsz; i++)
		 *     LIST_FOREACH_SAFE(&janitor->ushash[])
		 *         free
		 */
		myfree(jp);
	}
	exit(0);
}

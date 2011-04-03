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
 * $Id: main.c,v 1.39 2011/04/03 12:10:29 jlh Exp $
 */

#define	_ISOC99_SOURCE
#define	_BSD_SOURCE
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include "conf.h"
#include "faststring.h"
#include "freebsdqueue.h"
#include "hash.h"
#include "log.h"
#include "util.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif

#ifdef SNOOP
#include <pcap.h>
#endif

struct action_callout_args {
	char **argv;
	struct janitor *janitor;
};

struct state_callout_args {
	uint32_t ip;
	int state:31;
	int set:1;
	struct janitor *janitor;
};

typedef uint32_t    state_t;
#define	TIMEOUT_WHEEL_SIZE	59

static struct janitorlist janitors;
static struct tasklist timeout_wheel[TIMEOUT_WHEEL_SIZE];
static struct tasklist tasks_todo;	/* Tasks to execute on current tick */ 
static unsigned int curtick;
static int mustquit = 0;
static int debug = 0;
static sigset_t alrm_sigset;
static int devnull = 0;
static struct confinfo confinfo;
static struct hash *states = NULL;	/* Per-IP state array */

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
quit(int s)
{

	nx(NULL, "Received signal %d", s);
	mustquit = 1;
}

/*
 * Fork and split command into argument vector in child, then exec.
 */
static void
run(char **argv, struct janitor *janitor)
{
	struct janitor *j;
	pid_t pid;
	char **p;
	faststring fs;

	if (janitor->verbose & VERBOSE_ACTION) {
		FASTSTRING_INIT(&fs);
		faststring_alloc(&fs, 128);
		for (p = argv; *p != NULL; p++) {
			faststring_strcat(&fs, *p);
			faststring_strcat(&fs, " ");
		}
		verb(janitor, "[action] %s", faststring_peek(&fs));
		faststring_free(&fs);
	}
	pid = fork();
	if (pid == -1) {
		warn("Can't fork");
		return;
	}
	if (pid > 0)
		return;

	SLIST_FOREACH(j, &janitors, next)
		close(j->sock);
	dup2(devnull, 0);
	dup2(devnull, 1);
	dup2(devnull, 2);

	if (execvp(argv[0], argv) == -1)
		w(NULL, "Can't exec '%s'", argv[0]);
	exit(127);
}

/*
 * Call run() and free argument.
 */
static void
action_callout(void *p)
{
	struct action_callout_args *args;
	char **ap;

	args = p;
	run(args->argv, args->janitor);
	for (ap = args->argv; *ap != NULL; ap++)
		myfree(*ap);
	myfree(args);
}

static inline int
check_state(uint32_t ip, int state)
{
	state_t *states4ip;

	assert(states != NULL);
	states4ip = hash_get_val_sk(states, ip, NULL);
	if (states4ip == NULL)
		return 0;
	return states4ip[state];
}

#define	IP_VAARGS(ip)	    \
    (ip) & 0xff, ((ip) >> 8) & 0xff, ((ip) >> 16) & 0xff, (ip) >> 24
static inline void
set_state(uint32_t ip, int state, int set, struct janitor *janitor)
{
	register int i;
	state_t s, *states4ip;

	assert(confinfo.nstates > 0);
	assert(states != NULL);
	if (janitor->verbose & VERBOSE_STATE)
		verb(janitor, "[state] %s state %d for %d.%d.%d.%d",
		    set ? "set" : "unset", state, IP_VAARGS(ip));
	states4ip = hash_get_val_sk(states, ip, NULL);
	/* If we unset a state, an entry must exist. */
	assert(set != 0 || states4ip != NULL);
	if (states4ip == NULL) {
		if (janitor->verbose & DEBUG_STATE)
			verb(janitor, "[debugstate] allocating states for "
			    "%d.%d.%d.%d", IP_VAARGS(ip));
		states4ip = mymalloc(sizeof (state_t) * confinfo.nstates,
		    "state_t array");
		for (i = 0; i < confinfo.nstates; i++)
			states4ip[i] = 0;
		(void)hash_add_sk(states, ip, states4ip);
	}
	if (set)
		states4ip[state]++;
	else {
		assert(states4ip[state] > 0);
		states4ip[state]--;
	}

	if (set)
		return;
	s = 0;
	for (i = 0; i < confinfo.nstates; i++)
		s |= states4ip[i];
	if (s == 0) {
		if (janitor->verbose & DEBUG_STATE)
			verb(janitor, "[debugstate] destroying states for "
			    "%d.%d.%d.%d", IP_VAARGS(ip));
		hash_remove_sk(states, ip, myfree);
	}
}

static void
state_callout(void *p)
{
	struct state_callout_args *a;

	a = (struct state_callout_args *)p;
	set_state(a->ip, a->state, a->set, a->janitor);
	myfree(a);
}

/*
 * Expand escape characters in string:
 *     %h -> src ip
 *     %n -> tending count
 */
static char **
expand(int argc, char **argv, const char *ip, const struct janitor *j)
{
	faststring str = FASTSTRING_INITIALIZER;
	char *p;
	char *countstr;
	char **res, **rp;

	res = mymalloc(argc * sizeof (*argv), "argv array");
	for (rp = res; *argv != NULL; argv++, rp++) {
		faststring_alloc(&str, 32);
		p = *argv;
		while (*p != '\0') {
			if (*p != '%') {
				faststring_strncat(&str, p++, 1);
				continue;
			}
			p++;
			switch (*p) {
			case '\0':
				faststring_strcat(&str, "%");
				*rp = faststring_export(&str);
				continue;
			case '%':
				faststring_strcat(&str, "%");
				break;
			case 'h':
				faststring_strcat(&str, ip);
				break;
			case 'n':
				(void)asprintf(&countstr, "%u", j->usecount);
				if (countstr == NULL)
					e(2, j, "Command string expansion");
				faststring_strcat(&str, countstr);
				myfree(countstr);
				break;
			default:
				faststring_strcat(&str, "%");
				faststring_strncat(&str, p, 1);
				break;
			}
			p++;
		}
		*rp = faststring_export(&str);
	 }
	 *rp = NULL;
	 return res;
}

/*
 * Schedule a task!
 */
static void
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
static void
tick()
{
	struct task *prevtp, *tp;
	struct janitor *j;
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
		if (tp->janitor->verbose & VERBOSE_TASK)
			verb(tp->janitor, "[task] callout at tick %u", curtick);
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
	SLIST_FOREACH(j, &janitors, next) {
		slot = curtick % j->uswheelsz;

		j->uscur -= j->uswheel[slot];
		j->uswheel[slot] = 0;
	}

}

/*
 * Tend the incoming connection:
 *     - Check max usage and required state;
 *     - Handle dup requests;
 *     - Update usage wheel;
 *     - Perform immediate actions and schedule delayed actions.
 */
static void
tend(struct janitor *janitor)
{
	struct sockaddr_in sin;
	socklen_t sinlen;
	int i, slot, error;
	char buf[1], ipstr[NI_MAXHOST];
	uint32_t ip;
	struct action *action;
	struct hashbucket *hb;
	struct task *task;
	struct taskqueue *taskq;
	struct action_callout_args *aca;
	struct state_callout_args *sca;
#ifdef SNOOP
	const u_char *pkt;
	struct in_addr inaddr;
	struct pcap_pkthdr *pkthdr;
#endif

	/* Shutdown warnings. */
	i = 0;
	ip = 0;
	hb = NULL;
	taskq = NULL;
	aca = NULL;
	sca = NULL;

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
	 * Check usage wheel and ip2tasks mapping for dup requests.
	 * XXX Note that for reset janitors, clients with pending tasks
	 * should be able to bypass max usage and required state.
	 */
	sigprocmask(SIG_BLOCK, &alrm_sigset, NULL);
	if (janitor->uscur == janitor->usmax) {
		nx(janitor, "Max usage reached, can't fulfill request from %s",
		    ipstr);
		return;
	}

	if (janitor->reqstate >= 0) {
		if (check_state(ip, janitor->reqstate) == 0) {
			ix(janitor, "Missing required state for request from %s",
			    ipstr);
			return;
		}
	} else if (janitor->verbose & DEBUG_STATE)
		verb(janitor, "[debugstate] no state required");

	switch (janitor->dup) {
	case DUP_EXEC:
		assert(janitor->ip2tasks == NULL);
		hb = NULL;
		break;

	case DUP_IGNORE:
	case DUP_RESET:
		assert(janitor->ip2tasks != NULL);
		hb = hash_get_sk(janitor->ip2tasks, ip);

		if (hb == NULL) {
			taskq = mymalloc(sizeof (*taskq), "taskqueue");
			TAILQ_INIT(taskq);
			hash_add_sk(janitor->ip2tasks, ip, taskq);
			break;
		}

		/* There were remaining pending actions for this IP. */

		if (janitor->dup == DUP_IGNORE) {
			ix(janitor, "Ignore duplicate request from %s", ipstr);
			sigprocmask(SIG_UNBLOCK, &alrm_sigset, NULL);
			return;
		}
		/* janitor->dup == DUP_RESET */
		ix(janitor, "Resetting after duplicate request from %s", ipstr);
		taskq = hashbucket_get_val(hb);
		TAILQ_FOREACH(task, taskq, siblinglist) {
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
		if (action->type == ACTION) {
			aca = mymalloc(sizeof (*aca),
			    "struct action_callout_args");
			aca->argv = expand(action->u.a.argc, action->u.a.argv,
			    ipstr, janitor);
			aca->janitor = janitor;
		}
		else if (action->type == STATE) {
			sca = mymalloc(sizeof (*sca),
			    "struct state_callout_args");
			sca->ip = ip;
			sca->state = action->u.s.state;
			sca->set = action->u.s.set;
			sca->janitor = janitor;
		}

		if (action->timeout == 0) {
			if (janitor->verbose & VERBOSE_TASK)
				verb(janitor, "[task] immediate callout "
				    "at tick %u", curtick);

			if (action->type == ACTION)
				action_callout(aca);
			else if (action->type == STATE)
				state_callout(sca);
		} else {
			task = mymalloc(sizeof (*task), "struct task");
			task->bucket = hb;
			task->janitor = janitor;
			task->tick = 0;
			task->timeout = action->timeout + 1;
			if (action->type == ACTION) {
				task->func = action_callout;
				task->arg = aca;
			} else if (action->type == STATE) {
				task->func = state_callout;
				task->arg = sca;
			}

			/*
			 * Insert in ip2tasks mapping.
			 */
			if (hb != NULL) {
				/* Actions are sorted by timeout in janitor. */
				assert(taskq != NULL);
				TAILQ_INSERT_TAIL(taskq, task, siblinglist);
			}

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
	struct janitor *j, *j_;
	struct task *t, *t_;
	struct taskqueue *tq;
	struct action *a, *a_;
	int opt, i, s, fdmax;
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
			exitOnError();
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

	sa.sa_handler = SIG_IGN;
	sa.sa_flags = SA_NOCLDWAIT;
	if (sigaction(SIGCHLD, &sa, NULL) == -1)
		e(2, NULL, "sigaction");

	read_conf(configfile, &janitors, &confinfo);
	if (confinfo.nstates > 0)
		states = hash_create(confinfo.usmaxtotal); /* XXX: Better value? */

	fdmax = 0;
	SLIST_FOREACH(j, &janitors, next) {
		switch (j->type) {
		case LISTENING_JANITOR:
			ai = j->u.listen.addrinfo;
			s = socket(ai->ai_family, ai->ai_socktype,
			    ai->ai_protocol);
			if (s == -1)
				e(2, j, "socket");
			if (!strcmp(j->u.listen.proto, "tcp")) {
				i = 1;
				if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &i,
				    sizeof (i)) == -1)
					e(2, j, "setsockopt");
			}
			if (bind(s, ai->ai_addr, ai->ai_addrlen) == -1)
				e(2, j, "bind");
			if (!strcmp(j->u.listen.proto, "tcp"))
				if (listen(s, 5) == -1)
					e(2, j, "listen");
			j->sock = s;
			break;
#ifdef SNOOP
		case SNOOPING_JANITOR:
			pcapp = pcap_open_live(j->u.snoop.iface, 1518, 0, 50,
			    pcaperr);
			if (pcapp == NULL)
				ex(2, j, "pcap_open_live(%s): %s",
				    j->u.snoop.iface, pcaperr);
			if (pcap_datalink(pcapp) != DLT_EN10MB)
				ex(2, j, "%s is not ethernet",
				    j->u.snoop.iface);
			if (-1 == pcap_compile(pcapp, &j->u.snoop.bpfpg,
			    j->u.snoop.filter, 0, 0))
				ex(2, j, "Couldn't compile BPF filter: %s",
				    j->u.snoop.filter);
			if (-1 == pcap_setfilter(pcapp, &j->u.snoop.bpfpg))
				ex(2, j, "pcap_setfilter: %s",
				    pcap_geterr(pcapp));
			if (-1 == pcap_setdirection(pcapp, PCAP_D_IN))
				ex(2, j, "pcap_setdirection: %s", pcaperr);
			/*
			if (-1 == pcap_setnonblock(pcapp, 1, pcaperr))
				errx(2, "pcap_setnonblock: %s", pcaperr);
			*/
			j->u.snoop.pcap = pcapp;
			j->sock = pcap_get_selectable_fd(pcapp);
			break;
#endif
		}
		if (j->sock > fdmax)
			fdmax = j->sock;
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
		exitOnError();
	}
	i = snprintf(pid, sizeof (pid), "%li\n", (long int)getpid());
	fputs(pid, pidfh);
	fclose(pidfh);

	devnull = open("/dev/null", O_RDWR, 0);
	if (devnull == -1)
		e(2, NULL, "Cannot open '/dev/null'");

	alarm(1);

	/* Main loop. */
	FD_ZERO(&fds_);
	SLIST_FOREACH(j, &janitors, next)
		FD_SET(j->sock, &fds_);

	while (!mustquit) {
		/* Handle callouts. */
		sigprocmask(SIG_BLOCK, &alrm_sigset, NULL);
		LIST_FOREACH_SAFE(t, &tasks_todo, ticklist, t_) {
			(*t->func)(t->arg);
			
			j = t->janitor;
			/* Remove task from usage hash once performed. */
			if (j->dup == DUP_IGNORE || j->dup == DUP_RESET) {
				assert(t->bucket != NULL);
				tq = hashbucket_get_val(t->bucket);
				TAILQ_REMOVE(tq, t, siblinglist);
				if (TAILQ_EMPTY(tq))
					hashbucket_remove(j->ip2tasks, t->bucket,
					    &myfree);
			}

			myfree(t);
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
		SLIST_FOREACH(j, &janitors, next) {
			if (FD_ISSET(j->sock, &fds))
				tend(j);
		}
	}

	alarm(0);
	nx(NULL, "Exiting");
	/*
	LIST_FOREACH_SAFE(t, &tasks_todo, ticklist, tmptp) {
		myfree(t->ushashbucket);
		myfree(t->arg);
		myfree(t);
	}
	for (i = 0; i < TIMEOUT_WHEEL_SIZE; i++) {
		LIST_FOREACH_SAFE(t, &timeout_wheel[i], ticklist, tmptp) {
			myfree(t->ushashbucket);
			myfree(t->arg);
			myfree(t);
		}
	}
	*/
	SLIST_FOREACH_SAFE(j, &janitors, next, j_) {
		switch (j->type) {
		case LISTENING_JANITOR:
			myfree(j->u.listen.ip);
			myfree(j->u.listen.port);
			myfree(j->u.listen.proto);
			myfree(j->u.listen.addrinfo);
			shutdown(j->sock, SHUT_RDWR);
			close(j->sock);
			break;
#ifdef SNOOP
		case SNOOPING_JANITOR:
			myfree(j->u.snoop.iface);
			myfree(j->u.snoop.filter);
			pcap_close(j->u.snoop.pcap);
			break;
#endif
		}
		SLIST_FOREACH_SAFE(a, &j->actions, next, a_) {
			if (a->type == ACTION)
				for (ap = a->u.a.argv; *ap != NULL; ap++)
					myfree(*ap);
			myfree(a->u.a.argv);
			myfree(a);
		}
		/*
		 * No need to free hash buckets and tasks from hash,
		 * we did it above.
		 */
		hash_destroy(j->ip2tasks, myfree);
		/*
		 * TODO: 
		 * for (i = 0; i < janitor->ushashsz; i++)
		 *     LIST_FOREACH_SAFE(&janitor->ushash[])
		 *         free
		 */
		myfree(j);
	}
	exit(0);
}

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

#ifdef SNOOP
#include <pcap.h>
#endif

#define	TIMEOUT_WHEEL_SIZE	5

struct task {
	LIST_ENTRY(task) wheel;
	unsigned int tick;
	void (*func)(void *);
	void *arg; 
};

LIST_HEAD(tasklist, task);

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
run(char *cmd)
{
	char *sp;
	char **argv, **ap;
	int asize;
	struct janitor *jp;
	pid_t pid;

	fprintf(stderr, "DEBUG: gonna run '%s'\n", (char *)cmd);
	pid = fork();
	if (pid == -1) {
		warn("Can't fork");
		return;
	}
	if (pid > 0)
		return;

	sp = cmd;
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
	exit(127);
}

void
runcallout(void *p)
{

	run(p);
	myfree(p);
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

	prevtp = NULL;
	LIST_FOREACH(tp, &timeout_wheel[slot], wheel) {
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
		LIST_FIRST(&timeout_wheel[slot]) = task;
	else
		LIST_NEXT(prevtp, wheel) = task;
	LIST_NEXT(task, wheel) = tp;
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
	fprintf(stderr, "DEBUG: alarm, curtick %d, wheel slot %d, first task %p\n", curtick, slot, LIST_FIRST(&timeout_wheel[slot]));
	LIST_FOREACH(tp, &timeout_wheel[slot], wheel) {
		if (tp->tick > curtick)
			break;
		prevtp = tp;
	}
	fprintf(stderr, "DEBUG: alarm, prev task %p, next task %p\n", prevtp, tp);
	if (prevtp != NULL) {
		LIST_NEXT(prevtp, wheel) = NULL;
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
#ifdef SNOOP
	const u_char *pkt;
	struct in_addr inaddr;
	struct pcap_pkthdr *pkthdr;
#endif

	/*
	 * Get IP address.
	 */
	switch (janitor->type) {
	case LISTENING_JANITOR:
		fprintf(stderr, "DEBUG: activity on listening janitor %p\n",
		    janitor);
		sinlen = sizeof (sin);
		if (janitor->u.listen.addrinfo->ai_protocol == IPPROTO_TCP) {
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
			warnx("Could not resolve hostname: %s",
			    gai_strerror(error));
			return;
		}
		break;
#ifdef SNOOP
	case SNOOPING_JANITOR:
		fprintf(stderr, "DEBUG: activity on snooping janitor %p\n",
		    janitor);
		/* Cannot return 0. */
		if (-1 == pcap_next_ex(janitor->u.snoop.pcap, &pkthdr, &pkt)) {
			warnx("Could read packet: %s",
			    pcap_geterr(janitor->u.snoop.pcap));
			return;
		}
/* Ethernet header len + offset in IP header */
#define	SRCIP_OFFSET	14 + 12
		memcpy(&inaddr, pkt + SRCIP_OFFSET, sizeof (inaddr));
		strcpy(ip, inet_ntoa(inaddr));
		break;
#endif
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

	/*
	 * Perform and schedule actions.
	 */
	SLIST_FOREACH(action, &janitor->actions, next) {
		cmd = expand(action->cmd, ip, janitor->usecount);
		if (action->timeout == 0)
			runcallout(cmd);
		else
			schedule(action->timeout + 1, runcallout, cmd);
	}
	sigprocmask(SIG_UNBLOCK, &alrm_sigset, NULL);
	janitor->usecount++;
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
#ifdef SNOOP
	pcap_t *pcapp;
	char pcaperr[PCAP_ERRBUF_SIZE];
#endif
	fd_set fds_, fds;

	sa.sa_handler = &quit;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGQUIT, &sa, NULL) == -1)
		err(2, "sigaction");

	jcount = read_conf("portknox.conf", &janitors);

	fdmax = 0;
	SLIST_FOREACH(jp, &janitors, next) {
		switch (jp->type) {
		case LISTENING_JANITOR:
			ai = jp->u.listen.addrinfo;
			s = socket(ai->ai_family, ai->ai_socktype,
			    ai->ai_protocol);
			if (s == -1)
				err(2, "socket");
			if (!strcmp(jp->u.listen.proto, "tcp")) {
				i = 1;
				if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &i,
				    sizeof (i)) == -1)
					err(2, "setsockopt");
			}
			if (bind(s, ai->ai_addr, ai->ai_addrlen) == -1)
				err(2, "bind");
			if (!strcmp(jp->u.listen.proto, "tcp"))
				if (listen(s, 5) == -1)
					err(2, "listen");
			jp->sock = s;
			break;
#ifdef SNOOP
		case SNOOPING_JANITOR:
			pcapp = pcap_open_live(jp->u.snoop.iface, 1518, 0, 50,
			    pcaperr);
			if (pcapp == NULL)
				errx(2, "pcap_open_live(%s): %s",
				    jp->u.snoop.iface, pcaperr);
			if (pcap_datalink(pcapp) != DLT_EN10MB)
				errx(2, "%s is not ethernet",
				    jp->u.snoop.iface);
			if (-1 == pcap_compile(pcapp, &jp->u.snoop.bpfpg,
			    jp->u.snoop.filter, 0, 0))
				errx(2, "Couldn't compile BPF filter: %s",
				    jp->u.snoop.filter);
			if (-1 == pcap_setfilter(pcapp, &jp->u.snoop.bpfpg))
				errx(2, "pcap_setfilter: %s",
				    pcap_geterr(pcapp));
			if (-1 == pcap_setdirection(pcapp, PCAP_D_IN))
				errx(2, "pcap_setdirection: %s", pcaperr);
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
		LIST_FIRST(&timeout_wheel[i]) = NULL;

	sa.sa_handler = &tick;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGALRM, &sa, NULL) == -1)
		err(2, "sigaction");

	alarm(1);

	/* Main loop. */
	FD_ZERO(&fds_);
	SLIST_FOREACH(jp, &janitors, next) {
		fprintf(stderr, "DEBUG: selecting on fd %d\n", jp->sock);
		FD_SET(jp->sock, &fds_);
	}

	while (!mustquit) {
		/* Handle callouts. */
		sigprocmask(SIG_BLOCK, &alrm_sigset, NULL);
		LIST_FOREACH_SAFE(tp, &tasks_todo, wheel, tmptp) {
			(*tp->func)(tp->arg);
			myfree(tp);
		}
		LIST_FIRST(&tasks_todo) = NULL;
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
		switch (jp->type) {
		case LISTENING_JANITOR:
			myfree(jp->u.listen.ip);
			myfree(jp->u.listen.port);
			myfree(jp->u.listen.proto);
			/*
			myfree(jp->addrinfo->ai_addr);
			myfree(jp->addrinfo->ai_canonname);
			*/
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
			myfree(action->cmd);
			myfree(action);
			}
		myfree(jp);
	}
	LIST_FOREACH_SAFE(tp, &tasks_todo, wheel, tmptp) {
		myfree(tp->arg);
		myfree(tp);
	}
	for (i = 0; i < TIMEOUT_WHEEL_SIZE; i++) {
		LIST_FOREACH_SAFE(tp, &timeout_wheel[i], wheel, tmptp) {
			myfree(tp->arg);
			myfree(tp);
		}
	}
	exit(0);
}

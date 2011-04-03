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
 * $id$
 */

/*
 * conf.c
 * Parse the configuration file and create janitors and their server sockets.
 */

#define _ISOC99_SOURCE
#define _BSD_SOURCE
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include "conf.h"
#include "faststring.h"
#include "freebsdqueue.h"
#include "hash.h"
#include "util.h"
#include "log.h"
#ifdef SNOOP
#include <pcap.h>
#endif

#define	FS_OK(fs)   FASTSTRING_VALID(fs)

static int id;
static int linecount;
static const char *filename;
static int nstates;
static int usmaxtotal;

struct state {
	SLIST_ENTRY(state) next;
	int id;
	faststring name;
};

static SLIST_HEAD(statelist, state) statelist =
    SLIST_HEAD_INITIALIZER(statelist);

static int
declare_state(faststring *name)
{
	struct state *s, *prev;
	int c;

	prev = NULL;
	SLIST_FOREACH(s, &statelist, next) {
		c = strcmp(faststring_peek(name), faststring_peek(&s->name));
		if (c == 0)
			return s->id;
		if (c > 0)
			break;
		prev = s;
	}
	s = mymalloc(sizeof (*s), "state entry");
	s->id = nstates++;
	FASTSTRING_INIT(&s->name);
	faststring_strdup(&s->name, faststring_peek(name));
	ix(NULL, "State \"%s\" has id %d", faststring_peek(&s->name), s->id);
	if (prev)
		SLIST_INSERT_AFTER(prev, s, next);
	else
		SLIST_INSERT_HEAD(&statelist, s, next);
	return s->id;
}


#define	JANITOR_SYNTAX							\
"EBNF:\n"								\
"    listening janitor =\n"						\
"            'listen', wp, 'on', wp,\n"					\
"            ip address, ':', port, '/', proto, eol,\n"			\
"            parameters ;\n"						\
"    snooping janitor =\n"						\
"            'snoop', wp, 'on', wp, interface, wp, pcap filter, eol\n"	\
"            parameters ;\n"						\
"    parameters = { tab ( max rate | on dup | action ) eol } ;\n"	\
"    max rate =\n"							\
"    	    'max', wp, 'rate', ':', [ wp ], number, '/', timespan\n"	\
"    on dup =\n"							\
"           'on', wp, 'dup', colon, [ wp ],\n"				\
"           ( 'exec' | 'ignore' | 'reset' )\n"				\
"    action = 'action', wp, 'at', wp, timespan, ':', command\n"		\
"    timespan = number, ('s' | 'm' | 'h' | 'd' | 'w')\n"		\
"    ip address = (* self explanatory *)\n"				\
"    port = number\n"							\
"    proto = ( 'tcp' | 'udp' )\n"					\
"    interface = (* interface name *)\n"				\
"    pcap filter = (* self explanatory *)\n"				\
"    command = (* command to execute, see note below *)\n"		\
"    number = (* self explanatory *)\n"					\
"    wp = (* white space *)\n"						\
"    eol = (* end of line *)\n"						\
"    \n"								\
"Note:\n"								\
"    - Commands are subject to expansion (%h => src host, %n => usecount)\n"\
"    - 'max rate' parameter is mandatory and must appear only once\n"	\
"    - 'action' parameter is mandatory and can appear one or more time\n"\

#define	JANITOR_EXAMPLE							\
"EXAMPLE:\n"								\
"    listen on 192.168.0.1:1411/tcp\n"					\
"           max rate: 5/10s\n"						\
"           on dup: reset\n"						\
"           action at 0s: pfctl -t sshd -T add %h\n"			\
"           action at 30s: pfctl -t sshd -T delete %h\n"		\
"    \n"								\
"    snoop on bge0 dst host 192.168.0.1 and icmp[icmptype] == icmp-echo\n"\
"            max rate: 10/30m\n"					\
"            on dup: ignore\n"						\
"            action at 0s: /www/regen_index.sh\n"			\
"            action at 5m: true\n"

#define	EAT_BLANKS(p)	    do { while (isblank(*(p))) { (p)++; } } while (0)

static void
syntaxerr(int status, const char *fmt, ...)
{
	va_list ap;
	char *msg;

	va_start(ap, fmt);
	if (vasprintf(&msg, fmt, ap) == -1)
		msg = (char *)fmt;
	fprintf(stderr, "%s(%d): %s\n", filename, linecount, msg);
	fprintf(stderr, "%s", JANITOR_SYNTAX);
	syslog(LOG_ERR, "Error in configuration file %s(%d)",
	    filename, linecount);
	exit(status);
}

static void
fill_addrinfo(struct janitor *janitor)
{
	int error;
	struct addrinfo hints, *ai;

	hints.ai_family = AF_INET;
	if (!strcmp(janitor->u.listen.proto, "tcp"))
		hints.ai_socktype = SOCK_STREAM;
	else if (!strcmp(janitor->u.listen.proto, "udp"))
		hints.ai_socktype = SOCK_DGRAM;
	else
		errx(1, "%s: Unknown protocol", janitor->u.listen.proto);
	hints.ai_protocol = 0;
	hints.ai_flags = /*AI_ADDRCONFIG|*/AI_PASSIVE|AI_NUMERICHOST|AI_NUMERICSERV;
	hints.ai_addrlen = 0;
	hints.ai_addr = NULL;
	hints.ai_canonname = NULL;
	hints.ai_next = NULL;
	error = getaddrinfo(janitor->u.listen.ip, janitor->u.listen.port,
	    &hints, &ai);
	if (error != 0)
		errx(1, "%s:%s/%s: %s", janitor->u.listen.ip,
		    janitor->u.listen.port, janitor->u.listen.proto,
		    gai_strerror(error));
	assert(ai->ai_next == NULL);
	janitor->u.listen.addrinfo = ai;
}

static void
insert_action(struct janitor *janitor, struct action *action)
{
	struct action *actp;

	/* Sort list by timeout. */
	actp = SLIST_FIRST(&janitor->actions);
	if (SLIST_EMPTY(&janitor->actions) ||
	    action->timeout < actp->timeout)
		SLIST_INSERT_HEAD(&janitor->actions, action, next);
	else {
		while (SLIST_NEXT(actp, next) != NULL &&
		    action->timeout > SLIST_NEXT(actp, next)->timeout)
			actp = SLIST_NEXT(actp, next);

		SLIST_INSERT_AFTER(actp, action, next);
	}
}

static void
get_word(faststring *fs, const char **p)
{
	int len;

	EAT_BLANKS(*p);
	len = (int)strspn(*p, "abcdefghijklmnopqrstuvwxyz");
	if (FS_OK(fs))
		faststring_free(fs);
	if (len == 0)
		return;
	faststring_alloc(fs, len + 1);
	faststring_strncpy(fs, *p, len);
	*p += len;
}

static void
get_number(faststring *fs, const char **p)
{
	int len;

	EAT_BLANKS(*p);
	len = (int) strspn(*p, "0123456789");
	if (FS_OK(fs))
		faststring_free(fs);
	if (len == 0)
		return;
	faststring_alloc(fs, len + 1);
	faststring_strncpy(fs, *p, len);
	*p += len;
}

static int
get_punct(const char **p, int which)
{
	int c;

	EAT_BLANKS(*p);
	c = **p;
	if (!ispunct(c))
		return -1;
	if (which > '\0' && c != which)
		return -1;
	(*p)++;
	return c;
}

static int
parse_timespan(const char **lpp, const char *what)
{
	faststring num = FASTSTRING_INITIALIZER;
	faststring unit = FASTSTRING_INITIALIZER;
	long n;
	char u;

	get_number(&num, lpp);
	if (!FS_OK(&num))
		syntaxerr(1, "Expecting number for %s: %s", what, *lpp);
	get_word(&unit, lpp);
	if (!FS_OK(&num) || faststring_strlen(&unit) > 1)
		syntaxerr(1, "Expecting interval unit for %s: %s", what,
		    FS_OK(&num) ? faststring_peek(&unit) : *lpp);
	u = faststring_peek(&unit)[0];
	switch (u) {
	case 's': case 'm': case 'h': case 'd': case 'w':
		break;
	default:
		syntaxerr(1, "Bad interval unit for %s: %c", what, u);
	}

	n = strtol(faststring_peek(&num), NULL, 10);
	if ((n == 0 && errno == EINVAL) || n < 0 ||
	    (n == LONG_MAX && errno == ERANGE))
		syntaxerr(1, "Bad <integer> for interval for %s: %s",
		   what,  *lpp);

	switch (u) {
	case 'w':
		n *= 7;
	case 'd':
		n *= 24;
	case 'h':
		n *= 60;
	case 'm':
		n *= 60;
	}
	faststring_free(&num);
	faststring_free(&unit);

	return (int)n;
}

static void
parse_rate(struct janitor *janitor, const char **lpp)
{
	faststring max = FASTSTRING_INITIALIZER;
	long m;
	int i;

	if (janitor->uswheelsz != 0)
		syntaxerr(1, "Max rate property cannot be specified more than "
		    "once: %s", lpp);

	get_number(&max, lpp);
	if (!FS_OK(&max))
		syntaxerr(1, "Expecting interger <max> for rate: %s", *lpp);
	m = strtol(faststring_peek(&max), NULL, 10);
	if ((m == 0 && errno == EINVAL) || m < 0 ||
	    (m == LONG_MAX && errno == ERANGE))
		syntaxerr(1, "Bad <max> value for rate: %s", *lpp);
	janitor->usmax = m;
	usmaxtotal += m;

	if (-1 == get_punct(lpp, '/'))
		syntaxerr(1, "Expecting '/' for rate: %s", *lpp);

	janitor->uswheelsz = parse_timespan(lpp, "rate");

	if (janitor->uswheelsz == 0)
		syntaxerr(1, "Please specify a valid rate interval: %s", *lpp);

	janitor->uswheel = mymalloc(janitor->uswheelsz *
	    sizeof (*janitor->uswheel), "usage wheel");
	for (i = 0; i < janitor->uswheelsz; i++)
		janitor->uswheel[i] = 0;
	janitor->uscur = 0;

	faststring_free(&max);
}


static void
read_property(struct janitor *janitor, const char *lp)
{
	faststring word = FASTSTRING_INITIALIZER;
	struct action *action;
	const char *lp0;
	char *cmd, *sp, **argv, **ap;
	int start, end, i, arraysz;

	lp0 = lp;
	get_word(&word, &lp);
	if (!FS_OK(&word))
		syntaxerr(1, "Expecting property name: %s", lp);

	/* action at */
	if (!strcmp(faststring_peek(&word), "action")) {
		get_word(&word, &lp);
		if (!FS_OK(&word) || strcmp(faststring_peek(&word), "at"))
			syntaxerr(1, "Expecting \"at\" after word \"action\": "
			    "%s", FS_OK(&word) ? faststring_peek(&word) : lp);

		start = parse_timespan(&lp, "action");

		if (-1 == get_punct(&lp, ':'))
			syntaxerr(1, "Expecting ':' after \"action at "
			    "<interval>\": %s", lp);

		EAT_BLANKS(lp);
		action = mymalloc(sizeof (*action), "struct action");
		action->timeout = start;
		action->type = ACTION;
		SLIST_NEXT(action, next) = NULL;
		/* Split action command-line. */
		cmd = mystrdup(lp, "command");
		arraysz = 16;
		ap = argv = mymalloc(arraysz * sizeof (*argv), "argument list");
		while (cmd != NULL) {
			sp = strsep(&cmd, " \t");
			if (*sp == '\0')
				continue;
			*ap++ = sp;
			if (ap == argv + arraysz) {
				arraysz += 16;
				argv = myrealloc(argv, arraysz * sizeof (*argv),
				    "argument list");
			}
		}
		*ap = NULL;
		action->u.a.argv = argv;
		action->u.a.argc = ap - argv + 1;

		insert_action(janitor, action);
	}

	/* state span */
	else if (!strcmp(faststring_peek(&word), "state")) {
		get_word(&word, &lp);
		if (!FS_OK(&word) || strcmp(faststring_peek(&word), "span"))
			syntaxerr(1, "Expecting \"span\" after word \"state\": "
			    "%s", FS_OK(&word) ? faststring_peek(&word) : lp);
		get_word(&word, &lp);
		if (!FS_OK(&word) || strcmp(faststring_peek(&word), "from"))
			syntaxerr(1, "Expecting \"from\" after word \"span\": "
			    "%s", FS_OK(&word) ? faststring_peek(&word) : lp);

		start = parse_timespan(&lp, "state");

		get_word(&word, &lp);
		if (!FS_OK(&word) || strcmp(faststring_peek(&word), "to"))
			syntaxerr(1, "Expecting \"to\" after start time: "
			    "%s", FS_OK(&word) ? faststring_peek(&word) : lp);

		end = parse_timespan(&lp, "state");

		if (-1 == get_punct(&lp, ':'))
			syntaxerr(1, "Expecting ':' after \"state span from "
			    "<interval> to <interval>\": %s", lp);

		EAT_BLANKS(lp);
		faststring_free(&word);
		faststring_strdup(&word, lp);
		(void)strtok(faststring_peek(&word), " \t");
		i = declare_state(&word);

		action = mymalloc(sizeof (*action), "struct action");
		action->timeout = start;
		action->type = STATE;
		action->u.s.state = i;
		action->u.s.set = 1;
		insert_action(janitor, action);

		action = mymalloc(sizeof (*action), "struct action");
		action->timeout = end;
		action->type = STATE;
		action->u.s.state = i;
		action->u.s.set = 0;
		insert_action(janitor, action);

	/* require state */
	} else if (!strcmp(faststring_peek(&word), "require")) {
		get_word(&word, &lp);
		if (!FS_OK(&word) || strcmp(faststring_peek(&word), "state"))
			syntaxerr(1, "Expecting \"state\" after word "
			    "\"require\": %s",
			    FS_OK(&word) ? faststring_peek(&word) : lp);

		if (-1 == get_punct(&lp, ':'))
			syntaxerr(1, "Expecting ':' after \"require state\": "
			    "%s", lp);

		EAT_BLANKS(lp);
		faststring_free(&word);
		faststring_strdup(&word, lp);
		(void)strtok(faststring_peek(&word), " \t");
		janitor->reqstate = declare_state(&word);

	/* max rate */
	} else if (!strcmp(faststring_peek(&word), "max")) {
		get_word(&word, &lp);
		if (!FS_OK(&word) || strcmp(faststring_peek(&word), "rate"))
			syntaxerr(1, "Expecting \"rate\" after word \"max\": "
			    "%s", FS_OK(&word) ? faststring_peek(&word) : lp);

		if (-1 == get_punct(&lp, ':'))
			syntaxerr(1, "Expecting ':' after \"max rate\": %s",
			    lp);

		parse_rate(janitor, &lp);

	/* on dup */
	} else if (!strcmp(faststring_peek(&word), "on")) {
		get_word(&word, &lp);
		if (!FS_OK(&word) || strcmp(faststring_peek(&word), "dup"))
			syntaxerr(1, "Expecting \"dup\" after word \"on\": %s",
			    FS_OK(&word) ? faststring_peek(&word) : lp);

		if (-1 == get_punct(&lp, ':'))
			syntaxerr(1, "Expected ':' after \"on dup\": %s", lp);

		get_word(&word, &lp);
		if (!FS_OK(&word))
			syntaxerr(1, "Expecting \"exec\", \"ignore\" or "
			    "\"reset\" after \"on dup:\": %s", lp);
		if (!strcmp(faststring_peek(&word), "exec"))
			janitor->dup = DUP_EXEC;
		else if (!strcmp(faststring_peek(&word), "ignore"))
			janitor->dup = DUP_IGNORE;
		else if (!strcmp(faststring_peek(&word), "reset"))
			janitor->dup = DUP_RESET;
		else
			syntaxerr(1, "Expecting \"exec\", \"ignore\" or "
			    "\"reset\" after \"on dup:\": %s",
			    faststring_peek(&word));

		if (janitor->dup == DUP_IGNORE || janitor->dup == DUP_RESET)
			janitor->ip2tasks = hash_create(janitor->usmax / 4);

	/* verbose */
	} else if (!strcmp(faststring_peek(&word), "verbose")) {
		if (-1 == get_punct(&lp, ':'))
			syntaxerr(1, "Expected ':' after \"verbose\": %s", lp);

		while (1) {
			get_word(&word, &lp);
			if (!FS_OK(&word)) {
				/* XXX Final faststring_free() won't fail. */
				faststring_strdup(&word, "");
				break;
			}
			if (!strcmp(faststring_peek(&word), "task"))
				janitor->verbose |= VERBOSE_TASK;
			else if (!strcmp(faststring_peek(&word), "state"))
				janitor->verbose |= VERBOSE_STATE;
			else if (!strcmp(faststring_peek(&word), "action"))
				janitor->verbose |= VERBOSE_ACTION;
			else if (!strcmp(faststring_peek(&word), "conf"))
				janitor->verbose |= VERBOSE_CONF;
			else if (!strcmp(faststring_peek(&word), "debugstate"))
				janitor->verbose |= DEBUG_STATE;
			else
				syntaxerr(1, "Expecting \"task\" after \"verbose:\": %s",
				    faststring_peek(&word));
		}
	} else
		syntaxerr(1, "Unexpected property name: %s", lp0);

	faststring_free(&word);
}

static void
read_listen_on(struct janitor *janitor, char *lp)
{
	char *p;

	janitor->type = LISTENING_JANITOR;

	EAT_BLANKS(lp);

	p = strchr(lp, ':');
	if (p == NULL)
		syntaxerr(1, "Cannot find ':': %s", lp);
	*p = '\0';
	janitor->u.listen.ip = mystrdup(lp, "IP address");
	lp = p + 1;

	p = strchr(lp, '/');
	if (p == NULL)
		syntaxerr(1, "Cannot find '/': %s", lp);
	*p = '\0';
	janitor->u.listen.port = mystrdup(lp, "port");
	lp = p + 1;

	janitor->u.listen.proto = mystrdup(lp, "prototype");

	fill_addrinfo(janitor);
}

#ifdef SNOOP
static void
read_snoop_on(struct janitor *janitor, char *lp)
{
	char *p;
	pcap_t *pcapp;

	janitor->type = SNOOPING_JANITOR;

	EAT_BLANKS(lp);

	if (*lp == '\0')
		syntaxerr(1, "Expecting interface after \"on\"");

	p = strpbrk(lp, " \t");
	if (p == NULL)
		syntaxerr(1, "Expecting BPF filter after interface: %s", lp);
	*p = '\0';
	janitor->u.snoop.iface = mystrdup(lp, "interface");
	lp = p + 1;

	EAT_BLANKS(lp);

	if (*lp == '\0')
		syntaxerr(1, "Expecting BPF filter after interface");

	janitor->u.snoop.filter = mystrdup(lp, "filter");
	pcapp = pcap_open_dead(DLT_RAW, 128);
	if (-1 == pcap_compile(pcapp, &janitor->u.snoop.bpfpg,
	    janitor->u.snoop.filter, 0, 0))
		syntaxerr(1, "Bad BPF filter: %s", pcap_geterr(pcapp));
	pcap_freecode(&janitor->u.snoop.bpfpg);
	pcap_close(pcapp);
}
#endif

void
read_conf(const char *file, struct janitorlist *jlist, struct confinfo *ci)
{
	FILE *f;
	char line[1024], statebuf[16], *ondup;
	char *lp;
	faststring word = FASTSTRING_INITIALIZER;
	struct janitor *janitor, *jp;
	int jcount;

	filename = file;
	f = fopen(filename, "r");
	if (f == NULL)
		err(1, "Cannot open '%s'", filename);
	SLIST_INIT(jlist);
	janitor = NULL;
	id = 0;
	linecount = 0;
	jcount = 0;
	while (1) {
		linecount++;
		if (fgets(line, sizeof (line), f) == NULL) {
			if (ferror(f))
				err(1, "%s", filename);
			break;
		}
		lp = line;
		while (*lp != '\n')
			lp++;
		*lp = '\0';
		lp = line;

		if (*lp == '\t') {
			lp++;
			if (janitor == NULL)
				syntaxerr(1, "Unexpected property without "
				    "janitor declaration: %s", lp);
			read_property(janitor, lp);
			continue;
		}

		if (*lp == '\0' || *lp == '#')
			continue;

		/*
		 * New janitor.
		 */
		if (janitor != NULL) {
			if (janitor->uswheelsz == 0)
				syntaxerr(1, "Janitor with no max rate");
			if (SLIST_EMPTY(&janitor->actions))
				syntaxerr(1, "Janitor with no action");
		}

		janitor = mymalloc(sizeof (*janitor), "struct janitor");
		SLIST_INIT(&janitor->actions);
		SLIST_NEXT(janitor, next) = NULL;
		janitor->id = id++;
		janitor->line = linecount;
		janitor->verbose = 0;
		janitor->usecount = 0;
		janitor->reqstate = -1;
		janitor->dup = DUP_EXEC;
		janitor->ip2tasks = NULL;
		janitor->uswheelsz = 0;
		janitor->usmax = 0;
		janitor->uscur = 0;
		jcount++;

		get_word(&word, (const char **)&lp);
		if (!FS_OK(&word))
			syntaxerr(1, "Expecting 'listen': %s", lp);
		if (!strcmp(faststring_peek(&word), "listen")) {
			get_word(&word, (const char **)&lp);
			if (!FS_OK(&word) || strcmp(faststring_peek(&word), "on"))
				syntaxerr(1, "Expecting \"on\" after word "
				    "\"listen\": %s",
				    FS_OK(&word) ? faststring_peek(&word) : lp);
		
			read_listen_on(janitor, lp);
#ifdef SNOOP
		} else if (!strcmp(faststring_peek(&word), "snoop")) {
			get_word(&word, (const char **)&lp);
			if (!FS_OK(&word) || strcmp(faststring_peek(&word), "on"))
				syntaxerr(1, "Expecting \"on\" after word "
				    "\"snoop\": %s",
				    FS_OK(&word) ? faststring_peek(&word) : lp);

			read_snoop_on(janitor, lp);
#endif
		} else
			syntaxerr(1, "Unknown keyword: %s",
			   faststring_peek(&word));

		if (SLIST_EMPTY(jlist)) {
			SLIST_INSERT_HEAD(jlist, janitor, next);
			continue;
		}
		jp = SLIST_FIRST(jlist);
		while (SLIST_NEXT(jp, next) != NULL)
			jp = SLIST_NEXT(jp, next);
		SLIST_INSERT_AFTER(jp, janitor, next);
	}
	faststring_free(&word);
	fclose(f);
	ci->nstates = nstates;
	ci->njanitors = jcount;
	ci->usmaxtotal = usmaxtotal;

	SLIST_FOREACH(janitor, jlist, next) {
		switch (janitor->type) {
		case LISTENING_JANITOR:
			nx(janitor, "Listening on %s:%s/%s",
			    janitor->u.listen.ip, janitor->u.listen.port,
			    janitor->u.listen.proto);
			break;
#ifdef SNOOP
		case SNOOPING_JANITOR:
			nx(janitor, "Snooping on %s (%s)",
		 	    janitor->u.snoop.iface, janitor->u.snoop.filter);
			break;
#endif
		}
		if ((janitor->verbose & VERBOSE_CONF) == 0)
			continue;

		if (janitor->reqstate < 0)
			snprintf(statebuf, sizeof (statebuf), "none");
		else
			snprintf(statebuf, sizeof (statebuf), "%d",
			    janitor->reqstate);
		switch (janitor->dup) {
		case DUP_EXEC:
			ondup = "exec";
			break;
		case DUP_IGNORE:
			ondup = "ignore";
			break;
		case DUP_RESET:
			ondup = "reset";
			break;
		}
		line[0] = '\0';
		if (janitor->verbose) {
			if (janitor->verbose & VERBOSE_TASK)
				strcat(line, " task");
			if (janitor->verbose & VERBOSE_STATE)
				strcat(line, " state");
			if (janitor->verbose & VERBOSE_ACTION)
				strcat(line, " action");
			if (janitor->verbose & VERBOSE_CONF)
				strcat(line, " conf");
			if (janitor->verbose & DEBUG_STATE)
				strcat(line, " debugstate");
		} else
			strcat(line, " -");
		verb(janitor, "max usage: %d/%ds; "
		    "on dup: %s; require state: %s; verbose:%s",
		    janitor->usmax, janitor->uswheelsz, ondup, statebuf, line);
	}
}

void
show_conf_syntax()
{

	printf("%s", JANITOR_SYNTAX);
}

void
show_conf_example()
{

	printf("%s", JANITOR_EXAMPLE);
}

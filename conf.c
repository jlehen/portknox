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
#include "conf.h"
#include "freebsdqueue.h"
#include "util.h"

static int linecount;
static const char *filename;

#define	JANITOR_SYNTAX	    \
    "Syntax:\n" \
    "  listen <ip>:<port>/<proto> [modifiers]\n" \
    "  \\t\taction at <interval>: <action>\n" \
    "  ...\n" \
    "Modifiers:\n" \
    "  rate <max>/<interval>	    - Limit janitor use (MANDATORY)\n" \
    "Interval:\n" \
    "  <integer>[smhdw]\n"

static void
syntaxerr(int status, const char *fmt, ...)
{
	va_list ap;
	char *msg;

	va_start(ap, fmt);
	if (vasprintf(&msg, fmt, ap) == -1)
		msg = (char *)fmt;
	fprintf(stderr, "%s(%d): %s\n", filename, linecount, msg);
	fprintf(stderr, JANITOR_SYNTAX);
	exit(status);
}

static void
resolve(struct janitor *janitor)
{
	int error;
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
}

#define	EAT_BLANKS(p)	    do { while (isblank(*p)) { p++; } } while (0)
static int
parse_timespan(char **linepp, const char *what)
{
	int i;
	long n;
	char *p;
	char unit;

	i = strspn(*linepp, "012356789");
	if (i == 0)
		return -1;
	p = *linepp + i;
	switch (*p) {
	case 's': case 'm': case 'h': case 'd': case 'w':
		break;
	default:
		syntaxerr(1, "Bad interval unit for %s: %c", what, *p);
	}

	unit = *p;
	*p = '\0';

	n = strtol(*linepp, NULL, 10);
	if ((n == 0 && errno == EINVAL) || n < 0 ||
	    (n == LONG_MAX && errno == ERANGE))
		syntaxerr(1, "Bad <integer> for interval for %s: %s",
		   what,  *linepp);

	switch (unit) {
	case 'w':
		n *= 7;
	case 'd':
		n *= 24;
	case 'h':
		n *= 60;
	case 'm':
		n *= 60;
	}

	*linepp = p + 1;
	return (int)n;
}

static void
parse_rate(struct janitor *janitor, char **linep)
{
	int i;
	long n;
	char *p;

	i = strspn(*linep, "0123456789");
	if (i == 0)
		syntaxerr(1, "Expecting interger <max> for rate: %s", linep);
	p = *linep + i;
	if (*p != '/')
		syntaxerr(1, "Expecting '/' for rate: %c", *p);
	*p = '\0';
	n = strtol(*linep, NULL, 10);
	if ((n == 0 && errno == EINVAL) || n < 0 ||
	    (n == LONG_MAX && errno == ERANGE))
		syntaxerr(1, "Bad <max> value for rate: %s", linep);
	janitor->usmax = n;
	*linep = p + 1;

	janitor->uswheelsz = parse_timespan(linep, "rate");
}


static void
get_action(struct janitor *janitor, char *linep)
{
	struct action *action, *ap;
	int timeout;
	char *p;

	p = strpbrk(linep, " \t");
	if (p == NULL)
		syntaxerr(1, "Cannot find next blank: %s", linep);
	*p = '\0';
	if (strcmp(linep, "action"))
		syntaxerr(1, "Expecting 'action': %s", p);
	linep = p + 1;

	EAT_BLANKS(linep);

	p = strpbrk(linep, " \t");
	if (p == NULL)
		syntaxerr(1, "Cannot find next blank: %s", linep);
	*p = '\0';
	if (strcmp(linep, "at"))
		syntaxerr(1, "Expecting 'at': %s", p);
	linep = p + 1;

	EAT_BLANKS(linep);

	timeout = parse_timespan(&linep, "action");
	fprintf(stderr, "DEBUG: janitor %p, new action, timeout %d, *linep: %s\n", janitor, timeout, linep);
	if (*linep != ':')
		syntaxerr(1, "Expecting ':' for action: %c", *linep);
	linep++;

	EAT_BLANKS(linep);

	action = mymalloc(sizeof (*action), "struct action");
	action->timeout = timeout;
	action->cmd = strdup(linep);
	SLIST_NEXT(action, next) = NULL;

	if (SLIST_EMPTY(&janitor->actions))
		SLIST_INSERT_HEAD(&janitor->actions, action, next);
	else {
		ap = SLIST_FIRST(&janitor->actions);
		while (SLIST_NEXT(ap, next) != NULL)
			ap = SLIST_NEXT(ap, next);
		SLIST_INSERT_AFTER(ap, action, next);
	}
}

int
read_conf(const char *file, struct janitorlist *jlist)
{
	FILE *f;
	char line[1024];
	char *linep, *p;
	struct janitor *janitor, *jp;
	int i, jcount;

	filename = file;
	f = fopen(filename, "r");
	if (f == NULL)
		err(1, "%s", filename);
	SLIST_INIT(jlist);
	janitor = NULL;
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

		if (*linep == '\t') {
			linep++;
			if (janitor == NULL)
				syntaxerr(1, "Unexpected action without "
				    "janitor declaration");
			get_action(janitor, linep);
			continue;
		}

		if (*linep == '\0' || *linep == '#')
			continue;

		/*
		 * New janitor.
		 */

		if (janitor != NULL && SLIST_EMPTY(&janitor->actions))
			syntaxerr(1, "Janitor with no action");

		janitor = mymalloc(sizeof (*janitor), "struct janitor");
		SLIST_INIT(&janitor->actions);
		SLIST_NEXT(janitor, next) = NULL;
		janitor->usecount = 0;
		janitor->uswheelsz = 0;
		janitor->usmax = 0;
		janitor->uscur = 0;
		jcount++;

		p = strpbrk(linep, " \t");
		if (p == NULL)
			syntaxerr(1, "Cannot find next blank: %s", linep);
		*p = '\0';
		if (strcmp(linep, "listen"))
			syntaxerr(1, "Expecting 'listen': %s", p);
		linep = p + 1;

		EAT_BLANKS(linep);

		p = strchr(linep, ':');
		if (p == NULL)
			syntaxerr(1, "Cannot find ':': %s", linep);
		*p = '\0';
		janitor->ip = strdup(linep);
		linep = p + 1;

		p = strchr(linep, '/');
		if (p == NULL)
			syntaxerr(1, "Cannot find '/': %s", linep);
		*p = '\0';
		janitor->port = strdup(linep);
		linep = p + 1;

		p = strpbrk(linep, " \t");
		if (p == NULL)
			syntaxerr(1, "Cannot find next blank: %s", linep);
		*p = '\0';
		janitor->proto = strdup(linep);
		linep = p + 1;

		EAT_BLANKS(linep);

		while (*linep != '\0') {
			p = strpbrk(linep, " \t");
			/* There is no option without argument for now */
			if (p == NULL)
				syntaxerr(1, "Cannot find next blank: %s",
				    linep);

			*p++ = '\0';
			if (!strcmp(linep, "rate"))
				parse_rate(janitor, &p);
			else
				syntaxerr(1, "Unknown modifier: %s", linep);

			linep = p;
			EAT_BLANKS(linep);
		}

		if (janitor->uswheelsz == 0)
			syntaxerr(1, "Please specify a valid rate interval: %s",
			    linep);

		janitor->uswheel = mymalloc(janitor->uswheelsz *
		    sizeof (*janitor->uswheel), "usage wheel");
		for (i = 0; i < janitor->uswheelsz; i++)
			janitor->uswheel[i] = 0;
		janitor->uscur = 0;

		resolve(janitor);
		fprintf(stderr, "DEBUG: new janitor %p (%s:%s/%s)\n",
		    janitor, janitor->ip, janitor->port, janitor->proto);

		if (SLIST_EMPTY(jlist)) {
			SLIST_INSERT_HEAD(jlist, janitor, next);
			continue;
		}
		jp = SLIST_FIRST(jlist);
		while (SLIST_NEXT(jp, next) != NULL)
			jp = SLIST_NEXT(jp, next);
		SLIST_INSERT_AFTER(jp, janitor, next);
	}
	fclose(f);
	return jcount;
}



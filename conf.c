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
const char *filename;

static void
syntaxerr(int status, const char *fmt, ...)
{
	va_list ap;
	char *msg;

	va_start(ap, fmt);
	if (vasprintf(&msg, fmt, ap) == -1)
		errx(status, "%s(%d): %s", filename, linecount, fmt);
	err(status, "%s(%d): %s", filename, linecount, msg);
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
#define	JANITOR_FORMAT	    "<ip>/<port>:<proto> <max>/<interval>"
#define	ACTION_FORMAT	    "<TAB><timeout>: <action>"
#define TIMESPAN_FORMAT	    "<integer><'s'|'m'|'h'|'d'|'w'>"

static int
parse_timespan(char **linepp)
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
		return -1;
	}

	unit = *p;
	*p = '\0';

	n = strtol(*linepp, NULL, 10);
	if ((n == 0 && errno == EINVAL) || n < 0 ||
	    (n == LONG_MAX && errno == ERANGE))
		return -1;

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
get_action(struct janitor *janitor, char *linep)
{
	struct action *action, *ap;
	int timeout;

	timeout = parse_timespan(&linep);
	fprintf(stderr, "DEBUG: janitor %p, new action, timeout %d, *linep: %s\n", janitor, timeout, linep);
	if (timeout == -1 || *linep != ':')
		syntaxerr(1, "Format expected: \"" ACTION_FORMAT "\"\n"
		    "    with timeout: " TIMESPAN_FORMAT);
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
read_conf(const char *filename, struct janitorlist *jlist)
{
	FILE *f;
	char line[1024];
	char *linep, *linep2;
	struct janitor *janitor, *jp;
	int i, jcount;
	long n;

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
				    "janitor");
			get_action(janitor, linep);
			continue;
		}

		if (*linep == '\0' || *linep == '#')
			continue;

		/*
		 * New janitor.
		 */

		if (janitor != NULL && SLIST_EMPTY(&janitor->actions))
			syntaxerr(1, "Janitor with no actions");

		janitor = mymalloc(sizeof (*janitor), "struct janitor");
		SLIST_INIT(&janitor->actions);
		SLIST_NEXT(janitor, next) = NULL;
		janitor->count = 0;
		jcount++;

		linep2 = strchr(linep, ':');
		if (linep2 == NULL)
			syntaxerr(1, "Format expected: " JANITOR_FORMAT);
		*linep2 = '\0';
		janitor->ip = strdup(linep);
		linep = linep2 + 1;

		linep2 = strchr(linep, '/');
		if (linep2 == NULL)
			syntaxerr(1, "Format expected: " JANITOR_FORMAT);
		*linep2 = '\0';
		janitor->port = strdup(linep);
		linep = linep2 + 1;

		linep2 = strpbrk(linep, " \t");
		if (linep2 == NULL)
			syntaxerr(1, "Format expected: " JANITOR_FORMAT);
		*linep2 = '\0';
		janitor->proto = strdup(linep);
		linep = linep2 + 1;

		EAT_BLANKS(linep);

		i = strspn(linep, "0123456789");
		if (i == 0)
			syntaxerr(1, "Format expected: " JANITOR_FORMAT);
		linep2 = linep + i;
		if (*linep2 != '/')
			syntaxerr(1, "Format expected: " JANITOR_FORMAT);
		*linep2 = '\0';
		n = strtol(linep, NULL, 10);
		if ((n == 0 && errno == EINVAL) || n < 0 ||
		    (n == LONG_MAX && errno == ERANGE))
			syntaxerr(1, "Format expected: " JANITOR_FORMAT);
		janitor->usmax = n;
		linep = linep2 + 1;

		janitor->uswheelsz = parse_timespan(&linep);
		if (janitor->uswheelsz == -1)
			syntaxerr(1, "Format expected: " JANITOR_FORMAT);
		EAT_BLANKS(linep);
		if (*linep != '\0')
			syntaxerr(1, "Format expected: " JANITOR_FORMAT);

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



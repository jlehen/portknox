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
#include "util.h"
#include "conf.h"

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

	if (janitor == NULL)
		syntaxerr(1, "Unexpected action without janitor");

	timeout = parse_timespan(&linep);
	fprintf(stderr, "DEBUG: timeout %d, *linep: %s\n", timeout, linep);
	if (timeout == -1 || *linep != ':')
		syntaxerr(1, "Format expected: \"" ACTION_FORMAT "\"\n"
		    "    with timeout: " TIMESPAN_FORMAT);
	linep++;
	EAT_BLANKS(linep);

	action = mymalloc(sizeof (*action), "struct action");
	action->timeout = timeout;
	action->cmd = strdup(linep);
	action->next = NULL;

	if (janitor->actions == NULL)
		janitor->actions = action;
	else {
		for (ap = janitor->actions; ap->next != NULL; ap = ap->next)
			;
		ap->next = action;
	}
}

int
read_conf(const char *filename, struct janitor **jlist)
{
	FILE *f;
	char line[1024];
	char *linep, *linep2;
	struct janitor *prev, *cur;
	int i, jcount;
	long n;

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

		if (*linep == '\t') {
			linep++;
			get_action(cur, linep);
			continue;
		}

		if (*linep == '\0' || *linep == '#')
			continue;

		/*
		 * New janitor.
		 */

		if (cur != NULL && cur->actions == NULL)
			syntaxerr(1, "Janitor with no actions");

		cur = mymalloc(sizeof (*cur), "struct janitor");
		cur->actions = NULL;
		cur->next = NULL;
		jcount++;

		linep2 = strchr(linep, ':');
		if (linep2 == NULL)
			syntaxerr(1, "Format expected: " JANITOR_FORMAT);
		*linep2 = '\0';
		cur->ip = strdup(linep);
		linep = linep2 + 1;

		linep2 = strchr(linep, '/');
		if (linep2 == NULL)
			syntaxerr(1, "Format expected: " JANITOR_FORMAT);
		*linep2 = '\0';
		cur->port = strdup(linep);
		linep = linep2 + 1;

		linep2 = strpbrk(linep, " \t");
		if (linep2 == NULL)
			syntaxerr(1, "Format expected: " JANITOR_FORMAT);
		*linep2 = '\0';
		cur->proto = strdup(linep);
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
		cur->usmax = n;
		linep = linep2 + 1;

		cur->uswheelsz = parse_timespan(&linep);
		if (cur->uswheelsz == -1)
			syntaxerr(1, "Format expected: " JANITOR_FORMAT);
		EAT_BLANKS(linep);
		if (*linep != '\0')
			syntaxerr(1, "Format expected: " JANITOR_FORMAT);

		cur->uswheel = mymalloc(cur->uswheelsz *
		    sizeof (*cur->uswheel), "usage wheel");
		for (i = 0; i < cur->uswheelsz; i++)
			cur->uswheel[i] = 0;
		cur->uscur = 0;

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
}



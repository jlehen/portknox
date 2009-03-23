#define _ISOC99_SOURCE
#define _BSD_SOURCE
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
		err(status, "%s(%d): %s", filename, linecount, fmt);
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

static void
get_action(struct janitor *janitor, char *linep)
{
	char *p;
	char timeoutunit;
	struct action *action, *ap;
	int timeout, i;

	if (janitor == NULL)
		syntaxerr(1, "Unexpected action without janitor");

	i = strspn(linep, "012356789");
	if (i == 0)
		syntaxerr(1, "Format expected \"<tab>timeout: action\"\n"
		    "    with timeout: <integer><'s'|'m'|'h'|'d'|'w'>");
	p = linep + i;
	switch (*p) {
	case 's': case 'm': case 'h': case 'd': case 'w':
		break;
	default:
		syntaxerr(1, "Format expected \"<tab>timeout: action\"\n"
		    "    with timeout: <integer><'s'|'m'|'h'|'d'|'w'>");
	}

	timeoutunit = *p;
	*p++ = '\0';
	if (*p++ != ':')
		syntaxerr(1, "\"<tab>timeout: action\" expected");

	timeout = (int)strtol(linep, NULL, 10);
	if ((timeout == 0 && errno == EINVAL) ||
	    ((timeout == LONG_MIN || timeout == LONG_MAX) &&
	    errno == ERANGE))
		syntaxerr(1, "bad timeout");

	switch (timeoutunit) {
	case 'w':
		timeout *= 7;
	case 'd':
		timeout *= 24;
	case 'h':
		timeout *= 60;
	case 'm':
		timeout *= 60;
	}

	EAT_BLANKS(p);

	action = mymalloc(sizeof (*action), "struct action");
	action->timeout = timeout;
	action->cmd = strdup(p);
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
	int jcount;

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
			syntaxerr(1, "\"ip:port/proto\" expected");
		*linep2 = '\0';
		cur->ip = strdup(linep);
		linep = linep2 + 1;

		linep2 = strchr(linep, '/');
		if (linep2 == NULL)
			syntaxerr(1, "\"ip:port/proto\" expected");
		*linep2 = '\0';
		cur->port = strdup(linep);
		linep = linep2 + 1;

		cur->proto = strdup(linep);

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



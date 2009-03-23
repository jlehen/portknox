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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"
#include "conf.h"

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
get_action(struct janitor *janitor, char *linep, const char *filename,
    int linecount)
{
	char *p;
	char timeoutunit;
	struct action *action, *ap;
	int timeout, i;

	if (janitor == NULL)
		errx(1, "%s(%d): Unexpected action without janitor",
		    filename, linecount);

	i = strspn(linep, "012356789");
	if (i == 0)
		errx(1, "%s(%d): Format expected \"<tab>timeout: action\"\n"
		    "    with timeout: <integer><'s'|'m'|'h'|'d'|'w'>",
		    filename, linecount);
	p = linep + i;
	switch (*p) {
	case 's': case 'm': case 'h': case 'd': case 'w':
		break;
	default:
		errx(1, "%s(%d): Format expected \"<tab>timeout: action\"\n"
		    "    with timeout: <integer><'s'|'m'|'h'|'d'|'w'>",
		    filename, linecount);
	}

	timeoutunit = *p;
	*p++ = '\0';
	if (*p++ != ':')
		errx(1, "%s(%d): \"<tab>timeout: action\" "
		    "expected", filename, linecount);

	timeout = (int)strtol(linep, NULL, 10);
	if ((timeout == 0 && errno == EINVAL) ||
	    ((timeout == LONG_MIN || timeout == LONG_MAX) &&
	    errno == ERANGE))
		err(1, "%s(%d): bad timeout", filename,
		    linecount);

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
	int linecount, jcount;

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
			get_action(cur, linep, filename, linecount);
			continue;
		}

		if (*linep == '\0' || *linep == '#')
			continue;

		/*
		 * New janitor.
		 */

		if (cur != NULL && cur->actions == NULL)
			errx(1, "%s(%d): missing actions", filename, linecount);

		cur = mymalloc(sizeof (*cur), "struct janitor");
		cur->actions = NULL;
		cur->next = NULL;
		jcount++;

		linep2 = strchr(linep, ':');
		if (linep2 == NULL)
			errx(1, "%s(%d): \"ip:port/proto\" expected",
			    filename, linecount);
		*linep2 = '\0';
		cur->ip = strdup(linep);
		linep = linep2 + 1;

		linep2 = strchr(linep, '/');
		if (linep2 == NULL)
			errx(1, "%s(%d): \"ip:port/proto\" expected",
			    filename, linecount);
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



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
 * $Id: log.c,v 1.4 2011/03/29 21:08:19 jlh Exp $
 */

#include <err.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include "conf.h"

#ifndef LOG_SECURITY
# define LOG_SECURITY LOG_DAEMON
#endif

static struct facility {
	const char *string;
	int val;
} facilities[] = {
	{ "auth", LOG_AUTH },
	{ "daemon", LOG_DAEMON },
	{ "security", LOG_SECURITY },
	{ "user", LOG_USER },
	{ "local0", LOG_LOCAL0 },
	{ "local1", LOG_LOCAL1 },
	{ "local2", LOG_LOCAL2 },
	{ "local3", LOG_LOCAL3 },
	{ "local4", LOG_LOCAL4 },
	{ "local5", LOG_LOCAL5 },
	{ "local6", LOG_LOCAL6 },
	{ "local7", LOG_LOCAL7 },
	{ NULL, 0 }
};

static int debug = 0;
static int canexit = 0;
static int facility = LOG_DAEMON;

void
setDebug()
{

	debug = LOG_PERROR;
}

void
exitOnError()
{

	canexit = 1;
}

void
setLogFacility(const char *s)
{
	struct facility *f;

	for (f = facilities; f->string != NULL; f++)
		if (!strcmp(f->string, s))
			break;
	if (f->string == NULL)
		err(1, "Unknown log facility: %s", s);
	facility = f->val;
}

void
openLog(const char *basename)
{

	openlog(basename, debug | LOG_PID, facility);
}

void
mylog(int status, int prio, const struct janitor *j, const char *errstr,
    const char *fmt, ...)
{
    va_list ap;
    int i;
    char errbuf[256];	/* Should be enough */
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

    if (canexit || debug) {
	    if (status >= 0)
		    exit(status);
	    return;
    }

    if (status >= 0)
	    err(status, "Error occured, check system log");
    if (warns++ == 0)
	    warn("Warning occured, check system log");
}

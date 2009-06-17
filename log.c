#include <err.h>
#include <string.h>
#include <syslog.h>

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
static int facility = LOG_DAEMON;

void
setDebug()
{

	debug = LOG_PERROR;
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

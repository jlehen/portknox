#ifndef _CONF_H_
#define _CONF_H_
#include "freebsdqueue.h"

struct action {
	SLIST_ENTRY(action) next;
	int timeout;
	char *cmd;
};

SLIST_HEAD(actionlist, action);

struct janitor {
	SLIST_ENTRY(janitor) next;
	char *ip;			
	char *port;
	char *proto;
	int sock;
	struct addrinfo *addrinfo;
	struct actionlist actions;
	unsigned count;

	/* Usage wheel. */
	short *uswheel;
	int uswheelsz;
	int usmax;
	int uscur;
};

SLIST_HEAD(janitorlist, janitor);

extern int read_conf(const char *, struct janitorlist *);

#endif /* !_CONF_H_ */

#ifndef _CONF_H_
#define _CONF_H_
#include "freebsdqueue.h"

#ifdef SNOOP
#include <pcap.h>
#endif

struct action {
	SLIST_ENTRY(action) next;
	int timeout;
	char *cmd;
};

SLIST_HEAD(actionlist, action);

struct janitor {
	SLIST_ENTRY(janitor) next;

	int line;

	enum {
		LISTENING_JANITOR,
#ifdef SNOOP
		SNOOPING_JANITOR
#endif
	} type;

	union {
		struct {
			char *ip;			
			char *port;
			char *proto;
			struct addrinfo *addrinfo;
		} listen;
#ifdef SNOOP
		struct {
			char *iface;
			char *filter;
			struct bpf_program bpfpg;
			pcap_t *pcap;
		} snoop;
#endif
	} u;
	int sock;
	struct actionlist actions;
	unsigned usecount;		/* Number of janitor use so far */

	enum {
		DUP_EXEC,		/* Execute anyway */
		DUP_IGNORE,		/* Ignore the request */
		DUP_RESET		/* Reset pending tasks timeouts */
	} dup;

	/* Usage wheel. */
	short *uswheel;
	int uswheelsz;
	int usmax;
	int uscur;
};

SLIST_HEAD(janitorlist, janitor);

extern int read_conf(const char *, struct janitorlist *);

#endif /* !_CONF_H_ */

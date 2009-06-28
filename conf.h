#ifndef _CONF_H_
#define _CONF_H_
#include "freebsdqueue.h"

#ifdef SNOOP
#include <pcap.h>
#endif

struct ushashbucket;

/*
 * Pending task for a janitor.
 */
struct task {
	/* Used in timeout wheel. */
	LIST_ENTRY(task) ticklist;
	/* Used in usage hash bucket. */
	TAILQ_ENTRY(task) siblinglist;

	/* Hash bucket the task belongs to. */
	struct ushashbucket *ushashbucket;
	/* Janitor the task relates to. */
	struct janitor *janitor;

	unsigned int tick;
	/* Initial action timeout. */
	int timeout;

	void (*func)(void *);
	void *arg; 
};

LIST_HEAD(tasklist, task);


/*
 * Usage hash bucket, mapping IP to tasks.
 * Not use or even allocated if dup == DUP_EXEC.
 */
struct ushashbucket {
	LIST_ENTRY(ushashbucket) slotlist;
	uint32_t ip;
	uint16_t hash;
	TAILQ_HEAD(, task) tasks;
};

LIST_HEAD(ushashslot, ushashbucket);


/*
 * Actions described in the configuration file.
 */
struct action {
	SLIST_ENTRY(action) next;
	int timeout;
	char *cmd;
};

SLIST_HEAD(actionlist, action);


/*
 * Janitor.
 */
struct janitor {
	SLIST_ENTRY(janitor) next;

	int line;
	int id;

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

	/* Behaviour on duplicate request. */
	enum {
		DUP_EXEC,		/* Execute anyway */
		DUP_IGNORE,		/* Ignore the request */
		DUP_RESET		/* Reset pending tasks timeouts */
	} dup;

	/* Usage hash. */
	int ushashsz;
	struct ushashslot *ushash;

	/* Usage wheel. */
	int *uswheel;
	int uswheelsz;
	int usmax;
	int uscur;
};

SLIST_HEAD(janitorlist, janitor);

extern int read_conf(const char *, struct janitorlist *);
extern void show_conf_syntax();

#endif /* !_CONF_H_ */

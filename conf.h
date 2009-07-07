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
 * $Id: conf.h,v 1.13 2009/07/07 21:30:45 jlh Exp $
 */

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
extern void show_conf_example();

#endif /* !_CONF_H_ */

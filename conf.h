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
 * $Id: conf.h,v 1.15 2011/03/29 20:25:24 jlh Exp $
 */

#ifndef _CONF_H_
#define _CONF_H_
#include "freebsdqueue.h"
#include "hash.h"

#ifdef SNOOP
#include <pcap.h>
#endif

/*
 * Pending task for a janitor.
 */
struct task {
	/* Used in timeout wheel. */
	LIST_ENTRY(task) ticklist;
	/* Used in IP to tasks mapping. */
	TAILQ_ENTRY(task) siblinglist;

	/* ip2tasks mapping's bucket the task belongs to. */
	struct hashbucket *bucket;
	/* Janitor the task relates to. */
	struct janitor *janitor;

	unsigned int tick;
	/* Initial action timeout. */
	int timeout;

	void (*func)(void *);
	void *arg; 
};

LIST_HEAD(tasklist, task);

TAILQ_HEAD(taskqueue, task);


/*
 * Actions described in the configuration file.
 */
struct action {
	SLIST_ENTRY(action) next;
	int timeout;

	enum {
		ACTION = 1,
		STATE = 2
	} type;

	union {
		struct {
			char **argv;
			int argc;
		} a;	/* ACTION */
		struct {
			int state;
			int set;
		} s;	/* STATE */

	} u;
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
	} type:1;

	/* Behaviour on duplicate request. */
	enum {
		DUP_EXEC,		/* Execute anyway */
		DUP_IGNORE,		/* Ignore the request */
		DUP_RESET		/* Reset pending tasks timeouts */
	} dup:2;

#define	VERBOSE_TASK	    0x1
#define	VERBOSE_STATE	    0x2
#define	VERBOSE_ACTION	    0x4
#define	VERBOSE_CONF        0x8
#define	DEBUG_STATE	    0x10
	int verbose:5;

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

	/* -1 or required state */
	int reqstate;

	/* IP to tasks mapping. */
	struct hash *ip2tasks;

	/* Usage wheel. */
	int *uswheel;
	int uswheelsz;
	int usmax;
	int uscur;
};

SLIST_HEAD(janitorlist, janitor);

struct confinfo {
	int nstates;
	int njanitors;
	int usmaxtotal;
};

extern void read_conf(const char *, struct janitorlist *, struct confinfo *);
extern void show_conf_syntax();
extern void show_conf_example();

#endif /* !_CONF_H_ */

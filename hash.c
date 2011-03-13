/*-
 * Copyright (c) 2011 Jeremie LE HEN
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
 * $Id: hash.c,v 1.2 2011/03/13 09:00:30 jlh Exp $
 */

#include <sys/stddef.h>
#include <strings.h>
#include "util.h"
#include "freebsdqueue.h"
#include "hash.h"

struct hashbucket {
	LIST_ENTRY(hashbucket) siblings;
	char *k;
	int ksz;
	uint16_t hash;
	void *val;
};

LIST_HEAD(hashslot, hashbucket);

struct hash {
	int sz;
	struct hashslot slots[0];
};


/* Some random prime numbers. */
static int primes[] = { 7, 17, 31, 43, 59, 113, 163, 191, 223, 257, 293, 0 };

static int
choose_prime(int n)
{
	int *p;

	for (p = primes; *p != 0; p++)
		if (*p > n)
			break;
	if (p != primes)
		p--;
	return *p;
}

static uint16_t
hash(char *s, int len)
{
	uint16_t h;
	uint16_t a, b;
	int i;
	unsigned char *su;

	su = (unsigned char *)s;
	h = 0xB73F;
	a = 0x82;
	b = 0x53 << 8;
	for (i = 0; i < len; i++) {
		h = (h << 5) + su[i];
		a = h >> 7;
		b = h << 11;
		h = (h ^ b) >> 2 ^ a;
	}
	return h;
}

struct hash *
hash_create(int n)
{
	struct hash *h;
	int i;

	i = choose_prime(n);
	h = mymalloc(sizeof (struct hash) + i * sizeof (struct hashslot),
	    "struct hash");
	h->sz = i;
	while (i-- > 0)
		LIST_INIT(&h->slots[i]);
	return h;
}

void
hash_destroy(struct hash *h, void (*fr)(void *))
{
	int i;
	struct hashbucket *b1, *b2;

	for (i = 0; i < h->sz; i++) {
		LIST_FOREACH_SAFE(b1, &h->slots[i], siblings, b2) {
			if (fr != NULL)
				(*fr)(b1->val);
			myfree(b1->k);
			myfree(b1);
		}
		myfree(h);
	}
}

struct hashbucket *
hash_add(struct hash *h, char *k, int ksz, void *p)
{
	struct hashbucket *b;
	uint16_t hval, slot;

	hval = hash(k, ksz);
	slot = hval % h->sz;
	if (hash_get(h, k, ksz) != NULL)
		return NULL;
	b = mymalloc(sizeof (*b), "struct hashbucket");
	b->k = mymalloc(ksz, "hash key");
	bcopy(k, b->k, ksz);
	b->ksz = ksz;
	b->hash = hval;
	b->val = p;
	LIST_INSERT_HEAD(&h->slots[slot], b, siblings);
	return b;
}

struct hashbucket *
hash_get(struct hash *h, char *k, int ksz)
{
	struct hashbucket *b;
	uint16_t hval, slot;

	hval = hash(k, ksz);
	slot = hval % h->sz;
	LIST_FOREACH(b, &h->slots[slot], siblings)
		if (b->hash == hval && b->ksz == ksz && !bcmp(k, b->k, ksz))
			return b;
	return NULL;
}

void *
hash_get_val(struct hash *h, char *k, int ksz, struct hashbucket **hb)
{
	struct hashbucket *b;

	b = hash_get(h, k, ksz);
	if (b == NULL)
		return NULL;
	if (hb)
		*hb = b;
	return b->val;
}

int
hash_remove(struct hash *h, char *k, int ksz, void (*fr)(void *))
{
	struct hashbucket *hb;

	if ((hb = hash_get(h, k, ksz)) == NULL)
		return 0;
	hashbucket_remove(h, hb, fr);
	return 1;
}

void
hashbucket_remove(struct hash *h __attribute__ ((unused)), struct hashbucket *hb,
    void (*fr)(void *))
{

	if (fr != NULL)
		(*fr)(hb->val);
	LIST_REMOVE(hb, siblings);
	myfree(hb->k);
	myfree(hb);
}

void *
hashbucket_get_val(struct hashbucket *hb)
{

	return hb->val;
}

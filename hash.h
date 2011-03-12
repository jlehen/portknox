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
 * $Id: hash.h,v 1.1 2011/03/12 18:12:16 jlh Exp $
 */

#ifndef _HASH_H_
#define _HASH_H_
#include <sys/types.h>
#include <stdint.h>

struct hashbucket;
struct hash;

struct hash *hash_create(int n);
void hash_destroy(struct hash *h, void (*fr)(void *));
struct hashbucket *hash_add(struct hash *h, char *k, int ksz, void *p);
struct hashbucket *hash_get(struct hash *h, char *k, int ksz);
void *hash_get_val(struct hash *h, char *k, int ksz, struct hashbucket **hb);
int hash_remove(struct hash *h, char *k, int ksz, void (*fr)(void *));
void hashbucket_remove(struct hash *h, struct hashbucket *hb, void (*fr)(void *));
void *hashbucket_val(struct hashbucket *hb);

/* "sk" stands for scalar key */
#define hash_add_sk(h, k, p)	hash_add(h, (char *)&k, sizeof (k), p)
#define hash_get_sk(h, k)	hash_get(h, (char *)&k, sizeof (k))
#define hash_get_val_sk(h, k, hb) hash_get_val(h, (char *)&k, sizeof (k), hb)
#define hash_remove_sk(h, k, fr) hash_remove(h, (char *)&k, sizeof (k), fr)

#endif /* !_HASH_H_ */

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
 * $Id: faststring.c,v 1.8 2011/03/16 21:05:10 jlh Exp $
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"
#include "faststring.h"

#include <stdio.h>
#ifdef DMALLOC
#include <dmalloc.h>
#endif

struct _faststring {
	char *begin;
	char *end;
	int initlen;
	int maxlen;
};

#define FASTSTRING_ADDC(fsp, c) \
	do { \
		*fsp->p->end++ = c; \
		if (fsp->p->end == fsp->p->begin + fsp->p->maxlen) \
			faststring_extend(fsp); \
		*fsp->p->end = '\0'; \
	} while (0)

static faststring *
faststring_extend(faststring *fs)
{
	int end;

	end = fs->p->end - fs->p->begin;
	fs->p->begin = myrealloc(fs->p->begin, fs->p->maxlen + fs->p->initlen,
	    "buffer in faststring");
	fs->p->end = fs->p->begin + end;
	fs->p->maxlen += fs->p->initlen;
	return fs;
}

faststring *
faststring_alloc(faststring *fs, int size)
{

	assert(fs->p == FASTSTRING_UNALLOCED);
	fs->p = mymalloc(sizeof (struct _faststring), "faststring");
	fs->p->begin = mymalloc((size_t)size, "buffer in faststring");
	fs->p->end = fs->p->begin;
	fs->p->initlen = size;
	fs->p->maxlen = size;
	*fs->p->begin = '\0';
	return fs;
}

void
faststring_free(faststring *fs)
{
	char *s;

	assert(fs->p != FASTSTRING_UNALLOCED);
	s = faststring_export(fs);
	myfree(s);
}

faststring *
faststring_strcpy(faststring *dst, const char *src)
{
	
	assert(dst->p != FASTSTRING_UNALLOCED);
	dst->p->end = dst->p->begin;
	*dst->p->begin = '\0';
	return faststring_strcat(dst, src);
}

faststring *
faststring_strncpy(faststring *dst, const char *src, int len)
{
	
	assert(dst->p != FASTSTRING_UNALLOCED);
	dst->p->end = dst->p->begin;
	*dst->p->begin = '\0';
	return faststring_strncat(dst, src, len);
}

faststring *
faststring_strcat(faststring *dst, const char *src)
{

	assert(dst->p != FASTSTRING_UNALLOCED);
	while (*src != '\0')
		FASTSTRING_ADDC(dst, *src++);
	return dst;
}

faststring *
faststring_strncat(faststring *dst, const char *src, int len)
{

	assert(dst->p != FASTSTRING_UNALLOCED);
	while (*src != '\0' && len-- > 0) {
		FASTSTRING_ADDC(dst, *src++);
	}
	return dst;
}

faststring *
faststring_strdup(faststring *fs, const char *s)
{

	assert(fs->p == FASTSTRING_UNALLOCED);
	faststring_alloc(fs, (int)strlen(s));
	return faststring_strcpy(fs, s);
}

char *
faststring_peek(const faststring *fs)
{

	assert(fs->p != FASTSTRING_UNALLOCED);
	return fs->p->begin;
}

int
faststring_update(faststring *fs)
{

	char *s;

	assert(fs->p != FASTSTRING_UNALLOCED);
	for (s = fs->p->begin; *s != '\0'; s++)
		;
	fs->p->end = s;
	return fs->p->end - fs->p->begin;
}

char *
faststring_export(faststring *fs)
{
	char *s;

	assert(fs->p != FASTSTRING_UNALLOCED);
	s = fs->p->begin;
	/*
	fs->p->begin = fs->p->end = FASTSTRING_UNALLOCED;
	fs->p->maxlen = fs->p->initlen = (int)FASTSTRING_UNALLOCED;
	*/
	myfree(fs->p);
	fs->p = FASTSTRING_UNALLOCED;
	return s;
}

int
faststring_strlen(const faststring *fs)
{

	assert(fs->p != FASTSTRING_UNALLOCED);
	return fs->p->end - fs->p->begin;
}

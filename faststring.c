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
 * $Id: faststring.c,v 1.7 2011/03/13 10:42:53 jlh Exp $
 */

#include <stdlib.h>
#include <string.h>
#include "util.h"
#include "faststring.h"

#include <stdio.h>
#ifdef DMALLOC
#include <dmalloc.h>
#endif

#define FASTSTRING_ADDC(fsp, c) \
	do { \
		*fsp->end++ = c; \
		if (fsp->end == fsp->begin + fsp->maxlen) \
			faststring_extend(fsp); \
		*fsp->end = '\0'; \
	} while (0)

static faststring *
faststring_extend(faststring *fs)
{
	int end;

	end = fs->end - fs->begin;
	fs->begin = myrealloc(fs->begin, fs->maxlen + fs->initlen,
	    "buffer in faststring");
	fs->end = fs->begin + end;
	fs->maxlen += fs->initlen;
	return fs;
}

faststring *
faststring_alloc(int size)
{
	faststring *new;

	new = mymalloc(sizeof (faststring), "faststring");
	new->begin = mymalloc((size_t)size, "buffer in faststring");
	new->end = new->begin;
	new->initlen = size;
	new->maxlen = size;
	*new->begin = '\0';
	return new;
}

void
faststring_free(faststring *fs)
{
	char *s;

	s = faststring_export(fs);
	myfree(s);
}

faststring *
faststring_strcpy(faststring *dst, const char *src)
{
	
	dst->end = dst->begin;
	*dst->begin = '\0';
	return faststring_strcat(dst, src);
}

faststring *
faststring_strncpy(faststring *dst, const char *src, int len)
{
	
	dst->end = dst->begin;
	*dst->begin = '\0';
	return faststring_strncat(dst, src, len);
}

faststring *
faststring_strcat(faststring *dst, const char *src)
{
	while (*src != '\0')
		FASTSTRING_ADDC(dst, *src++);
	return dst;
}

faststring *
faststring_strncat(faststring *dst, const char *src, int len)
{

	while (*src != '\0' && len-- > 0) {
		FASTSTRING_ADDC(dst, *src++);
	}
	return dst;
}

faststring *
faststring_strdup(const char *s)
{
	faststring *fs;

	fs = faststring_alloc((int)strlen(s));
	return faststring_strcpy(fs, s);
}

char *
faststring_peek(const faststring *fs)
{

	return fs->begin;
}

int
faststring_update(faststring *fs)
{

	char *s;

	for (s = fs->begin; *s != '\0'; s++)
		;
	fs->end = s;
	return fs->end - fs->begin;
}

char *
faststring_export(faststring *fs)
{
	char *s;

	s = fs->begin;
	fs->begin = fs->end = (void *)0x14111980;
	fs->maxlen = fs->initlen = 14119180;
	myfree(fs);
	return s;
}

int
faststring_strlen(const faststring *fs)
{

	return fs->end - fs->begin;
}

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
 * $Id: util.c,v 1.5 2010/11/09 21:37:08 jlh Exp $
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif

void *
mymalloc(size_t size, const char *desc)
{
	void *res;

	res = malloc(size);
	if (res == NULL)
		err(2, "Cannot allocate %s (%zu bytes)", desc, size);
	/*
	fprintf(stderr, "DEBUG: alloc %4zu bytes: %p (%s)\n", size, res, desc);
	*/
	return res;
}

void *
myrealloc(void *ptr, size_t size, const char *desc)
{
	void *res;

	res = realloc(ptr, size);
	if (res == NULL)
		err(2, "Cannot reallocate %s (%zu bytes)", desc, size);
	/*
	fprintf(stderr, "DEBUG: realloc %p to %03zu bytes: %p (%s)\n", ptr, size, res, desc);
	*/
	return res;
}

void
myfree(void *ptr)
{

	/*
	fprintf(stderr, "DEBUG: free %p\n", ptr);
	*/
	free(ptr);
}

char *
mystrdup(const char *str)
{
	char * res;

	res = strdup(str);
	if (res == NULL)
		err(2, "Cannot duplicate string (%zu bytes)", strlen(str));
	return res;
}

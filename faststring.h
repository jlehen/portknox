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
 * $Id: faststring.h,v 1.8 2011/03/13 10:38:38 jlh Exp $
 */

#ifndef _FASTSTRING_H_
#define _FASTSTRING_H_

typedef struct {
	char *begin;
	char *end;
	int initlen;
	int maxlen;
} faststring;

/* Alloc size includes the final '\0'. */
extern faststring *faststring_alloc(int);
extern void faststring_free(faststring *);
extern faststring *faststring_strcpy(faststring *, const char *);
extern faststring *faststring_strncpy(faststring *, const char *, int);
extern faststring *faststring_strcat(faststring *, const char *);
extern faststring *faststring_strncat(faststring *, const char *, int);
extern faststring *faststring_strdup(const char *);
extern char *faststring_peek(const faststring *);
/* Update structure if the inner string has been modified. */
int faststring_update(faststring *);
/* Frees the faststring wrapper struct. */
extern char *faststring_export(faststring *);
int faststring_strlen(const faststring *);

#endif /* !_FASTSTRING_H_ */

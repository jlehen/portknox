#include <stdlib.h>
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

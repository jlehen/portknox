#include <err.h>
#include <stdio.h>
#include <stdlib.h>
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
	fprintf(stderr, "DEBUG: alloc %03zu bytes: %p (%s)\n", size, res, desc);
	return res;
}

void *
myrealloc(void *ptr, size_t size, const char *desc)
{
	void *res;

	res = realloc(ptr, size);
	if (res == NULL)
		err(2, "Cannot reallocate %s (%zu bytes)", desc, size);
	fprintf(stderr, "DEBUG: realloc %p to %03zu bytes: %p (%s)\n", ptr, size, res, desc);
	return res;
}

void
myfree(void *ptr)
{

	fprintf(stderr, "DEBUG: free %p\n", ptr);
	free(ptr);
}

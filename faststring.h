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
extern char *faststring_peek(faststring *);
/* Frees the faststring wrapper struct. */
extern char *faststring_export(faststring *);
int faststring_strlen(const faststring *);

#endif /* !_FASTSTRING_H_ */

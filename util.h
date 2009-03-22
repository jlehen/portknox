#ifndef _UTIL_H_
#define _UTIL_H_

extern void *mymalloc(size_t size, const char *desc);
extern void *myrealloc(void *ptr, size_t size, const char *desc);
extern void myfree(void *ptr);

#endif /* !_UTIL_H_ */

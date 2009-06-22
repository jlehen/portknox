CFLAGS+= -Wall -W -g3
SRCS= main.c conf.c faststring.c util.c log.c
OBJS= ${SRCS:.c=.o}

ifdef DMALLOC
CFLAGS+= -I/usr/local/include -DDMALLOC -DDMALLOC_FUNC_CHECK
LDFLAGS+= -L/usr/local/lib -ldmalloc
endif

ifdef SNOOP
CFLAGS+= -DSNOOP=1
LDFLAGS+= -lpcap
endif

all: portknox

portknox: ${OBJS}
	${CC} ${LDFLAGS} -o $@ ${OBJS}

main.o: main.c
conf.o: conf.c
faststring.o: faststring.c
util.o: util.c

clean:
	rm -f portknox ${OBJS}

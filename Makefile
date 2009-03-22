CFLAGS+= -Wall -W -g3
SRCS= main.c faststring.c util.c
OBJS= ${SRCS:.c=.o}

#CFLAGS+= -I/usr/local/include -DDMALLOC -DDMALLOC_FUNC_CHECK
#LDFLAGS+= -L/usr/local/lib -ldmalloc

all: portknox

portknox: ${OBJS}
	${CC} ${LDFLAGS} -o $@ ${OBJS}

main.o: main.c
faststring.o: faststring.c
util.o: util.c

clean:
	rm -f portknox ${OBJS}

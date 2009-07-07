#
# Copyright (c) 2009 Jeremie LE HEN
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# $Id: BSDmakefile,v 1.4 2009/07/07 21:32:02 jlh Exp $

CFLAGS+= -Wall -W -g3
SRCS= main.c conf.c faststring.c util.c log.c
OBJS= ${SRCS:.c=.o}

.ifdef DMALLOC
CFLAGS+= -I/usr/local/include -DDMALLOC -DDMALLOC_FUNC_CHECK
LDFLAGS+= -L/usr/local/lib -ldmalloc
.endif

.ifndef NOSNOOP
CFLAGS+= -DSNOOP=1
LDFLAGS+= -lpcap
.endif

all: portknox

portknox: ${OBJS}
	${CC} ${LDFLAGS} -o $@ ${OBJS}

main.o: main.c
conf.o: conf.c
faststring.o: faststring.c
util.o: util.c

clean:
	rm -f portknox ${OBJS}

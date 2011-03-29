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
 * $Id: log.h,v 1.3 2011/03/29 21:08:19 jlh Exp $
 */

#ifndef _LOG_H_
#define _LOG_H_

void setDebug();
void exitOnError();
void setLogFacility(const char *s);
void openLog(const char *basename);
void mylog(int status, int prio, const struct janitor *j, const char *errstr,
    const char *fmt, ...);

#define	e(s, j, fmt, ...)	\
    mylog(s, LOG_ERR, j, strerror(errno), fmt, ## __VA_ARGS__)
#define	ex(s, j, fmt, ...)	\
    mylog(s, LOG_ERR, j, NULL, fmt, ## __VA_ARGS__)
#define	w(j, fmt, ...)		\
    mylog(-1, LOG_WARNING, j, strerror(errno), fmt, ## __VA_ARGS__)
#define	wx(j, fmt, ...)		\
    mylog(-1, LOG_WARNING, j, NULL, fmt, ## __VA_ARGS__)
#define n(j, fmt, ...)		\
    mylog(-1, LOG_NOTICE, j, strerror(errno), fmt, ## __VA_ARGS__)
#define	nx(j, fmt, ...)		\
    mylog(-1, LOG_NOTICE, j, NULL, fmt, ## __VA_ARGS__)
#define	i(j, fmt, ...)		\
    mylog(-1, LOG_INFO, j, strerror(errno), fmt, ## __VA_ARGS__)
#define	ix(j, fmt, ...)		\
    mylog(-1, LOG_INFO, j, NULL, fmt, ## __VA_ARGS__)
#define verb(j, fmt, ...)	\
    mylog(-1, LOG_INFO, j, NULL, fmt, ## __VA_ARGS__)


#endif /* !_LOG_H_ */

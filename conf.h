#ifndef _CONF_H_
#define _CONF_H_

struct action {
	int timeout;
	char *cmd;
	struct action *next;
};

struct janitor {
	struct janitor *next;
	int line;
	char *ip;			
	char *port;
	char *proto;
	int sock;
	struct addrinfo *addrinfo;
	struct action *actions;

	/* Usage wheel. */
	short *uswheel;
	int uswheelsz;
	int usmax;
	int uscur;
};

extern int read_conf(const char *, struct janitor **);

#endif /* !_CONF_H_ */

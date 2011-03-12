#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include "hash.h"

int
main(int ac, char *av[])
{
	struct in_addr inp;
	struct hash *iph;
	char cmd[128], ip[128];
	int n, i;

	iph = hash_create(10);
	n = 0;
	while (1) {
		printf("> ");
		fflush(stdout);
		i = scanf("%s %s", cmd, ip);
		if (i != 2)
			break;
		if (!inet_aton(ip, &inp))
			continue;
		n++;
		if (!strcmp(cmd, "add")) {
			printf("storing %s -> %d\n", ip, n);
			if (hash_add_sk(iph, inp.s_addr, (void *)n))
				printf("succeeded\n");
			else
				printf("failed\n");
			continue;
		}
		if (!strcmp(cmd, "get")) {
			i = (int)hash_get_val_sk(iph, inp.s_addr, NULL);
			if ((void *)i == NULL)
				printf("(null)\n");
			else
				printf("getting %s -> %d\n", ip, i);
		}
		if (!strcmp(cmd, "remove")) {
			if (hash_remove_sk(iph, inp.s_addr, NULL))
				printf("succeeded\n");
			else
				printf("failed\n");
		}
	}
}

// This is a test program that opens a Homa socket and responds to
// requests.
//
// Usage: homaServer port

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "homa.h"
#include "test_utils.h"

int main(int argc, char** argv) {
	int fd;
	int port;
	struct sockaddr_in addr_in;
	int message[100000];
	struct sockaddr_in source;
	int length;
	
	if (argc < 2) {
		printf("Usage: %s port\n", argv[0]);
		exit(1);
	}
	port = strtol(argv[1], NULL, 10);
	if (port == 0) {
		printf("Bad port number %s; must be positive integer\n",
				argv[1]);
		exit(1);
	}
	
	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_HOMA);
	if (fd < 0) {
		printf("Couldn't open Homa socket: %s\n", strerror(errno));
		exit(1);
	}
	
	memset(&addr_in, 0, sizeof(addr_in));
	addr_in.sin_family = AF_INET;
	addr_in.sin_port = htons(port);
	if (bind(fd, (struct sockaddr *) &addr_in, sizeof(addr_in)) != 0) {
		printf("Couldn't bind socket to Homa port %d: %s\n", port,
				strerror(errno));
		exit(1);
	}
	printf("Successfully bound to Homa port %d\n", port);
	while (1) {
		uint64_t id;
		int seed;
		int result;
		
		length = homa_recv(fd, message, sizeof(message),
			(struct sockaddr *) &source, sizeof(source), &id);
		if (length < 0) {
			printf("Recvmsg failed: %s\n", strerror(errno));
			continue;
		}
		seed = check_buffer(message, length);
		printf("Received message from %s with %d bytes, "
			"seed %d, id %lu\n",
			print_address(&source),length, seed, id);
		result = homa_reply(fd, message, length,
			(struct sockaddr *) &source, sizeof(source), id);
		if (result < 0) {
			printf("Homa_reply failed: %s\n", strerror(errno));
		}
	}
}

#include <stdio.h>
#include <stdlib.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>

void read_packet(int);
int process_packet(uint8_t *, ssize_t);

int main(int argc, char **argv) 
{
	int sock, status;
	char *opt = argv[1];
	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (sock < 0) {
		perror("socket");
		exit(1);	
	}
	
	struct sockaddr_ll sll = {
        	.sll_family = AF_PACKET,
        	.sll_protocol = htons(ETH_P_ALL),
        	.sll_ifindex = if_nametoindex(opt),
	};

	if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
		perror("bind");
		exit(1);
	}

	struct packet_mreq mreq = {
		.mr_ifindex = if_nametoindex(opt),
		.mr_type = PACKET_MR_PROMISC,	
	};

	if(setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) != 0) {
		perror("setsockopt promiscuous mode");
		
	}

	read_packet(sock);	
	
	return 0;
}

void read_packet(int sock) 
{
	int status;
	uint8_t buf[65536];
	while(1) {
		ssize_t n = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
		
		status = process_packet(buf, n);

		if(status != 0) {
			perror("packet processing");
			exit(1);
		}
	}
}

int process_packet(uint8_t *buf, ssize_t n) 
{
	struct ethhdr *eth = (struct ethhdr *)buf;

	printf("src: %02x:%02x:%02x:%02x:%02x:%02x\ndst: %02x:%02x:%02x:%02x:%02x:%02x\nproto: 0x%04x\n",eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5], eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5], ntohs(eth->h_proto));
	
	return 0;
}



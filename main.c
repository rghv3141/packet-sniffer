#include <stdio.h>
#include <stdlib.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <linux/ipv6.h>

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

	printf("src mac: %02x:%02x:%02x:%02x:%02x:%02x -> dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n",eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5], eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	
	if(ntohs(eth->h_proto) == 0x0800) {
		uint8_t *ip = buf + sizeof(struct ethhdr);
		struct iphdr *ip_hdr = (struct iphdr *)ip;
		
		char src[INET_ADDRSTRLEN];
		if(inet_ntop(AF_INET, &ip_hdr->saddr, src, INET_ADDRSTRLEN) == NULL) {
			perror("inet_ntop() ipv4");
		}
		else printf("src IPv4: %s -> ", src);

		char dest[INET_ADDRSTRLEN];
		if(inet_ntop(AF_INET, &ip_hdr->daddr, dest, INET_ADDRSTRLEN) == NULL) {
			perror("inet_ntop()");
                }
                else printf("dest IPv4: %s\n", dest);

	}

	else if (ntohs(eth->h_proto) == 0x0806) {
		struct ipv6hdr *ip6_h = (struct ipv6hdr *)(buf + sizeof(struct ethhdr));

		char src[INET6_ADDRSTRLEN];
		if(inet_ntop(AF_INET6, &ip6_h->saddr, src, sizeof(src)) == NULL) perror("inet_ntop ipv6");
		else printf("src IPv6: %s -> ", src);

		char dest[INET6_ADDRSTRLEN];
                if(inet_ntop(AF_INET6, &ip6_h->daddr, dest, sizeof(dest)) == NULL) perror("inet_ntop ipv6");
                else printf("dest IPv6: %s\n", dest); 
	} 	

	return 0;
}



#include <linux/if_ether.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <linux/ipv6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/types.h>
#include <linux/filter.h>

void read_packet(int);
int process_packet(uint8_t *, ssize_t);
void parse_eth(struct ethhdr *);
void parse_ipv4(struct ethhdr *, uint8_t *);
void parse_ipv6(struct ethhdr *, uint8_t *);
void parse_tcp(uint8_t *);
void parse_udp(uint8_t *);
void bpf_filter(int);

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
	bpf_filter(sock); 
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
	parse_eth(eth);
//	printf("0x%04x\n",ntohs(eth->h_proto));

	if(ntohs(eth->h_proto) == 0x0800) {
		parse_ipv4(eth, buf);
	}

	else if (ntohs(eth->h_proto) == 0x86dd) {
		parse_ipv6(eth, buf);
	}
	return 0;
}



void parse_eth(struct ethhdr *eth) {
	printf("src mac: %02x:%02x:%02x:%02x:%02x:%02x -> dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n",eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5], eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
}


void parse_ipv4(struct ethhdr *eth, uint8_t buf[]) {
	uint8_t *ip = buf + sizeof(struct ethhdr);
	struct iphdr *ip_hdr = (struct iphdr *)ip;
	uint8_t *p = buf + sizeof(struct ethhdr) + ip_hdr->ihl*4;
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

	if(ip_hdr->protocol == 6) {
		parse_tcp(p);
	}
	if(ip_hdr->protocol == 17) {
		parse_udp(p);
	}
}


void parse_ipv6(struct ethhdr *eth, uint8_t *buf) {
    	struct ipv6hdr *ip6_h = (struct ipv6hdr *)(buf + sizeof(struct ethhdr));
	uint8_t *p = buf + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
	char src[INET6_ADDRSTRLEN];
	if(inet_ntop(AF_INET6, &ip6_h->saddr, src, sizeof(src)) == NULL) perror("inet_ntop ipv6");
	else printf("src IPv6: %s -> ", src);

	char dest[INET6_ADDRSTRLEN];
        if(inet_ntop(AF_INET6, &ip6_h->daddr, dest, sizeof(dest)) == NULL) perror("inet_ntop ipv6");
        else printf("dest IPv6: %s\n", dest);

	if(ip6_h->nexthdr == 6) {
		parse_tcp(p);
	}
	if(ip6_h->nexthdr == 17) {
		parse_udp(p);
	}
}

void parse_tcp(uint8_t *tcp) 
{
	struct tcphdr *tcp_h = (struct tcphdr *)tcp;

	uint16_t src_port = ntohs(tcp_h->source);
	uint16_t dest_port = ntohs(tcp_h->dest);

	printf("TCP src port: %d -> ", src_port);
	printf("TCP dest port: %d\n\n", dest_port);
}

void parse_udp(uint8_t *udp) 
{
	struct udphdr *udp_h = (struct udphdr *)udp;

	uint16_t src_port = ntohs(udp_h->source);
	uint16_t dest_port = ntohs(udp_h->dest);

	printf("UDP src port: %d -> ", src_port);
	printf("UDP dest port: %d\n\n", dest_port);
}

void bpf_filter(int sock) 
{
	struct sock_filter code[] = {
        { 0x28,  0,  0, 0x0000000c },	//0  	Load ethertype 
        { 0x15,  0,  3, 0x000086dd },	//1	compare with Ipv6		
        { 0x30,  0,  0, 0x00000014 },	//2	load protocol for ipv6
        { 0x15,  5,  0, 0x00000006 },	//3	for TCP
        { 0x15,  4,  5, 0x00000011 },	//4	for UDP if not UDP, reject
        { 0x15,  0,  4, 0x00000800 },	//5	check if Ipv4
        { 0x30,  0,  0, 0x00000017 },	//6	Load protocol
        { 0x15,  1,  0, 0x00000006 },	//7	for tcp
	{ 0x15,  0,  1, 0x00000011 },	//8	for udp 
	{ 0x06,  0,  0, 0x0000ffff },	//9	accept packet
	{ 0x06,  0,  0, 0x00000000 },	//10	drop packet
	};
	
	struct sock_fprog bpf = {
        .len = sizeof(code)/sizeof(code[0]),
        .filter = code,
	};
	
	int ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));

	if (ret < 0) {
		perror("setsockopt bpf_filter");
		exit(1);
	}
}


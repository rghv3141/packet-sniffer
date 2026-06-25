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
#include <signal.h>
#include "main.h"
#include "tcp_state.h"
#include "talkers.h"
#include "scan-detector.h"
#include <string.h>

int main(int argc, char **argv)
{
	signal(SIGINT, sigint_handler);
	int sock, status;
	char *interface = argv[1]; 
	if(argc != 3) {
		fprintf(stderr, "Usage: ./sniffer <interface> [cature | tcp | talkers | scan]\n");
		return 1;
	}	
	enum mode mode = parse_mode(argv[2]);
	
	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (sock < 0) {
		perror("socket");
		exit(1);
	}

	struct sockaddr_ll sll = {
        	.sll_family = AF_PACKET,
        	.sll_protocol = htons(ETH_P_ALL),
        	.sll_ifindex = if_nametoindex(interface),
	};

	if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
		perror("bind");
		exit(1);
	}

	struct packet_mreq mreq = {
		.mr_ifindex = if_nametoindex(interface),
		.mr_type = PACKET_MR_PROMISC,
	};

	if(setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) != 0) {
		perror("setsockopt promiscuous mode");

	}
	bpf_filter(sock, mode); 
	read_packet(sock, mode);
	return 0;
}

enum mode parse_mode(const char *arg) {
	if(strcmp(arg, "capture") == 0)
		return MODE_CAPTURE;
	if(strcmp(arg, "tcp") == 0)
		return MODE_TCP;
	if(strcmp(arg, "talkers") == 0)
		return MODE_TALKERS;
	if(strcmp(arg, "scan") == 0)
		return MODE_SCAN;
	fprintf(stderr, "Usage: ./sniffer <interface> [capture|tcp|talkers|scan]\n");
	exit(EXIT_FAILURE);	
}

void read_packet(int sock, enum mode mode)
{
	int status;
	uint8_t buf[65536];
	while(1) {
		ssize_t n = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);

		status = process_packet(buf, mode, n);

		if(status != 0) {
			perror("packet processing");
			exit(1);
		}
	}
}

int process_packet(uint8_t *buf, enum mode mode, ssize_t n)
{	
	struct packet_info info;
	struct packet_info *pkt = &info;
	struct ethhdr *eth = (struct ethhdr *)buf;
	parse_eth(eth);
//	printf("0x%04x\n",ntohs(eth->h_proto));
	struct syn_source syn;
	if(ntohs(eth->h_proto) == 0x0800) {
		pkt->ipv6 = 0;
		syn.ipv6 = 0;
		parse_ipv4(eth, buf, pkt, &syn, mode, n);
	}

	else if (ntohs(eth->h_proto) == 0x86dd) {
		pkt->ipv6 = 1;
		syn.ipv6 = 1;
		parse_ipv6(eth, buf, pkt, &syn, mode, n);
	}
	return 0;
}



void parse_eth(struct ethhdr *eth) {
	printf("src mac: %02x:%02x:%02x:%02x:%02x:%02x -> dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n",eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5], eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
}


void parse_ipv4(struct ethhdr *eth, uint8_t buf[], struct packet_info *pkt, struct syn_source *syn, enum mode mode, ssize_t n) {
	
	uint8_t *ip = buf + sizeof(struct ethhdr);
	struct iphdr *ip_hdr = (struct iphdr *)ip;
	uint8_t *p = buf + sizeof(struct ethhdr) + ip_hdr->ihl*4;
	char src[INET_ADDRSTRLEN];
	if(inet_ntop(AF_INET, &ip_hdr->saddr, src, INET_ADDRSTRLEN) == NULL) {
		perror("inet_ntop() ipv4");
	}
	else printf("src IPv4: %s -> ", src);

	pkt->ipv4_src = ip_hdr->saddr;
	syn->ipv4_src = ip_hdr->saddr;
	
	char dest[INET_ADDRSTRLEN];
	if(inet_ntop(AF_INET, &ip_hdr->daddr, dest, INET_ADDRSTRLEN) == NULL) {
		perror("inet_ntop()");
        }
        else printf("dest IPv4: %s\n", dest);
	
	pkt->ipv4_dest = ip_hdr->daddr;	

	if(ip_hdr->protocol == 6) {
		parse_tcp(p, pkt, syn, mode, n);
	}
	if(ip_hdr->protocol == 17) {
		parse_udp(p, pkt, mode, n);
	}
}


void parse_ipv6(struct ethhdr *eth, uint8_t *buf, struct packet_info *pkt, struct syn_source *syn, enum mode mode, ssize_t n) {
    	
	struct ipv6hdr *ip6_h = (struct ipv6hdr *)(buf + sizeof(struct ethhdr));
	uint8_t *p = buf + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
	char src[INET6_ADDRSTRLEN];
	if(inet_ntop(AF_INET6, &ip6_h->saddr, src, sizeof(src)) == NULL) perror("inet_ntop ipv6");
	else printf("src IPv6: %s -> ", src);

	pkt->ipv6_src = ip6_h->saddr;
	syn->ipv6_src = ip6_h->saddr;

	char dest[INET6_ADDRSTRLEN];
        if(inet_ntop(AF_INET6, &ip6_h->daddr, dest, sizeof(dest)) == NULL) perror("inet_ntop ipv6");
        else printf("dest IPv6: %s\n", dest);
	
	pkt->ipv6_dst = ip6_h->daddr;

	if(ip6_h->nexthdr == 6) {
		parse_tcp(p, pkt, syn, mode, n);
	}
	if(ip6_h->nexthdr == 17) {
		parse_udp(p, pkt, mode, n);
	}
}

void parse_tcp(uint8_t *tcp, struct packet_info *pkt, struct syn_source *syn, enum mode mode, ssize_t n) 
{
	struct tcphdr *tcp_h = (struct tcphdr *)tcp;

	pkt->src_port = ntohs(tcp_h->source);
	syn->port = ntohs(tcp_h->dest);
	pkt->dst_port = ntohs(tcp_h->dest);

	printf("TCP src port: %d -> ", pkt->src_port);
	printf("TCP dest port: %d\n", pkt->dst_port);
	switch (mode) {

        	case MODE_TCP:
                	update_tcp_conn(tcp_h, pkt, n);
                	break;

        	case MODE_TALKERS:
                	update_talkers(pkt, n);
                	break;

       	 	case MODE_SCAN:
         	       	if (tcp_h->syn && !tcp_h->ack)
                	        update_syn_entry(syn);
			break;

        	case MODE_CAPTURE:
                	break;
        }
}

void parse_udp(uint8_t *udp, struct packet_info *pkt, enum mode mode, ssize_t n) 
{
	struct udphdr *udp_h = (struct udphdr *)udp;

	pkt->src_port = ntohs(udp_h->source);
	pkt->dst_port = ntohs(udp_h->dest);

	printf("UDP src port: %d -> ", pkt->src_port);
	printf("UDP dest port: %d\n\n", pkt->dst_port);
	if(mode == MODE_TALKERS)
		update_talkers(pkt, n);
}

void bpf_filter(int sock, enum mode mode) 
{	
	if (mode == MODE_CAPTURE || mode == MODE_TALKERS) {
		struct sock_filter code1[] = {
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
	
		struct sock_fprog bpf1 = {
        		.len = sizeof(code1)/sizeof(code1[0]),
       			.filter = code1,
			};
	
		int ret1 = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf1, sizeof(bpf1));

		if (ret1 < 0) {
			perror("setsockopt bpf_filter");
			exit(1);
		}
	}
	if (mode == MODE_TCP || mode == MODE_SCAN) {
		struct sock_filter code2[] = {
        	{ 0x28,  0,  0, 0x0000000c },	//0  	Load ethertype 
        	{ 0x15,  0,  2, 0x000086dd },	//1	compare with Ipv6		
        	{ 0x30,  0,  0, 0x00000014 },	//2	load protocol for ipv6
        	{ 0x15,  3,  4, 0x00000006 },	//3	for TCP
        	{ 0x15,  0,  3, 0x00000800 },	//5	check if Ipv4
        	{ 0x30,  0,  0, 0x00000017 },	//6	Load protocol
        	{ 0x15,  0,  1, 0x00000006 },	//7	for tcp
		{ 0x06,  0,  0, 0x0000ffff },	//9	accept packet
		{ 0x06,  0,  0, 0x00000000 },	//10	drop packet
		};
	
		struct sock_fprog bpf2 = {
        		.len = sizeof(code2)/sizeof(code2[0]),
        		.filter = code2,
		};
	
		int ret2 = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf2, sizeof(bpf2));
		if (ret2 < 0) {
			perror("setsockopt bpf_filter");
			exit(1);
		}
	}
}
void sigint_handler(int sig) {
	(void)sig;
	
	print_top_talkers();

	exit(0);
}

#include <stdint.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <linux/if_ether.h>
#include <netinet/in.h>

struct packet_info {
	uint8_t ipv6;
	
	union {
		uint32_t ipv4_src;
		struct in6_addr ipv6_src;
	};
	
	union {
		uint32_t ipv4_dest;
		struct in6_addr ipv6_dst;
	};
	
	uint16_t src_port;
	uint16_t dst_port;

	uint8_t tcp_flags;
};	

void read_packet(int);
int process_packet(uint8_t *, ssize_t);
void parse_eth(struct ethhdr *);
void parse_ipv4(struct ethhdr *, uint8_t *, ssize_t);
void parse_ipv6(struct ethhdr *, uint8_t *, ssize_t);
void parse_tcp(uint8_t *, struct packet_info *, ssize_t);
void parse_udp(uint8_t *);
void bpf_filter(int);

#include "main.h"
#include "tcp_state.h"

#define MAX_TALKERS 1024

struct talker talkers[MAX_TALKERS];
ssize_t talker_count = 0;

void update_talkers(struct packet_info *pkt, ssize_t n) {
	struct talker *tak = find_talker(pkt);
	if(tak == NULL) {
		create_talker(pkt, n);
	} else {
		tak->bytes += n;	
	}
}

struct talker *find_talker(struct packet_info *pkt) {
	for(int i = 0; i < talker_count; i++) {
		
		if(talkers[i].key.ipv6 != pkt->ipv6) continue;
		if(!pkt->ipv6) {
			if (talkers[i].key.ipv4_src == pkt->ipv4_src && talkers[i].key.ipv4_dest == pkt->ipv4_dest && talkers[i].key.src_port  == pkt->src_port  && talkers[i].key.dst_port  == pkt->dst_port) {
					return &talkers[i];
			}
			if (talkers[i].key.ipv4_src == pkt->ipv4_dest && talkers[i].key.ipv4_dest == pkt->ipv4_src && talkers[i].key.src_port  == pkt->dst_port  && talkers[i].key.dst_port  == pkt->src_port) {
					return &talkers[i];
			}
		}
		else {
			if (memcmp(&talkers[i].key.ipv6_src, &pkt->ipv6_src, sizeof(struct in6_addr)) == 0 && memcmp(&talkers[i].key.ipv6_dst, &pkt->ipv6_dst, sizeof(struct in6_addr)) == 0 && talkers[i].key.src_port == pkt->src_port && talkers[i].key.dst_port == pkt->dst_port){
    				return &talkers[i];
			}
			if (memcmp(&talkers[i].key.ipv6_src, &pkt->ipv6_dst, sizeof(struct in6_addr)) == 0 && memcmp(&talkers[i].key.ipv6_dst, &pkt->ipv6_src, sizeof(struct in6_addr)) == 0 && talkers[i].key.src_port == pkt->dst_port && talkers[i].key.dst_port == pkt->src_port){
    				return &talkers[i];
			}
		}
	}
	return NULL;
}

void create_talker(struct packet_info *pkt, ssize_t n) {
	if(talker_count >= MAX_TALKERS) return;
	struct talker *tak = &talkers[talker_count++];
	tak->key = *pkt;
	tak->bytes = (uint64_t)n;
}

int compare_talker(const void *a, const void *b) {
	const struct talker *ta = a;
	const struct talker *tb = b;

	if (ta->bytes < tb->bytes) 
		return 1;

	if (ta->bytes > tb->bytes)
		return -1;
	return 0;
}

void print_top_talkers() {
	qsort(talkers, talker_count, sizeof(struct talker), compare_talker);

	
}	


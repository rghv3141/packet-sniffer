#include "tcp_state.h"
#include <string.h>
#include <stdio.h>
#define MAX_CONNECTIONS 128

struct tcp_connection connections[MAX_CONNECTIONS];

ssize_t connection_count = 0;

struct tcp_connection *find_connection(struct packet_info *pkt) 
{
	
	for(int i = 0; i < connection_count; i++) {
		
		if(connections[i].key.ipv6 != pkt->ipv6) continue;
		if(!pkt->ipv6) {
			if (connections[i].key.ipv4_src == pkt->ipv4_src && connections[i].key.ipv4_dest == pkt->ipv4_dest && connections[i].key.src_port  == pkt->src_port  && connections[i].key.dst_port  == pkt->dst_port) {
					return &connections[i];
			}
			if (connections[i].key.ipv4_src == pkt->ipv4_dest && connections[i].key.ipv4_dest == pkt->ipv4_src && connections[i].key.src_port  == pkt->dst_port  && connections[i].key.dst_port  == pkt->src_port) {
					return &connections[i];
			}
		}
		else {
			if (memcmp(&connections[i].key.ipv6_src, &pkt->ipv6_src, sizeof(struct in6_addr)) == 0 && memcmp(&connections[i].key.ipv6_dst, &pkt->ipv6_dst, sizeof(struct in6_addr)) == 0 && connections[i].key.src_port == pkt->src_port && connections[i].key.dst_port == pkt->dst_port){
    				return &connections[i];
			}
			if (memcmp(&connections[i].key.ipv6_src, &pkt->ipv6_dst, sizeof(struct in6_addr)) == 0 && memcmp(&connections[i].key.ipv6_dst, &pkt->ipv6_src, sizeof(struct in6_addr)) == 0 && connections[i].key.src_port == pkt->dst_port && connections[i].key.dst_port == pkt->src_port){
    				return &connections[i];
			}
		}
	}
	return NULL;
		
}

struct tcp_connection *create_connection(struct packet_info *pkt, struct tcphdr *tcp, ssize_t n)
{
	if(connection_count >= MAX_CONNECTIONS) return NULL;
	struct tcp_connection *conn = &connections[connection_count++];
	conn->key = *pkt;
	conn->bytes = (uint64_t)n;
	
	if (tcp->syn && !tcp->ack)
		conn->state = CONN_SYN_SENT;
	else if (tcp->syn && tcp->ack)
		conn->state = CONN_SYN_RECEIVED;
	else 
		conn->state = CONN_ESTABLISHED;
	printf("NEW CONNECTION\n");
	printf("CONNECTION count = %ld\n\n", connection_count);
	return conn;
}

char *tcp_state_string(enum conn_state state) {
	switch(state) {
		case CONN_SYN_SENT:
			return "SYN_SENT";
		case CONN_SYN_RECEIVED:
			return "SYN_RECEIVED";
		case CONN_ESTABLISHED:
			return "ESTABLISHED";
		case CONN_FIN_WAIT:
			return "FIN_WAIT";
		case CONN_CLOSED:
			return "CLOSED";
		default:
			return "UNKNOWN";
	}
}
void update_tcp_conn(struct tcphdr *tcp, struct packet_info *pkt, ssize_t n) 
{
//	printf("INSIDE UPDATE\n");
//	printf("flags: SYN=%d ACK=%d FIN=%d RST=%d\n", tcp->syn, tcp->ack, tcp->fin, tcp->rst);
//	fflush(stdout);
	struct tcp_connection connection;
	struct tcp_connection *conn = &connection;
	conn = find_connection(pkt);
	if(conn == NULL) {
		conn = create_connection(pkt, tcp, n);
	} else {
		printf("FOUND State\n\n");
		enum conn_state old_state = conn->state;
		conn->bytes += n;
		switch (old_state) {

        		case CONN_SYN_SENT:
                		if (tcp->syn && tcp->ack)
                        		conn->state = CONN_SYN_RECEIVED;
                		break;

        		case CONN_SYN_RECEIVED:
                		if (tcp->ack && !tcp->syn)
                        		conn->state = CONN_ESTABLISHED;
                		break;

        		case CONN_ESTABLISHED:
                		if (tcp->fin)
                        		conn->state = CONN_FIN_WAIT;
                		else if (tcp->rst)
                        		conn->state = CONN_CLOSED;
                		break;

        		case CONN_FIN_WAIT:
                		if (tcp->ack)
                        		conn->state = CONN_CLOSED;
               			break;
				
        		case CONN_CLOSED:
                		break;
		}
	//	if(old_state != conn->state) {
			printf("connection state changed: %s -> %s\n\n", tcp_state_string(old_state), tcp_state_string(conn->state));
	//	} 
		
	}
}

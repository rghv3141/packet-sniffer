#include <tcp_state.h>

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
		conn->state = TCP_SYN_SENT;
	else if (tcp->syn && tcp->ack)
		conn->state = TCP_SYN_RECIEVED;
	else 
		conn->state = TCP_ESTABLISHED;
	return conn;
}
void update_tcp_conn(struct tcphdr *tcp, struct packet_info *pkt, ssize_t n) 
{
	struct tcp_connection *conn;
	
	conn = find_connection(pkt);

	if(conn == NULL) {
		conn = create_connection(pkt, tcp, n);
	} else {
		conn->bytes += n;
		switch (conn->state) {

        		case TCP_STATE_SYN_SENT:
                		if (tcp->syn && tcp->ack)
                        		conn->state = TCP_STATE_SYN_RECEIVED;
                		break;

        		case TCP_STATE_SYN_RECEIVED:
                		if (tcp->ack && !tcp->syn)
                        		conn->state = TCP_STATE_ESTABLISHED;
                		break;

        		case TCP_STATE_ESTABLISHED:
                		if (tcp->fin)
                        		conn->state = TCP_STATE_FIN_WAIT;
                		else if (tcp->rst)
                        		conn->state = TCP_STATE_CLOSED;
                		break;

        		case TCP_STATE_FIN_WAIT:
                		if (tcp->ack)
                        		conn->state = TCP_STATE_CLOSED;
               			break;
				
        		case TCP_STATE_CLOSED:
                		break;
		}
	}
}

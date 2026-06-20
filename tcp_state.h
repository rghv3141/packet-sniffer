#include <main.h>

enum tcp_state {
	TCP_SYN_SENT,
	TCP_SYN_RECEIVED,
	TCP_ESTABLISHED,
	TCP_FIN_WAIT,
	TCP_CLOSED
};

struct tcp_connection {
	struct packet_info key;
	enum tcp_state state;
	uint64_t bytes;
};

struct tcp_connection *find_connection(struct packet_info *);
void update_tcp_conn(struct tcphdr *, struct packet_info *, ssize_t);
struct tcp_connection *create_connection(struct packet_info *, ssize_t);


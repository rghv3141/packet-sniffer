#include "main.h"

enum conn_state {
	CONN_SYN_SENT,
	CONN_SYN_RECEIVED,
	CONN_ESTABLISHED,
	CONN_FIN_WAIT,
	CONN_CLOSED
};

struct tcp_connection {
	struct packet_info key;
	enum conn_state state;
	uint64_t bytes;
};

struct tcp_connection *find_connection(struct packet_info *);
void update_tcp_conn(struct tcphdr *, struct packet_info *, ssize_t);
struct tcp_connection *create_connection(struct packet_info *, struct tcphdr *, ssize_t);
char *tcp_state_string(enum conn_state);

#include "main.h"
#include "tcp_state.h"

struct talker {
	struct packet_info key;
	uint64_t bytes;
};

void update_talkers(struct packet_info *, ssize_t );
struct talker *find_talker(struct packet_info *);
void create_talker(struct packet_info *, ssize_t);
void print_top_talkers();

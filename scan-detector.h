#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
struct syn_source {
	uint8_t ipv6;
	
	union {
		uint32_t ipv4_src;
		struct in6_addr ipv6_src;
	};
	
	uint16_t port;
};

struct syn_entry {
	struct syn_source key;
	uint16_t ports[1024];
	ssize_t port_count;
};

void update_syn_entry(struct syn_source *);
void create_syn_entry(struct syn_source *);
struct syn_entry *find_syn_entry(struct syn_source *);

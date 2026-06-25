#include "scan-detector.h"
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

#define MAX_SYNS 1024

struct syn_entry syn_table[MAX_SYNS];

ssize_t syn_count = 0;

void update_syn_entry(struct syn_source *syn) {
	struct syn_entry *entry = find_syn_entry(syn); // just match the src ip
	if (entry == NULL) {
		create_syn_entry(syn);
	}
	else {
		for(int i = 0; i< entry->port_count; i++) {
			if(entry->ports[i] == syn->port) {
				return;
			}
		}
		entry->ports[entry->port_count++] = syn->port;
	
		if (entry->port_count == 20) {
			printf("Possible SYN port scan detected\n");
			if(entry->key.ipv6) {
				char ip[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6, &entry->key.ipv6_src, ip, sizeof(ip));
				printf("The offending ip is %s", ip );
			} else {
				char ip[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &entry->key.ipv4_src , ip, INET_ADDRSTRLEN);
				printf("the offending ip is %s", ip);
			}
		}
	}
}	

struct syn_entry *find_syn_entry(struct syn_source *syn) {
	for(int i = 0; i < syn_count; i++) {
		if(!syn->ipv6) {
			if(syn->ipv4_src == syn_table[i].key.ipv4_src)
				return &syn_table[i];
		} else {
			if(memcmp(&syn->ipv6_src, &syn_table[i].key.ipv6_src, sizeof(struct in6_addr)) == 0)
				return &syn_table[i];
		}
		
	}
	return NULL;
}

void create_syn_entry(struct syn_source *syn) {
	if (syn_count >= MAX_SYNS)
		return;
	syn_table[syn_count].key = *syn;
	syn_table[syn_count].ports[0] = syn->port;
	syn_table[syn_count++].port_count = 1;
}

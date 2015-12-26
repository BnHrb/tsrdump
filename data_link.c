#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#include "network.h"

void ethernet_viewer(const u_char *packet) {
	struct ether_header *ethernet;
	ethernet = (struct ether_header*)(packet);
	int size_ethernet = sizeof(struct ether_header);

	void (*next_layer)(const u_char*) = NULL;

	printf("\n=== Ethernet Header ===\n");
	printf("Destination: %02x:%02x:%02x:%02x:%02x:%02x\n", 
		ethernet->ether_dhost[0],
		ethernet->ether_dhost[1],
		ethernet->ether_dhost[2],
		ethernet->ether_dhost[3],
		ethernet->ether_dhost[4],
		ethernet->ether_dhost[5]);

	printf("Source: %02x:%02x:%02x:%02x:%02x:%02x\n", 
		ethernet->ether_shost[0],
		ethernet->ether_shost[1],
		ethernet->ether_shost[2],
		ethernet->ether_shost[3],
		ethernet->ether_shost[4],
		ethernet->ether_shost[5]);

	switch(ntohs(ethernet->ether_type)) {
		case ETHERTYPE_IP:
			printf("Type : IPv4\n");
			next_layer = ip_viewer;
			break;
		case ETHERTYPE_IPV6:
			printf("Type : IPv6\n");
			break;
		case ETHERTYPE_ARP:
			printf("Type : ARP\n");
			next_layer = arp_viewer;
			break;
	}

	if(next_layer != NULL)
		(*next_layer)(packet + size_ethernet);
}
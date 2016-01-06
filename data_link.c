#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#include "network.h"
#include "verbose.h"

void ethernet_viewer(const u_char *packet, u_char verbose) {
	struct ether_header *ethernet;
	ethernet = (struct ether_header*)(packet);
	int size_ethernet = sizeof(struct ether_header);

	void (*next_layer)(const u_char*, u_char) = NULL;
	printf("\033[1m");
	printf("\n=== Ethernet ===\n");
	printf("\033[0m");

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

	if(verbose & (MID|HIGH)) {
		printf("Type: ");
		switch(ntohs(ethernet->ether_type)) {
			case ETHERTYPE_IP:
				printf("IPv4 ");
				next_layer = ip_viewer;
				break;
			case ETHERTYPE_IPV6:
				printf("IPv6 ");
				break;
			case ETHERTYPE_ARP:
				printf("ARP ");
				next_layer = arp_viewer;
				break;
			default:
				printf("Unknown ");
				break;
		}

		if(verbose & HIGH)
			printf("(0x%04x)\n", ntohs(ethernet->ether_type));
		else
			printf("\n");
	}
	else {
		switch(ntohs(ethernet->ether_type)) {
			case ETHERTYPE_IP:
				next_layer = ip_viewer;
				break;
			case ETHERTYPE_ARP:
				next_layer = arp_viewer;
				break;
		}	
	}

	if(next_layer != NULL)
		(*next_layer)(packet + size_ethernet, verbose);
}
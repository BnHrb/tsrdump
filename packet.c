#include <stdio.h>
#include <pcap.h>

#include "packet.h"

void packet_viewer(const u_char *packet) {
	//struct ether_header *ethernet;
	//sniff_ip *ip;

	//ethernet = (struct ether_header*)(packet);
	ethernet_viewer(packet);
}

// Couche liaison

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

// Couche réseau 

void arp_viewer(const u_char *packet) {
	struct arphdr *arp = (struct arphdr*)(packet);
	int size_arp = sizeof(struct arphdr);

	printf("\t=== ARP Header ===\n");
	printf("\tHardware type : 0x%04x -- ", arp->ar_hrd);
	switch(ntohs(arp->ar_hrd)) {
		case ARPHRD_ETHER:
			printf("Ethernet 10/100Mbps\n");
			break;
		default:
			printf("Unknown\n");
			break;
	}
	printf("\tProtocol type : 0x%04x -- ", arp->ar_pro);
	switch(ntohs(arp->ar_pro)) {
		case ETHERTYPE_IP:
			printf("IPv4\n");
			break;
		case ETHERTYPE_IPV6:
			printf("IPv6\n");
			break;
		default:
			printf("Unknown\n");
			break;
	}
	printf("\tHardware address length : %d bytes\n", arp->ar_hln);
	printf("\tProtocol address length : %d bytes\n", arp->ar_pln);
	printf("\tOperation : ");
	switch(ntohs(arp->ar_op)) {
		case ARPOP_REQUEST:
			printf("ARP Request\n");

			// todo
			break;
		case ARPOP_REPLY:
			printf("ARP Reply\n");

			// todo
			break;
		case ARPOP_RREQUEST:
			printf("RARP Request\n");
			break;
		case ARPOP_RREPLY:
			printf("RARP Reply\n");
			break;
		case ARPOP_InREQUEST:
			printf("InARP Request\n");
			break;
		case ARPOP_InREPLY:
			printf("InARP Reply\n");
			break;
		case ARPOP_NAK:
			printf("ARP NAK\n");
			break;
		default:
			printf("Unknown\n");
			break;
	}
}

void ip_viewer(const u_char *packet) {
	struct ip *ip = (struct ip*)(packet);
	int size_ip = 32*ip->ip_len;

	void (*next_layer)(const u_char*);

	printf("\t=== Ip Header ===\n");
	printf("\tVersion : %d\n", ip->ip_v);
	printf("\tIHL : %d\n", ip->ip_hl);
	printf("\tTotal length : %d\n", ip->ip_len);
	printf("\tTime to live : %d\n", ip->ip_ttl);

	switch(ip->ip_p) {
		case SOL_UDP:
			printf("\tProtocol : UDP\n");
			next_layer = udp_viewer;
			break;
		case SOL_TCP:
			printf("\tProtocol : TCP\n");
			next_layer = tcp_viewer;
			break;
	} 

	printf("\tSource : %s\n", inet_ntoa(ip->ip_src));
	printf("\tDestination : %s\n", inet_ntoa(ip->ip_dst));

	(*next_layer)(packet + size_ip);
}

// Couche transport

void udp_viewer(const u_char *packet) {
	struct udphdr* udp = (struct udphdr*)(packet);
	//int size_udp = sizeof(struct udphdr);

	printf("\t\t=== UDP Header ===\n");
	printf("\t\tSource port : %d\n", udp->source);
	printf("\t\tDestination port : %d\n", udp->dest);
	printf("\t\tLength : %d\n", udp->len);
}

void tcp_viewer(const u_char *packet) {
	//struct tcphdr* tcp = (struct tcphdr*)(packet);
}


// Couche application
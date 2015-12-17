#include <stdio.h>
#include <pcap.h>

#include "packet.h"

void packet_viewer(const u_char *packet) {
	struct ether_header *ethernet;
	//sniff_ip *ip;

	ethernet = (struct ether_header*)(packet);
	ethernet_viewer(packet, ethernet);
}

void ethernet_viewer(const u_char *packet, struct ether_header* ethernet) {
	int size_ethernet = sizeof(struct ether_header);

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

			struct ip *ip;
			ip = (struct ip*)(packet + size_ethernet);
			ip_viewer(packet + size_ethernet, ip);
			break;
		case ETHERTYPE_IPV6:
			printf("Type : IPv6\n");
			break;
		case ETHERTYPE_ARP:
			printf("Type : ARP\n");
			break;
	}
}

void ip_viewer(const u_char *packet, struct ip* ip) {
	int size_ip = 32*ip->ip_len;

	printf("\t=== Ip Header ===\n");
	printf("\tVersion : %d\n", ip->ip_v);
	printf("\tIHL : %d\n", ip->ip_hl);
	printf("\tTotal length : %d\n", ip->ip_len);
	printf("\tTime to live : %d\n", ip->ip_ttl);

	switch(ip->ip_p) {
		case SOL_UDP:
			printf("\tProtocol : UDP\n");
			struct udphdr* udp = (struct udphdr*)(packet + size_ip);
			udp_viewer(packet + size_ip, udp);
			break;
		case SOL_TCP:
			printf("\tProtocol : TCP\n");
			struct tcphdr* tcp = (struct tcphdr*)(packet + size_ip);
			tcp_viewer(packet + size_ip, tcp);
			break;
	} 

	// printf("\tSource : %s\n", inet_ntoa(ip->ip_src));
	// printf("\tDestination : %s\n", inet_ntoa(ip->ip_dst));
}

void udp_viewer(const u_char *packet, struct udphdr *udp) {
	int size_udp = sizeof(struct udphdr);
	printf("\t\t=== UDP Header ===\n");
	printf("\t\tSource port : %d\n", udp->source);
	printf("\t\tDestination port : %d\n", udp->dest);
	printf("\t\tLength : %d\n", udp->len);
}

void tcp_viewer(const u_char *packet, struct tcphdr *tcp) {

}
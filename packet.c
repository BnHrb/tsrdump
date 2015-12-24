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
	//int size_arp = sizeof(struct arphdr);

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
	int size_ip = 4*ip->ip_hl;

	void (*next_layer)(const u_char*) = NULL;

	printf("\t=== Ip Header ===\n");
	printf("\tVersion : %d\n", ip->ip_v);
	printf("\tIHL : %d\n", ip->ip_hl);
	printf("\tToS : %d\n", ip->ip_tos);
	printf("\tTotal length : %d\n", ip->ip_len);
	printf("\tIdentification : %d\n", ip->ip_id);
	// todo offset
	//printf("\tOffset : %d\n", ip->ip_off);

	printf("\tTime to live : %d\n", ip->ip_ttl);
	printf("\tProtocol : ");
	switch(ip->ip_p) {
		case SOL_UDP:
			printf("UDP\n");
			next_layer = udp_viewer;
			break;
		case SOL_TCP:
			printf("TCP\n");
			next_layer = tcp_viewer;
			break;
		default:
			printf("Unknown\n");
			break;
	} 
	printf("\tChecksum : %d\n", ip->ip_sum);
	printf("\tSource : %s\n", inet_ntoa(ip->ip_src));
	printf("\tDestination : %s\n", inet_ntoa(ip->ip_dst));

	//todo options

	if(next_layer != NULL)
		(*next_layer)(packet + size_ip);
}

// Couche transport

void udp_viewer(const u_char *packet) {
	struct udphdr* udp = (struct udphdr*)(packet);
	int size_udp = sizeof(struct udphdr);

	void (*next_layer)(const u_char*) = NULL;

	printf("\t\t=== UDP Header ===\n");
	printf("\t\tSource port : %d\n", ntohs(udp->uh_sport));
	switch(ntohs(udp->uh_sport)) {
		case 53:
			next_layer = dns_viewer;
			break;
	}
	printf("\t\tDestination port : %d\n", ntohs(udp->uh_dport));
	if(next_layer == NULL) {
		switch(ntohs(udp->uh_dport)) {
			case 53:
				next_layer = dns_viewer;
				break;
		}
	}
	printf("\t\tLength : %d\n", ntohs(udp->uh_ulen));
	printf("\t\tChecksum : %d\n", ntohs(udp->uh_sum));
	// todo check checksum

	printf("\t\tDATA : %s\n", packet+size_udp);

	if(next_layer != NULL)
		(*next_layer)(packet + size_udp);
}

void tcp_viewer(const u_char *packet) {
	struct tcphdr* tcp = (struct tcphdr*)(packet);
	int size_tcp = tcp->th_off*4;

	void (*next_layer)(const u_char*) = NULL;

	printf("\t\t=== TCP Header ===\n");
	printf("\t\tSource port : %d\n", ntohs(tcp->th_sport));
	switch(ntohs(tcp->th_sport)) {
		case 80:
			next_layer = http_viewer;
			break;
	}
	printf("\t\tDestination port : %d\n", ntohs(tcp->th_dport));
	if(next_layer == NULL) {
		switch(ntohs(tcp->th_dport)) {
			case 80:
				next_layer = http_viewer;
				break;
		}		
	}
	printf("\t\tSequence number : %d\n", ntohs(tcp->th_seq));
	printf("\t\tAcknowledgment number : %d\n", ntohs(tcp->th_ack));
	printf("\t\tData offset : %d\n", tcp->th_off);
	printf("\t\tReserved : %d\n", tcp->th_x2);
	printf("\t\tFlags : %d\n", tcp->th_flags);
	// todo flags
	printf("\t\tWindow : %d\n", tcp->th_win);
	printf("\t\tChecksum : %d\n", tcp->th_sum);
	printf("\t\tUrgent pointer : %d\n",tcp->th_urp);

	// todo options

	if(next_layer != NULL)
		(*next_layer)(packet + size_tcp);

}


// Couche application

void bootp_viewer(const u_char *packet) {

}

void dhcp_viewer(const u_char *packet) {

}

void dns_viewer(const u_char *packet) {
	
}

void http_viewer(const u_char *packet) {
	
}

void ftp_viewer(const u_char *packet) {
	
}

void smtp_viewer(const u_char *packet) {
	
}

void pop_viewer(const u_char *packet) {
	
}

void imap_viewer(const u_char *packet) {
	
}

void telnet_viewer(const u_char *packet) {
	
}
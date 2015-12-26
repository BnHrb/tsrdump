#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "network.h"
#include "transport.h"

void ip_viewer(const u_char *packet) {
	struct ip *ip = (struct ip*)(packet);
	int ip_size = 4*ip->ip_hl;

	void (*next_udp)(const u_char*) = NULL;
	void (*next_tcp)(const u_char*, int) = NULL;

	printf("\t=== Ip Header ===\n");
	printf("\tVersion : %d\n", ip->ip_v);
	printf("\tIHL : %d\n", ip->ip_hl);
	printf("\tToS : %d\n", ip->ip_tos);
	printf("\tTotal length : %d\n", ntohs(ip->ip_len));
	printf("\tIdentification : %d\n", ntohs(ip->ip_id));
	// todo offset
	//printf("\tOffset : %d\n", ip->ip_off);

	printf("\tTime to live : %d\n", ip->ip_ttl);
	printf("\tProtocol : ");
	switch(ip->ip_p) {
		case SOL_UDP:
			printf("UDP\n");
			next_udp = udp_viewer;
			break;
		case SOL_TCP:
			printf("TCP\n");
			next_tcp = tcp_viewer;
			break;
		default:
			printf("Unknown\n");
			break;
	} 
	printf("\tChecksum : %d\n", ip->ip_sum);
	printf("\tSource : %s\n", inet_ntoa(ip->ip_src));
	printf("\tDestination : %s\n", inet_ntoa(ip->ip_dst));

	//todo options

	if(next_udp != NULL)
		(*next_udp)(packet + ip_size);
	else if(next_tcp != NULL)
		(*next_tcp)(packet + ip_size, ntohs(ip->ip_len) - ip_size);
}

void arp_viewer(const u_char *packet) {
	struct arphdr *arp = (struct arphdr*)(packet);
	int arp_size = sizeof(struct arphdr);

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
			break;
		case ARPOP_REPLY:
			printf("ARP Reply\n");
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

	struct arpaddr *arpaddr = (struct arpaddr*)(packet + arp_size);

	printf("\tSender hardware address : %02x:%02x:%02x:%02x:%02x:%02x\n", 
		arpaddr->ar_sha[0],
		arpaddr->ar_sha[1],		
		arpaddr->ar_sha[2],
		arpaddr->ar_sha[3],
		arpaddr->ar_sha[4],
		arpaddr->ar_sha[5]
	);
	printf("\tSender protocol address : %d.%d.%d.%d\n", 
		arpaddr->ar_spa[0],
		arpaddr->ar_spa[1],
		arpaddr->ar_spa[2],
		arpaddr->ar_spa[3]
	);
	printf("\tTarget hardware address : %02x:%02x:%02x:%02x:%02x:%02x\n", 
		arpaddr->ar_tha[0],
		arpaddr->ar_tha[1],		
		arpaddr->ar_tha[2],
		arpaddr->ar_tha[3],
		arpaddr->ar_tha[4],
		arpaddr->ar_tha[5]
	);
	printf("\tSender protocol address : %d.%d.%d.%d\n", 
		arpaddr->ar_tpa[0],
		arpaddr->ar_tpa[1],
		arpaddr->ar_tpa[2],
		arpaddr->ar_tpa[3]
	);

}
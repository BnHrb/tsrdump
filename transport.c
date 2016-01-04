#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "application.h"

void udp_viewer(const u_char *packet) {
	struct udphdr* udp = (struct udphdr*)(packet);
	int udp_size = sizeof(struct udphdr);

	void (*next_layer)(const u_char*, int) = NULL;

	printf("\t\t=== UDP ===\n");
	printf("\t\tSource port: %d\n", ntohs(udp->uh_sport));
	switch(ntohs(udp->uh_sport)) {
		case 53:
			next_layer = dns_viewer;
			break;
		case 67:
			next_layer = bootp_viewer;
			break;
		case 68:
			next_layer = bootp_viewer;
			break;
	}
	printf("\t\tDestination port: %d\n", ntohs(udp->uh_dport));
	if(next_layer == NULL) {
		switch(ntohs(udp->uh_dport)) {
			case 53:
				next_layer = dns_viewer;
				break;
			case 67:
				next_layer = bootp_viewer;
				break;
			case 68:
				next_layer = bootp_viewer;
				break;
		}
	}
	printf("\t\tLength: %d\n", ntohs(udp->uh_ulen));
	printf("\t\tChecksum: 0x%04x\n", ntohs(udp->uh_sum));
	// todo check checksum

	//printf("\t\tDATA : %s\n", packet+udp_size);

	if(next_layer != NULL && (int)(ntohs(udp->uh_ulen) - udp_size) > 0)
		(*next_layer)(packet + udp_size, (int)(ntohs(udp->uh_ulen) - udp_size));
}

void tcp_viewer(const u_char *packet, int tcp_size) {
	struct tcphdr* tcp = (struct tcphdr*)(packet);
	int tcphdr_size = tcp->th_off*4;

	void (*next_layer)(const u_char*, int) = NULL;

	printf("\t\t=== TCP ===\n");
	printf("\t\tSource port: %d\n", ntohs(tcp->th_sport));
	switch(ntohs(tcp->th_sport)) {
		case 80:
			next_layer = http_viewer;
			break;
		case 23:
			next_layer = telnet_viewer;
			break;
		case 25:
			next_layer = smtp_viewer;
			break;
		case 110:
			next_layer = pop_viewer;
			break;
		case 143:
			next_layer = imap_viewer;
			break;
		case 20:
			next_layer = ftp_viewer;
			break;
		case 21:
			next_layer = ftp_viewer;
			break;
	}
	printf("\t\tDestination port: %d\n", ntohs(tcp->th_dport));
	if(next_layer == NULL) {
		switch(ntohs(tcp->th_dport)) {
			case 80:
				next_layer = http_viewer;
				break;
			case 23:
				next_layer = telnet_viewer;
				break;
			case 25:
				next_layer = smtp_viewer;
				break;
			case 110:
				next_layer = pop_viewer;
				break;
			case 143:
				next_layer = imap_viewer;
				break;
			case 20:
				next_layer = ftp_viewer;
				break;
			case 21:
				next_layer = ftp_viewer;
				break;
		}		
	}
	printf("\t\tSequence number: %d (0x%04x)\n", ntohs(tcp->th_seq), ntohs(tcp->th_seq));
	printf("\t\tAcknowledgment number: %d\n", ntohs(tcp->th_ack));
	printf("\t\tData offset: %d\n", tcp->th_off);
	printf("\t\tReserved: %d\n", tcp->th_x2);
	printf("\t\tFlags: 0x%02x\n", tcp->th_flags);

	if((1<<0) & tcp->th_flags)
		printf("\t\t - FIN\n");
	if((1<<1) & tcp->th_flags)
		printf("\t\t - SYN\n");
	if((1<<2) & tcp->th_flags)
		printf("\t\t - RST\n");
	if((1<<3) & tcp->th_flags)
		printf("\t\t - PSH\n");
	if((1<<4) & tcp->th_flags)
		printf("\t\t - ACK\n");
	if((1<<5) & tcp->th_flags)
		printf("\t\t - URG\n");

	printf("\t\tWindow: %d\n", tcp->th_win);
	printf("\t\tChecksum: 0x%04x\n", ntohs(tcp->th_sum));
	printf("\t\tUrgent pointer: %d\n",tcp->th_urp);

	// todo options

	if(next_layer != NULL && (tcp_size - tcphdr_size) > 0)
		(*next_layer)(packet + tcphdr_size, tcp_size - tcphdr_size);

}
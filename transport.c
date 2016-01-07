#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "application.h"
#include "verbose.h"

// gestion des paquets udp
void udp_viewer(const u_char *packet, u_char verbose) {
	struct udphdr* udp = (struct udphdr*)(packet);
	int udp_size = sizeof(struct udphdr);

	void (*next_layer)(const u_char*, int, u_char) = NULL;

	// si verbose 2 et 3
	if(verbose & (MID|HIGH)) {
		printf("\033[1m");
		printf("\t\t=== UDP ===\n");
		printf("\033[0m");
		printf("\t\tSource port: %d\n", ntohs(udp->uh_sport));
	}
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
	if(verbose & (MID|HIGH))
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
	if(verbose & (MID|HIGH))
		printf("\t\tLength: %d\n", ntohs(udp->uh_ulen));
	if(verbose & HIGH)
		printf("\t\tChecksum: 0x%04x\n", ntohs(udp->uh_sum));

	// si verbose 1
	if(verbose & LOW) 
		printf(" > (UDP) %d -> %d ", ntohs(udp->uh_sport), ntohs(udp->uh_dport));

	if(next_layer != NULL && (int)(ntohs(udp->uh_ulen) - udp_size) > 0)
		(*next_layer)(packet + udp_size, (int)(ntohs(udp->uh_ulen) - udp_size), verbose); // appel de la couche supérieure 
}


// gestion des paquets tcp
void tcp_viewer(const u_char *packet, int tcp_size, u_char verbose) {
	struct tcphdr* tcp = (struct tcphdr*)(packet);
	int i, j, tmp, tcphdr_size = tcp->th_off*4;

	void (*next_layer)(const u_char*, int, u_char) = NULL;

	if(verbose & (MID|HIGH)) {
		printf("\033[1m");
		printf("\t\t=== TCP ===\n");
		printf("\033[0m");
		printf("\t\tSource port: %d\n", ntohs(tcp->th_sport)); // port source 
	}
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
	if(verbose & (MID|HIGH))
		printf("\t\tDestination port: %d\n", ntohs(tcp->th_dport)); // port destination
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

	if(verbose & (MID|HIGH)) {
		printf("\t\tSequence number: %d (0x%04x)\n", ntohl(tcp->th_seq), ntohl(tcp->th_seq));
		printf("\t\tAcknowledgment number: %d\n", ntohl(tcp->th_ack));
		printf("\t\tHeader length: %d bytes\n", tcphdr_size);
	}

	if(verbose & HIGH)
		printf("\t\tFlags: 0x%02x\n", tcp->th_flags);
	else if(verbose & MID)
		printf("\t\tFlags: \n");

	if(verbose & (MID|HIGH)) {
		if(TH_FIN & tcp->th_flags)
			printf("\t\t - FIN\n");
		if(TH_SYN & tcp->th_flags)
			printf("\t\t - SYN\n");
		if(TH_RST & tcp->th_flags)
			printf("\t\t - RST\n");
		if(TH_PUSH & tcp->th_flags)
			printf("\t\t - PSH\n");
		if(TH_ACK & tcp->th_flags)
			printf("\t\t - ACK\n");
		if(TH_URG & tcp->th_flags)
			printf("\t\t - URG\n");
	}

	if(verbose & HIGH) {
		printf("\t\tWindow: %d\n", ntohs(tcp->th_win));
		printf("\t\tChecksum: 0x%04x\n", ntohs(tcp->th_sum));
		printf("\t\tUrgent pointer: %d\n",ntohs(tcp->th_urp));
	}

	if(tcp_size > sizeof(struct tcphdr)) {
		if(verbose & HIGH) {
			printf("\t\tOptions:\n");
			for(i=sizeof(struct tcphdr); i<tcphdr_size && packet[i] != 0x00; i++) {
				switch(packet[i]) {
					case 1:
						printf("\t\t - NOP\n");
						break;
					case 2:
						printf("\t\t - Type: maximum segment size (%d)\n", packet[i]);
						printf("\t\t   Length: %d\n", packet[i+1]);
						tmp = packet[i+2]<<8 | packet[i+3];
						printf("\t\t   MSS value: %d\n", tmp);
						i += (int)packet[i+1]-1;
						break;
					case 3:
						printf("\t\t - Type: windows scale (%d)\n", packet[i]);
						printf("\t\t   Length: %d\n", packet[i+1]);
						printf("\t\t   windows scale value: %d\n", packet[i+2]);
						i += (int)packet[i+1]-1;
						break;
					case 4:
						printf("\t\t - Type: SACK permited\n");
						printf("\t\t   Length: %d\n", packet[i+1]);
						i += (int)packet[i+1]-1;
						break;
					case 8:
						printf("\t\t - Type: timestamps(%d)\n", packet[i]);
						printf("\t\t   Length: %d\n", packet[i+1]);
						tmp = packet[i+2] << 24 | packet[i+3] << 16 | packet[i+4] << 8 | packet[i+5];
						printf("\t\t   timestamps value: %d\n", tmp);
						tmp = packet[i+6] << 24 | packet[i+7] << 16 | packet[i+8] << 8 | packet[i+9];
						printf("\t\t   timestamps echo reply: %d\n", tmp);
						i += (int)packet[i+1]-1;	
						break;
					default:
						printf("\t\t - Type: unknown (%d)\n", packet[i]);
						printf("\t\t   Length %d\n", packet[i+1]);
						if((int)packet[i+1]>2) {
							printf("\t\t   Value 0x");
							for(j=2; j<(int)packet[i+1]; j++) {
								printf("%02x", packet[j+i]);
							}
							printf("\n");
						}
						i += (int)packet[i+1]-1;
						break;
				}
			}
		}
		else if(verbose & MID) {
			printf("\t\tOptions: %ld bytes\n", tcp_size - sizeof(struct tcphdr));
		}
	}

	// si verbose 1
	if(verbose & LOW) {
		printf(" > (TCP) %d -> %d (", ntohs(tcp->th_sport), ntohs(tcp->th_dport));
		if(TH_FIN & tcp->th_flags)
			printf("FIN ");
		if(TH_SYN & tcp->th_flags)
			printf("SYN ");
		if(TH_RST & tcp->th_flags)
			printf("RST ");
		if(TH_PUSH & tcp->th_flags)
			printf("PSH ");
		if(TH_ACK & tcp->th_flags)
			printf("ACK ");
		if(TH_URG & tcp->th_flags)
			printf("URG ");

		printf("\b)");
	}

	if(next_layer != NULL && (tcp_size - tcphdr_size) > 0)
		(*next_layer)(packet + tcphdr_size, tcp_size - tcphdr_size, verbose); // appel de la couche supérieure

}
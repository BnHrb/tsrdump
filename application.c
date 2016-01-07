#include <pcap.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <ctype.h>

#include "application.h"
#include "verbose.h"

void bootp_viewer(const u_char *packet, int data_size, u_char verbose) {
	struct bootphdr *bootp = (struct bootphdr*)(packet);
	int i,j,l;
	u_int32_t tmp;

	if(verbose & (MID|HIGH)) {
		printf("\033[1m");
		printf("\t\t\t=== BOOTP ===\n");
		printf("\033[0m");
		printf("\t\t\tMessage type : ");
		switch(bootp->msg_type) {
			case 1:
				printf("Request\n");
				break;
			case 2:
				printf("Reply\n");
				break;
			default:
				printf("Unknown\n");
				break;
		}
	}

	if(verbose & HIGH) {
		printf("\t\t\tHardware type : ");
		switch(bootp->hrdwr_type) {
			case 1:
				printf("Ethernet\n");
				break;
			case 6:
				printf("IEEE 802\n");
				break;
			case 18:
				printf("Fibre channel\n");
				break;
			case 20:
				printf("Serial line\n");
				break;
			default:
				printf("Unknown\n");
				break;
		}
		printf("\t\t\tHardware address length : %d bytes\n", bootp->hrdwr_addr_length);
		printf("\t\t\tHops : %d\n", bootp->hops);
		printf("\t\t\tTransaction ID : 0x%08x\n", ntohl(bootp->trans_id));
		printf("\t\t\tSeconds elapsed : %d\n", ntohs(bootp->num_sec));
	}

	if(verbose & (MID|HIGH)) {
		printf("\t\t\tClient IP address : %s\n", inet_ntoa(bootp->ciaddr));
		printf("\t\t\tYour IP address : %s\n", inet_ntoa(bootp->yiaddr));
		printf("\t\t\tNext server IP address : %s\n", inet_ntoa(bootp->siaddr));
		printf("\t\t\tRelay agent IP address : %s\n", inet_ntoa(bootp->giaddr));
		if(bootp->hrdwr_addr_length == 6) {
			printf("\t\t\tClient MAC address : %02x:%02x:%02x:%02x:%02x:%02x\n", 
				bootp->hrdwr_caddr[0],
				bootp->hrdwr_caddr[1],
				bootp->hrdwr_caddr[2],
				bootp->hrdwr_caddr[3],
				bootp->hrdwr_caddr[4],
				bootp->hrdwr_caddr[5]);

			if(verbose & HIGH) {
				printf("\t\t\tClient hardware address padding : ");
				for(i=6; i<16;i++) {
					printf("%02x", bootp->hrdwr_caddr[i]);
				}
				printf("\n");
			}
		}
		else {
			printf("\t\t\tClient hardware address unknown : ");
			for(i=0; i<16; i++) {
				printf("%02x", bootp->hrdwr_caddr[i]);
			}
			printf("\n");
		}
	}

	if(verbose & HIGH) {
		printf("\t\t\tServer host name : ");
		if(bootp->srv_name[0] != 0) {
			for(i=0; i<64 && bootp->srv_name[i] != 0; i++) {
				if(isprint(bootp->srv_name[i]))
					printf("%c", bootp->srv_name[i]);
				else
					printf(".");
			}
			printf("\n");
		}
		else {
			printf("not given\n");
		}
		printf("\t\t\tBoot file name : ");
		if(bootp->bpfile_name[0] != 0) {
			for(i=0; i<128 && bootp->bpfile_name[i] != 0; i++) {
				if(isprint(bootp->bpfile_name[i]))
					printf("%c", bootp->bpfile_name[i]);
				else
					printf(".");
			}
			printf("\n");
		}
		else {
			printf("not given\n");
		}
	}

	if(ntohl(bootp->magic_cookie) == 0x63825363) {
		if(verbose & HIGH)
			printf("\t\t\tMagic cookie : DHCP (0x%x)\n", ntohl(bootp->magic_cookie));
		else if(verbose & MID)
			printf("\t\t\tMagic cookie : DHCP\n");

		if(verbose & (MID|HIGH)) {
			for(i = sizeof(struct bootphdr); i < data_size && packet[i] != 0xff; i++) {
				printf("\t\t\tOption : ");
				switch((int)packet[i]) {
					case 53: // length 1
						printf("DHCP message type ");
						i++;
						l = (int)packet[i];
						i++;
						switch((int)packet[i]) {
							case 1:
								printf("discover");
								break;
							case 2:
								printf("offer");
								break;
							case 3:
								printf("request");
								break;
							case 4:
								printf("decline");
								break;
							case 5:
								printf("ack");
								break;
							case 6:
								printf("nack");
								break;
							case 7:
								printf("release");
								break;
							default:
								printf("unknown");
								break;
						}
						i+=l-1;
						printf("\n");
						break;
					case 58: // length 4
						printf("Renewal time value ");
						i++;
						l = (int)packet[i];
						i++;
						tmp = packet[i] << 24 | packet[i+1] << 16 | packet[i+2] << 8 | packet[i+3];
						printf("%ds\n", tmp);
						i+=l-1;
						break;
					case 59: // length 4
						printf("Rebinding time value ");
						i++;
						l = (int)packet[i];
						i++;
						tmp = packet[i] << 24 | packet[i+1] << 16 | packet[i+2] << 8 | packet[i+3];
						printf("%ds\n", tmp);
						i+=l-1;
						break;
					case 50:
						printf("Requested IP address ");
						i++;
						l = (int)packet[i];
						i++;
						printf("%d.%d.%d.%d\n", 
							packet[i],
							packet[i+1],
							packet[i+2],
							packet[i+3]);
						i+=l-1;
						break;
					case 51: // length 4
						printf("IP address lease time ");
						i++;
						l = (int)packet[i];
						i++;
						tmp = packet[i] << 24 | packet[i+1] << 16 | packet[i+2] << 8 | packet[i+3];
						printf("%ds\n", tmp);
						i+=l-1;
						break;
					case 1: // length 4
						printf("Subnet mask ");
						i++;
						l = (int)packet[i];
						i++;
						printf("%d.%d.%d.%d\n", 
							packet[i],
							packet[i+1],
							packet[i+2],
							packet[i+3]);
						i+=l-1;
						break;
					case 54: // length 4
						printf("DHCP server identifier ");
						i++;
						l = (int)packet[i];
						i++;
						printf("%d.%d.%d.%d\n", 
							packet[i],
							packet[i+1],
							packet[i+2],
							packet[i+3]);
						i+=l-1;				
						break;
					case 55: // length variable
						printf("Parameter request list");
						i++;
						for(j=0;j<(int)packet[i];j++) {
							switch(packet[i+j+1]) {
								case 1:
									printf(" subnet mask");
									break;
								case 3:
									printf(" router");
									break;
								case 6:
									printf(" domain name server");
									break;
								case 42:
									printf(" network time protocol servers");
									break;
								default:
									printf(" unknown");
									break;
							}
							if(j != (int)packet[i]-1)
								printf(",");
						}
						i+=((int)packet[i]);
						printf("\n");
						break;
					case 61:
						printf("Client identifier ");
						i++;
						l = (int)packet[i];
						i++;
						if((int)packet[i] == 1) {
							printf("%02x.%02x.%02x.%02x.%02x.%02x\n", 
								packet[i+1],
								packet[i+2],
								packet[i+3],
								packet[i+4],
								packet[i+5],
								packet[i+6]);
						}
						else {
							printf("unknown identifier\n");
						}
						i += l-1;
						break;
					default:
						printf("Unknown (0x%02x)\n", packet[i]);
						i++;
						printf("\t\t\t\tLength : %d bytes\n", (int)packet[i]);
						printf("\t\t\t\tValue : 0x");
						for(j=0; j<(int)packet[i];j++) {
							printf("%02x", packet[i+j+1]);
						}
						printf("\n");
						i+=j;
						break;
				}
			}
		}
		else {
			for(i = sizeof(struct bootphdr); i < data_size && packet[i] != 0xff; i++) {
				switch((int)packet[i]) {
					case 53: // length 1
						printf("(DHCP) ");
						i++;
						l = (int)packet[i];
						i++;
						switch((int)packet[i]) {
							case 1:
								printf("Discover");
								break;
							case 2:
								printf("Offer");
								break;
							case 3:
								printf("Request");
								break;
							case 4:
								printf("Decline");
								break;
							case 5:
								printf("Ack");
								break;
							case 6:
								printf("Nack");
								break;
							case 7:
								printf("release");
								break;
							default:
								printf("Unknown");
								break;
						}
						i+=l-1;
						break;
					default:
						i++;
						l = (int)packet[i];
						i+=l-1;
						break;
				}
			}
		}
	}
	else {
		printf("Vendor specific : not given\n");
	}

}

void dns_viewer(const u_char *packet, int data_size, u_char verbose) {
	struct dnshdr *dns = (struct dnshdr*)(packet);
	int i, j = 0, k, questions, answers;
	u_int16_t *type, *class, *d_size;
	u_int32_t *ttl;

	if(verbose & (MID|HIGH)) {
		printf("\033[1m");
		printf("\t\t\t=== DNS ===\n");
		printf("\033[0m");
	}

	if(verbose & HIGH) {
		printf("\t\t\tQuery id : 0x%04x\n", ntohs(dns->query_id));
		printf("\t\t\tFlags : 0x%04x\n", ntohs(dns->flags));
	}
	// todo flags
	if(verbose & (MID|HIGH)) {
		printf("\t\t\tQuestions : %d\n", ntohs(dns->quest_count));
		printf("\t\t\tAnswer count : %d\n", ntohs(dns->answ_count));
		printf("\t\t\tAuthority count : %d\n", ntohs(dns->auth_count));
		printf("\t\t\tAdditional count : %d\n", ntohs(dns->add_count));
	}

	questions = ntohs(dns->quest_count);
	answers = ntohs(dns->answ_count);

	// questions

	if(verbose & (MID|HIGH)) {
		if(questions > 0) {
			printf("\t\t\tQueries\n");
			for(k = 0; k < questions; k++) {
				printf("\t\t\t\t");
				for(i = sizeof(struct dnshdr) + j; i < data_size && packet[i] != 0x00; i++) {
					if(packet[i] == 0x03)
						printf(".");
					else if(packet[i] != 0x0c) {
						if(isprint(packet[i]))
							printf("%c", packet[i]);
						else
							printf(".");
					}
				}
				j = i+1;
				printf("\n");

				if(verbose & (MID|HIGH)) {
					type = (u_int16_t*)(packet + j);
					j+=2;
					class = (u_int16_t*)(packet + j);

					if(verbose & HIGH) {
						printf("\t\t\t\t0x%04x : ", ntohs(*type));
						switch(ntohs(*type)) {
							case 1:
								printf("A (Address record)\n");
								break;
							case 28:
								printf("AAAA (IPv6 address record)\n");
								break;
							case 5:
								printf("CNAME (Canonical name record)\n");
								break;
							case 15:
								printf("MX (Mail exchange record)\n");
								break;
							case 2:
								printf("NS (Name server record)\n");
								break;
							case 6:
								printf("SOA (Start of authority record)\n");
								break;
							case 16:
								printf("TXT (Text record)\n");
								break;
							default:
								printf("Unknown\n");
								break;
						}

						printf("\t\t\t\t0x%04x : ", ntohs(*class));
						switch(ntohs(*class)) {
							case 0:
								printf("Reserved\n");
								break;
							case 1:
								printf("Internet\n");
								break;
							case 2:
								printf("Unassigned\n");
								break;
							case 3:
								printf("Chaos\n");
								break;
							case 4:
								printf("Hesiod\n");
								break;
							default:	
								printf("Unknown\n");
								break;
						}
					}
				}
				else {
					j+=2;
				}
			}
		}

		// answers
		if(answers > 0) {
			printf("\t\t\tAnswers\n");
			for(k = 0; k < answers; k++) {
				j += 4;
				type = (u_int16_t*)(packet + j);
				j += 2;
				class = (u_int16_t*)(packet + j);
				j += 2;
				ttl = (u_int32_t*)(packet + j);
				j += 4;
				d_size = (u_int16_t*)(packet + j);
				j += 2;

				if(verbose & HIGH) {
					printf("\t\t\t\tType 0x%04x\n", ntohs(*type));
					printf("\t\t\t\tData length %d\n", ntohs(*d_size));
					printf("\t\t\t\tTime to live %d\n", ntohs(*ttl));
				}
				if(ntohs(*type) == 1) {
					printf("\t\t\t\t%d.%d.%d.%d\n", 
						packet[j], 
						packet[j+1],
						packet[j+2],
						packet[j+3]);
				}
				else {
					for(i = 0; i < ntohs(*d_size); ++i)
					{
						printf("%c", packet[j+i]);
					}

					printf("\n");

					j += ntohs(*d_size);
				}

			}

			printf("\n");
		}
	}

	if(verbose & LOW) {
		printf(" > (DNS) ");
		if(answers > 0)
			printf(" Answer");
		else if(questions > 0)
			printf(" Query");
	}
}


void http_viewer(const u_char *packet, int data_size, u_char verbose) {
	int i;


	if(verbose & (MID|HIGH)) {
		printf("\033[1m");
		printf("\t\t\t=== HTTP ===\n");
		printf("\033[0m");

		printf("\t\t\t");

		for (i = 0; i < data_size; ++i) 
		{
			if(packet[i-1] == '\n')
				printf("\t\t\t");
			if(isprint(packet[i]) || packet[i] == '\n' || packet[i] == '\t' || packet[i] == '\r')
				printf("%c", packet[i]);
			else 
				printf(".");
		}
	}
	else {
		printf(" > (HTTP) ");
		if(!islower(packet[0])) {
			for (i = 0; i < data_size; ++i) 
			{
				if(isprint(packet[i]))
					printf("%c", packet[i]);
				else 
					printf(".");

				if(packet[i] == ' ')
					break;
			}	
		}
		else
			printf("data");	
	}
}

void ftp_viewer(const u_char *packet, int data_size, u_char verbose) {
	int i;

	if(verbose & (MID|HIGH)) {
		printf("\033[1m");
		printf("\t\t\t=== FTP ===\n");
		printf("\033[0m");
		printf("\t\t\t");
		for (i = 0; i < data_size; ++i) 
		{
			if(packet[i-1] == '\n')
				printf("\t\t\t");
			if(isprint(packet[i]) || packet[i] == '\n' || packet[i] == '\t' || packet[i] == '\r')
				printf("%c", packet[i]);	
			else
				printf(".");
		}

		printf("\n");	
	}
	else {
		printf(" > (FTP) ");
		for (i = 0; i < data_size && packet[i] != '\n'; ++i) 
		{
			if(isprint(packet[i]))
				printf("%c", packet[i]);
		}
	}

}

void smtp_viewer(const u_char *packet, int data_size, u_char verbose) {
	int i;

	if(verbose & (MID|HIGH)) {
		printf("\033[1m");
		printf("\t\t\t=== SMTP ===\n");
		printf("\033[0m");
		printf("\t\t\t");
		for (i = 0; i < data_size; ++i) 
		{
			if(packet[i-1] == '\n')
				printf("\t\t\t");
			if(isprint(packet[i]) || packet[i] == '\n' || packet[i] == '\t' || packet[i] == '\r')
				printf("%c", packet[i]);	
			else
				printf(".");
		}

		printf("\n");	
	}
	else {
		printf(" > (SMTP) ");
		for (i = 0; i < data_size && packet[i] != ' '; ++i) 
		{
			if(isprint(packet[i]))
				printf("%c", packet[i]);	
			else
				printf(".");
		}
	}

}

void pop_viewer(const u_char *packet, int data_size, u_char verbose) {
	int i;

	if(verbose & (MID|HIGH)) {
		printf("\033[1m");
		printf("\t\t\t=== POP ===\n");
		printf("\033[0m");	
		printf("\t\t\t");
		for (i = 0; i < data_size; ++i) 
		{
			if(packet[i-1] == '\n')
				printf("\t\t\t");
			if(isprint(packet[i]) || packet[i] == '\n' || packet[i] == '\t' || packet[i] == '\r')
				printf("%c", packet[i]);
			else
				printf(".");	
		}

		printf("\n");	
	}
	else {
		printf(" > (POP) ");
		for (i = 0; i < data_size && packet[i] != ' '; ++i) 
		{
			if(isprint(packet[i]))
				printf("%c", packet[i]);	
			else
				printf(".");
		}
	}
}

void imap_viewer(const u_char *packet, int data_size, u_char verbose) {
	int i;

	if(verbose & (MID|HIGH)) {
		printf("\033[1m");
		printf("\t\t\t=== IMAP ===\n");
		printf("\033[0m");
		printf("\t\t\t");
		for (i = 0; i < data_size; ++i) 
		{
			if(packet[i-1] == '\n')
				printf("\t\t\t");

			if(isprint(packet[i]) || packet[i] == '\n' || packet[i] == '\t' || packet[i] == '\r')
				printf("%c", packet[i]);	
			else
				printf(".");
		}

		printf("\n");
	}
	else {
		printf(" > (IMAP) ");
		for (i = 0; i < data_size && packet[i] != '\n'; ++i) 
		{
			if(isprint(packet[i]))
				printf("%c", packet[i]);	
			else
				printf(".");
		}		
	}	
}

void telnet_viewer(const u_char *packet, int data_size, u_char verbose) {
	int i = 0, f = 1;

	if(verbose & (MID|HIGH)) {
		printf("\033[1m");
		printf("\t\t\t=== TELNET ===\n");
		printf("\033[0m");
		while(i < data_size) 
		{
			if(packet[i] == 255) { // IAC
				i++;
				f = 1;
				printf("\t\t\t");
				while(f) {
					switch(packet[i]) {
						case 0:
							printf("Binary transmission ");
							break;
						case 1:
							printf("Echo ");
							break;
						case 2:
							printf("Reconnection ");
							break;
						case 3:
							printf("Suppress go ahead ");
							break;
						case 4:
							printf("Approx message size negotation ");
							break;
						case 5:
							printf("Status ");
							break;
						case 6:
							printf("Timing mark ");
							break;
						case 7:
							printf("Remote controlled transmition and echo");
							break;
						case 8:
							printf("Output line width ");
							break;
						case 9:
							printf("Output page size ");
							break;
						case 10:
							printf("Output carriage-return disposition ");
							break;
						case 11:
							printf("Output horizontal tabstops ");
							break;
						case 12:
							printf("Output horizontal tab disposition ");
							break;
						case 13:
							printf("Output formfeed disposition ");
							break;
						case 14:
							printf("Output vertical tabstops ");
							break;
						case 15:
							printf("Output vertical tab disposition ");
							break;
						case 16:
							printf("Output linefeed disposition ");
							break;
						case 17:
							printf("Extended ASCII ");
							break;
						case 18:
							printf("Logout ");
							break;
						case 19:
							printf("Byte macro ");
							break;
						case 20:
							printf("Data entry terminal ");
							break;
						case 21:
							printf("SUPDUP ");
							break;
						case 22:
							printf("SUPDUP output ");
							break;
						case 23:
							printf("Send location ");
							break;
						case 24:
							printf("Terminal type ");
							break;
						case 25:
							printf("End of record ");
							break;
						case 26:
							printf("TACACS user identification ");
							break;
						case 27:
							printf("Output marking");
							break;
						case 28:
							printf("Terminal location number ");
							break;
						case 29:
							printf("Telnet 3270 regime ");
							break;
						case 30:
							printf("X.3 PAD ");
							break;
						case 31:
							printf("Window size ");
							break;
						case 32:
							printf("Terminal speed ");
							break;
						case 33:
							printf("Remote flow control ");
							break;
						case 34:
							printf("Linemode ");
							break;
						case 35:
							printf("X display location");
							break;
						case 36:
							printf("Environment variables ");
							break;
						case 39:
							printf("New environment options ");
							break;
						case 240:
							printf("End of subnegotiation parameters ");
							break;
						case 241:
							printf("No operation ");
							break;
						case 242:
							printf("Data mark ");
							break;
						case 243:
							printf("Break ");
							break;
						case 244:
							printf("Suspend ");
							break;
						case 245:
							printf("Abort output ");
							break;
						case 246:
							printf("Are you there ");
							break;
						case 247:
							printf("Erase character ");
							break;
						case 248:
							printf("Erase line ");
							break;
						case 249:
							printf("Go ahead ");
							break;
						case 250:
							printf("Subnegotiation ");
							break;
						case 251:
							printf("WILL ");
							break;
						case 252:
							printf("WON'T ");
							break;
						case 253:
							printf("DO ");
							break;
						case 254:
							printf("DON'T ");
							break;
						default:
							//printf("Unknown");
							printf("%c ", packet[i]);
							break;
					}

					i++;
					if(packet[i] == 255 || i >= data_size) {
						f = 0;
						printf("\n");
					}
				}
			}
			else {
				if(packet[i-1] == '\n' || packet[i-1] == '\r' || i == 0) {
					printf("\t\t\t");
				}
				printf("%c", packet[i]);
				i++;
			}
		}

		printf("\n");	
	}
	else {
		printf(" > (TELNET)");
	}
}
#include <pcap.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include "application.h"

void dhcp_viewer(const u_char *packet, int data_size) {
	int i;

	printf("\t\t\t=== DHCP ===\n");
	for (i = 0; i < data_size; ++i) 
	{
		printf("%c", packet[i]);	
	}

	printf("\n");	
}

void dns_viewer(const u_char *packet, int data_size) {
	struct dnshdr *dns = (struct dnshdr*)(packet);
	int i, j = 0, k, questions, answers;
	u_int16_t *type, *class, *d_size;
	u_int32_t *ttl;

	printf("\t\t\t=== DNS ===\n");

	printf("\t\t\tQuery id : 0x%04x\n", ntohs(dns->query_id));
	printf("\t\t\tFlags : 0x%04x\n", ntohs(dns->flags));
	printf("\t\t\tQuestions : %d\n", ntohs(dns->quest_count));
	questions = ntohs(dns->quest_count);
	printf("\t\t\tAnswer count : %d\n", ntohs(dns->answ_count));
	answers = ntohs(dns->answ_count);
	printf("\t\t\tAuthority count : %d\n", ntohs(dns->auth_count));
	printf("\t\t\tAdditional count : %d\n", ntohs(dns->add_count));

	// questions
	printf("\t\t\tQueries\n");
	for(k = 0; k < questions; k++) {
		printf("\t\t\t\t");
		for(i = sizeof(struct dnshdr) + j; i < data_size && packet[i] != 0x00; i++) {
			if(packet[i] == 0x03)
				printf(".");
			else if(packet[i] != 0x0c)
				printf("%c", packet[i]);
		}
		j = i+1;
		printf("\n");
		type = (u_int16_t*)(packet + j);
		j+=2;
		class = (u_int16_t*)(packet + j);

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

	// answers
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

		printf("Type 0x%04x\n", ntohs(*type));
		printf("Data length %d\n", ntohs(*d_size));
		printf("Time to live %d\n", ntohs(*ttl)); // todo
		if(ntohs(*type) == 1) {
			printf("%d.%d.%d.%d\n", 
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

void http_viewer(const u_char *packet, int data_size) {
	int i;

	printf("\t\t\t=== HTTP ===\n");
	printf("\t\t\t");
	for (i = 0; i < data_size; ++i) 
	{
		if(packet[i-1] == '\n')
			printf("\t\t\t");
		printf("%c", packet[i]);
	}

	printf("\n");	
}

void ftp_viewer(const u_char *packet, int data_size) {
	int i;

	printf("\t\t\t=== FTP ===\n");
	printf("\t\t\t");
	for (i = 0; i < data_size; ++i) 
	{
		if(packet[i-1] == '\n')
			printf("\t\t\t");
		printf("%c", packet[i]);	
	}

	// ftp data

	printf("\n");	
}

void smtp_viewer(const u_char *packet, int data_size) {
	int i;

	printf("\t\t\t=== SMTP ===\n");
	printf("\t\t\t");
	for (i = 0; i < data_size; ++i) 
	{
		if(packet[i-1] == '\n')
			printf("\t\t\t");
		printf("%c", packet[i]);	
	}

	printf("\n");	
}

void pop_viewer(const u_char *packet, int data_size) {
	int i;

	printf("\t\t\t=== POP ===\n");
	printf("\t\t\t");
	for (i = 0; i < data_size; ++i) 
	{
		if(packet[i-1] == '\n')
			printf("\t\t\t");
		printf("%c", packet[i]);	
	}

	printf("\n");	
}

void imap_viewer(const u_char *packet, int data_size) {
	int i;

	printf("\t\t\t=== IMAP ===\n");
	for (i = 0; i < data_size; ++i) 
	{
		printf("%c", packet[i]);	
	}

	printf("\n");	
}

void telnet_viewer(const u_char *packet, int data_size) {
	int i = 0, f = 1;

	// todo subnegotation

	printf("\t\t\t=== TELNET ===\n");
	while(i < data_size) 
	{
		//printf("0x%02x\n", packet[i]);
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
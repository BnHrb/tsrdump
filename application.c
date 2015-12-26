#include <pcap.h>

void dhcp_viewer(const u_char *packet, int data_size) {
	int i;

	printf("\t\t\t=== HTTP ===\n");
	for (i = 0; i < data_size; ++i) 
	{
		printf("%c", packet[i]);	
	}

	printf("\n");	
}

void dns_viewer(const u_char *packet, int data_size) {
	int i;

	printf("\t\t\t=== DNS ===\n");
	for (i = 0; i < data_size; ++i) 
	{
		printf("%c", packet[i]);	
	}

	printf("\n");
}

void http_viewer(const u_char *packet, int data_size) {
	int i;

	printf("\t\t\t=== HTTP ===\n");
	for (i = 0; i < data_size; ++i) 
	{
		printf("%c", packet[i]);	
	}

	printf("\n");	
}

void ftp_viewer(const u_char *packet, int data_size) {
	int i;

	printf("\t\t\t=== HTTP ===\n");
	for (i = 0; i < data_size; ++i) 
	{
		printf("%c", packet[i]);	
	}

	printf("\n");	
}

void smtp_viewer(const u_char *packet, int data_size) {
	int i;

	printf("\t\t\t=== HTTP ===\n");
	for (i = 0; i < data_size; ++i) 
	{
		printf("%c", packet[i]);	
	}

	printf("\n");	
}

void pop_viewer(const u_char *packet, int data_size) {
	int i;

	printf("\t\t\t=== HTTP ===\n");
	for (i = 0; i < data_size; ++i) 
	{
		printf("%c", packet[i]);	
	}

	printf("\n");	
}

void imap_viewer(const u_char *packet, int data_size) {
	int i;

	printf("\t\t\t=== HTTP ===\n");
	for (i = 0; i < data_size; ++i) 
	{
		printf("%c", packet[i]);	
	}

	printf("\n");	
}

void telnet_viewer(const u_char *packet, int data_size) {
	int i;

	printf("\t\t\t=== HTTP ===\n");
	for (i = 0; i < data_size; ++i) 
	{
		printf("%c", packet[i]);	
	}

	printf("\n");	
}
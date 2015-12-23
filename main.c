#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <sys/time.h>
#include <unistd.h>

#include "packet.h"

int n;

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	/* Print its length */
	//printf("Got one packet, size of [%d] bytes\n", header->len);

	printf("Packet #%d -- timestamp: %ld | length %d bytes\n", n, header->ts.tv_sec, header->len);
	n++;

	packet_viewer(packet);
	printf("\n");
}

void usage() {
	printf("usage \n");
}

int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev = NULL;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */

	n = 0;
	int c;
	extern char * optarg;
	char* file = NULL;

	while((c = getopt(argc, argv, "i:o:f:v:h")) != -1) {
		switch(c) {
			case 'i':
				dev = optarg;
				break;
			case 'o':
				break;
			case 'f':
				file = optarg;
				break;
			case 'v':
				break;
			case 'h':
				usage();
				return -1;
				break;
			case '?':
				usage();
				return -1;
				break;
		}
	}

	if(dev == NULL) {
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return -1;
		}
	}

	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	if(file == NULL) {
		/* Open the session in promiscuous mode */
		handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			return -1;
		}
		/* Compile and apply the filter */
		if(strcmp(filter_exp, "") != 0) {
			if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
				fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
				return -1;
			}
			if (pcap_setfilter(handle, &fp) == -1) {
				fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
				return -1;
			}
		}
	}
	else {
		handle = pcap_open_offline(file, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open the file %s: %s\n", file, errbuf);
			return -1;
		}
	}

	printf("Device: %s\n", dev);

	/* Loop */
	pcap_loop(handle, -1, packet_handler, NULL);
	/* And close the session */
	pcap_close(handle);
	return 0;
}

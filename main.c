#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <sys/time.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#include "data_link.h"
#include "verbose.h"

int n;
pcap_t *handle;

static void signal_handler(int signo) {
    pcap_breakloop(handle);
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	struct tm *ts;
	char buf[80];
	// int i;
	// for (i = 0; i < header->len; ++i)
	// {
	// 	printf("%02x ", packet[i]);
	// 	if((i+1)%16 == 0)
	// 		printf("\n");
	// }
	// printf("\n");


	n++;
	//if(n<3) { 
		ts = localtime(&(header->ts.tv_sec));
		strftime(buf, sizeof(buf), "%a %Y-%m-%d %H:%M:%S %Z", ts);
		if(*args & LOW)
			printf("#%d: ", n);
		else 
			printf("Packet #%d -- %s | length %d bytes\n", n, buf, header->len);
		ethernet_viewer(packet, *args);
		printf("\n");
	//}
}

void usage() {
	printf("usage \n");
}

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */

	n = 0;
	int tmp, verbose = HIGH;
	char c;
	char *file = NULL, *filter = NULL, *dev = NULL;

    if (signal(SIGINT, signal_handler) == SIG_ERR) {
        printf("An error occurred while setting a signal handler.\n");
        return -1;
    }

	while((c = getopt(argc, argv, "i:o:f:v:h")) != -1) {
		switch(c) {
			case 'i':
				dev = optarg;
				break;
			case 'o':
				file = optarg;
				break;
			case 'f':
				filter = optarg;
				break;
			case 'v':
				tmp = atoi(optarg);
				if(tmp >= 1 && tmp <= 3)
					if(tmp == 3)
						verbose = HIGH;
					else
						verbose = tmp;
				else
					printf("Verbose level %d doesn't exist, the default level will be used.\n", tmp);
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
		if(filter != NULL) {
			if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
				fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
				return -1;
			}
			if (pcap_setfilter(handle, &fp) == -1) {
				fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
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


	printf("Device: %s\n\n", dev);

	/* Loop */
	pcap_loop(handle, -1, packet_handler, (u_char*)&verbose);
	/* And close the session */
	printf("\n\n%d packet captured\n", n);
	pcap_close(handle);
	return 0;
}

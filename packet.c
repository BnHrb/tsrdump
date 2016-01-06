#include <pcap.h>

#include "data_link.h"

void packet_viewer(const u_char *packet, u_char verbose) {
	ethernet_viewer(packet, verbose);
}
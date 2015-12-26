#include <pcap.h>

#include "data_link.h"

void packet_viewer(const u_char *packet) {
	ethernet_viewer(packet);
}
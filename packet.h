#include <arpa/inet.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <net/if_arp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

void packet_viewer(const u_char*);

void ethernet_viewer(const u_char*);

void arp_viewer(const u_char*);
void ip_viewer(const u_char*);

void tcp_viewer(const u_char*);
void udp_viewer(const u_char*);
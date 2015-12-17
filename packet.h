#include <arpa/inet.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

void packet_viewer(const u_char*);
void ethernet_viewer(const u_char*, struct ether_header*);
void ip_viewer(const u_char*, struct ip*);
void tcp_viewer(const u_char*, struct tcphdr*);
void udp_viewer(const u_char*, struct udphdr*);
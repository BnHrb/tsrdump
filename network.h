#define IP_ALEN 4

struct arpaddr
{
	unsigned char ar_sha[ETH_ALEN];
	unsigned char ar_spa[IP_ALEN];
	unsigned char ar_tha[ETH_ALEN];
	unsigned char ar_tpa[IP_ALEN];
};

void ip_viewer(const u_char*, u_char);
void arp_viewer(const u_char*, u_char);
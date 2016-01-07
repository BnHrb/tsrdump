struct dnshdr {
	u_int16_t query_id;
	u_int16_t flags;
	u_int16_t quest_count;
	u_int16_t answ_count;
	u_int16_t auth_count;
	u_int16_t add_count;
};

struct bootphdr {
	u_int8_t msg_type;
	u_int8_t hrdwr_type;
	u_int8_t hrdwr_addr_length;
	u_int8_t hops;
	u_int32_t trans_id;
	u_int16_t num_sec;
	u_int16_t flags;
	struct in_addr ciaddr;
	struct in_addr yiaddr;
	struct in_addr siaddr;
	struct in_addr giaddr;
	u_char hrdwr_caddr[16];
	u_char srv_name[64];
	u_char bpfile_name[128];
	u_int32_t magic_cookie;
};

void bootp_viewer(const u_char*, int, u_char);
void dns_viewer(const u_char*, int, u_char);
void http_viewer(const u_char*, int, u_char);
void ftp_viewer(const u_char*, int, u_char);
void smtp_viewer(const u_char*, int, u_char);
void pop_viewer(const u_char*, int, u_char);
void imap_viewer(const u_char*, int, u_char);
void telnet_viewer(const u_char*, int, u_char);
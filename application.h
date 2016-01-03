struct dnshdr {
	u_int16_t query_id;
	u_int16_t flags;
	u_int16_t quest_count;
	u_int16_t answ_count;
	u_int16_t auth_count;
	u_int16_t add_count;
};

void dhcp_viewer(const u_char*, int);
void dns_viewer(const u_char*, int);
void http_viewer(const u_char*, int);
void ftp_viewer(const u_char*, int);
void smtp_viewer(const u_char*, int);
void pop_viewer(const u_char*, int);
void imap_viewer(const u_char*, int);
void telnet_viewer(const u_char*, int);
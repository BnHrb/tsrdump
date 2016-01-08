# tsrdump
Projet M1 RISE transport et services réseau
Analyseur de trames sous Debian

Protocoles supportés: 

- Ethernet
- IPv4
- UDP, TCP, ARP
- BOOTP, DHCP, DNS, HTTP, FTP, SMTP, POP, IMAP, TELNET


Usage:
-i <interface> : interface pour l’analyse live

-o <fichier> : fichier d’entrée pour l’analyse offline

-f <filtre> : filtre BPF (optionnel)

-v <1..3> : niveau de verbosité (1=très concis ; 2=synthétique ; 3=complet)


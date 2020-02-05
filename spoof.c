#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>

struct ipheader {
	unsigned char      iph_ihl:4;
	unsigned char	   iph_ver:4;
	unsigned char      iph_tos;
	unsigned short int iph_len;
	unsigned short int iph_ident;
	unsigned short int iph_flag:3;
	unsigned short int iph_offset:13;
	unsigned char      iph_ttl;
	unsigned char	   iph_protocol;
	unsigned short int iph_chksum;
	struct   in_addr   iph_sourceip;
	struct   in_addr   iph_destip;  
};

struct icmpheader  {
	unsigned char icmp_type;
	unsigned char icmp_code;
	unsigned short int icmp_chksum;
	unsigned short int icmp_id;
	unsigned short int icmp_seq;
}

struct udpheader 
{
	u_int16_t udp_sport;
	u_int16_t udp_dport;
	u_int16_t udp_ulen;
	u_int16_t udp_sum;
};

unsigned short in_chksum(unsigned short *buf, int length);

void send_raw_ip_packet(struct ipheader* ip) {
	struct sockaddr_in dest_info;
	int enable = 1;

	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
			&enable, sizeof(enable));
	dest_info.sin_family = AF_INET;
	dest_info.sin_addr = ip ->iph_destip;

	sendto(sock, ip, ntohs(ip->iph_len), 0, 
		(struct sockaddr*)&dest_info, sizeof(dest_info));
	close(sock);	
}

int main()
{
  char buffer[1500];

  memset(buffer, 0, 1500);
  struct ipheader *ip = (struct ipheader *) buffer;
  struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));

  /*********************************************************
     Step 1: Fill in the UDP data field.
   ********************************************************/
  char *data = buffer + sizeof(struct ipheader) + sizeof(struct udpheader);
  const char *msg = "Hello Server!\n";
  int data_len = strlen(msg);
  strncpy (data, msg, data_len);

  /*********************************************************
     Step 2: Fill in the UDP header.
   ********************************************************/
  udp->udp_sport = htons(12345);
  udp->udp_dport = htons(9090);//Destination port for attack will use netcat for attack
  udp->udp_ulen = htons(sizeof(struct udpheader) + data_len);
  udp->udp_sum =  0; /* Many OSes ignore this field, so we do not 
                        calculate it. */

  /*********************************************************
     Step 3: Fill in the IP header.
   ********************************************************/
  ip->iph_ver = 4;
  ip->iph_ihl = 5;
  ip->iph_ttl = 20;
  ip->iph_sourceip.s_addr = inet_addr("1.2.3.4");
  ip->iph_destip.s_addr = inet_addr("10.0.2.7");//IP Address of VM2 target machine
  ip->iph_protocol = IPPROTO_UDP; // The value is 17.
  ip->iph_len = htons(sizeof(struct ipheader) +
                      sizeof(struct udpheader) + data_len);

  /*********************************************************
     Step 4: Finally, send the spoofed packet
   ********************************************************/
  send_raw_ip_packet (ip);

  return 0;
}

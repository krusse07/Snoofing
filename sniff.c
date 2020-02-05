#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>


struct ipheader {
	unsigned char      iph_ihl:4,
		      	   iph_ver:4;
	unsigned char      iph_tos;
	unsigned short int iph_len;
	unsigned short int iph_ident;
	unsigned short int iph_flag,
		       	   iph_offset;
	unsigned char      iph_ttl;
	unsigned char	   iph_protocol;
	unsigned short int iph_chksum;
	struct   in_addr   iph_sourceip;
	struct   in_addr   iph_destip;  
};

struct ethheader {
	u_char ether_dhost[6];
	u_char ether_shost[6];
	u_short ether_type;
};

struct tcpheader 
{
	u_short tcp_sport;
	u_short tcp_dport;
	u_int   tcp_seq;
	u_int   tcp_ack;
	u_char  tcp_offx2;
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
	u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS 
	//(TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short tcp_win;
	u_short tcp_sum;
	u_short tcp_urp;
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, 
		const u_char *packet)
{
	//typecast the ipheader struct 
	struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader));
	unsigned short pktlen = ntohs(ip->iph_len);
	struct tcpheader *tcp = (struct tcpheader *)((u_char*)ip + sizeof(struct ipheader));
	u_char dataoffset = TH_OFF(tcp) * 4;
	
	if ((pktlen - sizeof(struct ipheader)) > dataoffset)
	{
	  printf(" SrcIP: %s,", inet_ntoa(ip->iph_sourceip));
	  printf(" DstIP: %s,", inet_ntoa(ip->iph_destip));
	  printf(" Data: ");
	  u_char* data = (u_char*)tcp + dataoffset;
	  for (unsigned short s = 0; s < (ntohs(ip->iph_len) - (sizeof(struct ipheader) + dataoffset));s++)
	  {
 		if (isprint(*data) != 0)
		{
			printf("%c", *data);
		}
		else
		{
			printf("\\%.3hho", *data);
		}
		data++;
	    }
	    printf("\n");
	}
 
}

int main()
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "tcp port telnet";
	bpf_u_int32 net;
	
	handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

	pcap_compile(handle, &fp, filter_exp, 0, net);
	pcap_setfilter(handle, &fp);

	pcap_loop(handle, -1, got_packet, NULL);

	pcap_close(handle);
	return 0;
}

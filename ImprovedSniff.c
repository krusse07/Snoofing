#include <pcap.h>
#include <stdio.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, 
		const u_char *packet)
{
	struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader));
	unsigned short pktlen = ntohs(ip->iph_len);
	printf(" SrcIP: %s,", inet_ntoa(ip->iph_sourceip));
	printf(" DstIP: %s,", inet_ntoa(ip->iph_destip));
	printf(" PktLenIP: %hu\n", pktlen);

	switch(ip->iph_protocol)
	{
	  case IPPROTO_TCP:
		printf(" Protocol: TCP\n");
		break;
	  case IPPROTO_UDP:
		printf(" Protocol: UDP\n");
		break;
	  case IPPROTO_ICMP:
		printf(" Protocol: ICMP\n");
		break;
	  default:
		printf(" Protocol: others\n");
		break;
	}
	printf("\n");
}

int main()
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "ip proto icmp";
	bpf_u_int32 net;
	
	//open live pcap session on NIC with eth specific name to own device.
	handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

	pcap_compile(handle, &fp, filter_exp, 0, net);
	pcap_setfilter(handle, &fp);

	pcap_loop(handle, -1, got_packet, NULL);

	pcap_close(handle);
	return 0;
}

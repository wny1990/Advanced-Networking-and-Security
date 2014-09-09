#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <stdbool.h>
#include <errno.h>
#include <ctype.h>

#include <signal.h>
#include <sys/syscall.h>    

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <pcap.h>

#include <map>
#include <set>
#include <iostream>
#include "net.h"
#define SIZE_ETHERNET 14
using namespace std;
map<pair<int,int>,string> in_flow;
map<pair<int,int>,string> out_flow;
 
void processPacket(u_char* prot, const struct pcap_pkthdr* pkthdr, const u_char * packet)
{ 
    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip; /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */
    const u_char *payload; /* Packet payload */
   u_int size_ip;
    u_int size_tcp; 
    ethernet = (const struct sniff_ethernet*)(packet);
    ip = (const struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) 
    {
//	printf("   * Invalid IP header length: %u bytes\n", size_ip);
	return;
    }
    tcp = (const struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
  //  int ip_addr = ip_to_int ( ip->ip_src);
    if (size_tcp < 20) 
    {
//	printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
	return;
    }
    payload = (packet + SIZE_ETHERNET + size_ip + size_tcp);

    int i = 0;
/*
    0: undefined;
    1: last source
    2: last destination

*/
    int status = 0;

    if (*prot == 1 )
    {
	if ( ntohs(tcp->th_sport) != 80 &&  ntohs(tcp->th_dport) != 80 )
	{
		printf("non http packet %u, %u\n",ntohs(tcp->th_sport),ntohs(tcp->th_dport));
		return;	
	}   
    }
    else if (*prot == 2 )
    {
	if ( ntohs(tcp->th_sport) != 21 &&  ntohs(tcp->th_dport) != 21 && ntohs(tcp->th_sport) != 20 &&  ntohs(tcp->th_dport) != 20 )
	{
		printf("non ftp packet %u, %u\n",ntohs(tcp->th_sport),ntohs(tcp->th_dport));
		return;	
	}
    }
    else if (*prot == 3 )
    {
	if ( ntohs(tcp->th_sport) != 23 &&  ntohs(tcp->th_dport) != 23 )
	{
		printf("non telnet packet %u, %u\n",ntohs(tcp->th_sport),ntohs(tcp->th_dport));
		return;	
	}   
    }

//    printf("\n\n\nport %u, %u\n\n\n\n",ntohs(tcp->th_sport),ntohs(tcp->th_dport));

    for (i=  SIZE_ETHERNET + size_ip + size_tcp; i < pkthdr->len; i++)
    { 
		map<pair<int,int>,string>::iterator it;
	    	string s ;
		int ip_addr;
		if (ntohs(tcp->th_sport) == 80)
		{
    			ip_addr =  ip->ip_src.s_addr;
			if ( ! in_flow.count({ip_addr,ntohs(tcp->th_dport)}))
				in_flow.insert( { {ip_addr,ntohs(tcp->th_dport)},string() });
			it = in_flow.find({ip_addr,ntohs(tcp->th_dport)});
			s = it->second;
			in_flow.erase({ip_addr,ntohs(tcp->th_dport)});
			s.push_back(packet[i]);
			in_flow.insert( { {ip_addr,ntohs(tcp->th_dport)},s });
		}
		else if (ntohs(tcp->th_dport) == 80)
		{
    			ip_addr =  ip->ip_dst.s_addr;
			if ( !out_flow.count({ip_addr,ntohs(tcp->th_sport)}))
				out_flow.insert( { {ip_addr,ntohs(tcp->th_sport)},string() });
			it = out_flow.find({ip_addr,ntohs(tcp->th_sport)});
			s = it->second;
			out_flow.erase({ip_addr,ntohs(tcp->th_sport)});
			s.push_back(packet[i]);
			out_flow.insert( { {ip_addr,ntohs(tcp->th_sport)},s });
		}
     } 

   return; 
} 


int main(int argc,char **argv)
{ 
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    struct bpf_program fp;      /* hold compiled program     */
    bpf_u_int32 maskp;          /* subnet mask               */
    bpf_u_int32 netp;           /* ip                        */
    char *filter_expr;
    u_char prot;                   /* protocol number*/
    pcap_t *pcap;
    unsigned char *packet;
    struct pcap_pkthdr header;
//    printf("Enter your network trace file path: ");
//    scanf("%s",trace_path);
//     trace_path = "tfsession.pcap" ;
    char trace_path[] = "httpsession.pcap" ;
//    printf("Choose the protocol you want to analyze\n ");
 //   printf("Enter 1 for http, Enter 2 for ftp, Enter 3 for telnet:\n");
//    scanf("%d",&prot);
    prot = 1;
    pcap = pcap_open_offline(trace_path, errbuf);
    if (pcap == NULL)
    {
	fprintf(stderr, "error reading pcap file: %s\n", errbuf);
	return 1;
    }
// process the packet
    if ( pcap_loop(pcap, -1, processPacket,&prot) == -1){
        fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr) );
 }

    for(auto it = in_flow.begin(); it != in_flow.end(); it++)
	cout << it->second << endl;
    for(auto it = out_flow.begin(); it != out_flow.end(); it++)
	cout << it->second << endl;

}

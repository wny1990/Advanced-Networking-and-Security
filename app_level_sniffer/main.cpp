#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <pcap.h>

#include <map>
#include <set>
#include <iostream>
#include "net.h"
#define SIZE_ETHERNET 14
using namespace std;
map<pair<int,int>,string> flow;
// last = 1 response
// last = 2 request
map<pair<int,int>,int> last;
//convert the ip address to a readable string
string ip_to_string(int ip)
{
	char s[20] ="";
	string result = "";
	
	sprintf(s,"%d", ip &  127);
	result.append(s);
	result.append(".");
	sprintf(s,"%d", (ip &  ( 127 << 8)) >> 8);
	result.append(s);
	result.append(".");
	sprintf(s,"%d", (ip &  ( 127 << 16 )) >> 16);
	result.append(s);
	result.append(".");
	sprintf(s,"%d",  (ip & ( 127  << 24)) >> 24 );
	result.append(s);
	return result;
}
//if the users choices matchs the port number
bool match(int port, int protocal)
{
	if( port == 80 && protocal == 1)
		return true;
	if( port == 21 && protocal == 2)
		return true;
	if( port == 20 && protocal == 2)
		return true;
	if( port == 23 && protocal == 3)
		return true;

	return false;
}
 
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
 //Invalid IP header length
    if (size_ip < 20) 
	return;
    tcp = (const struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
//Invalid TCP header length
    if (size_tcp < 20) 
	return;
    payload = (packet + SIZE_ETHERNET + size_ip + size_tcp);

    if (*prot == 1 )
    {
	if ( ntohs(tcp->th_sport) != 80 &&  ntohs(tcp->th_dport) != 80 )
		return;	
    }
    else if (*prot == 2 )
    {
	if ( ntohs(tcp->th_sport) != 21 &&  ntohs(tcp->th_dport) != 21 && ntohs(tcp->th_sport) != 20 &&  ntohs(tcp->th_dport) != 20 )
		return;	
    }
    else if (*prot == 3 )
    {
	if ( ntohs(tcp->th_sport) != 23 &&  ntohs(tcp->th_dport) != 23 )
		return;	
    }


// add the packet paylod into a has table, entry is set according to a pair {ip,port}
    for (int i=  SIZE_ETHERNET + size_ip + size_tcp; i < pkthdr->len; i++)
    { 
		map<pair<int,int>,string>::iterator it;
	    	string s  = "";
		int ip_addr;
		if ( match(ntohs(tcp->th_sport),*prot))
		{
    			ip_addr =  ip->ip_src.s_addr;
			if ( ! flow.count({ip_addr,ntohs(tcp->th_dport)}))
				flow.insert( { {ip_addr,ntohs(tcp->th_dport)},string() });
			it = flow.find({ip_addr,ntohs(tcp->th_dport)});
			s.append(it->second);
			if ( i == SIZE_ETHERNET + size_ip + size_tcp)
			{
				if ( last.count({ip_addr,ntohs(tcp->th_dport)}))
				{
					auto ii =  last.find({ip_addr,ntohs(tcp->th_dport)});
					if ( ii->second != 1)
						s.append("\nResponse:\n");
				}
				else
					s.append("\nResponse:\n");
			}
			flow.erase({ip_addr,ntohs(tcp->th_dport)});
			if ( isprint(packet[i]) || packet[i] == '\n')
				s.push_back(packet[i]);
			else
			{	
				char temp[5];
				sprintf(temp," %d ",packet[i]);
				s.append(temp);

			}
			flow.insert( { {ip_addr,ntohs(tcp->th_dport)},s });
			
			if ( last.count({ip_addr,ntohs(tcp->th_dport)}))
					last.erase({ip_addr,ntohs(tcp->th_dport)});
			 last.insert({{ip_addr,ntohs(tcp->th_dport)},1});
		}
		else if (match(ntohs(tcp->th_dport),*prot))
		{
    			ip_addr =  ip->ip_dst.s_addr;
			if ( !flow.count({ip_addr,ntohs(tcp->th_sport)}))
				flow.insert( { {ip_addr,ntohs(tcp->th_sport)},string() });
			it = flow.find({ip_addr,ntohs(tcp->th_sport)});
			s.append(it->second);
			if ( i == SIZE_ETHERNET + size_ip + size_tcp )
			{
				if ( last.count({ip_addr,ntohs(tcp->th_sport)}))
				{
					auto ii =  last.find({ip_addr,ntohs(tcp->th_sport)});
					if ( ii->second != 2)
						s.append("\nRequest:\n");
				}
				else
					s.append("\nRequest:\n");
			}
			flow.erase({ip_addr,ntohs(tcp->th_sport)});
			if ( isprint(packet[i]) || packet[i] == '\n')
			    s.push_back(packet[i]);
			else
			{	
				char temp[5];
				sprintf(temp,"%d",packet[i]);
				s.append(temp);

			}
			flow.insert( { {ip_addr,ntohs(tcp->th_sport)},s });
			if ( last.count({ip_addr,ntohs(tcp->th_sport)}))
					last.erase({ip_addr,ntohs(tcp->th_sport)});
			 last.insert({{ip_addr,ntohs(tcp->th_sport)},2});
	
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
    char trace_path[100];
    printf("Enter your network trace file path: \n");
    scanf("%s",trace_path);
    printf("Choose the protocol you want to analyze\n ");
    printf("Enter 1 for http, Enter 2 for ftp, Enter 3 for telnet:\n");
    scanf("%d",&prot);
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
    if (prot == 1)
	cout << "Protocal HTTP:" << endl;
    else if (prot == 2)
	cout << "Protocal FTP:" << endl;
    else if (prot == 3)
	cout << "Protocal TELNET:" << endl;
    cout << endl;
    cout << endl;
// Go through the hash map and output the combined payload from every entry.

    for(auto it = flow.begin(); it != flow.end(); it++)
    {
	cout << "Session Between Server IP:" << ip_to_string(it->first.first) << " and  Local Client Port:" << it->first.second << ":" << endl;
	cout << it->second << endl;
        cout << endl;
        cout << endl;
    }

}

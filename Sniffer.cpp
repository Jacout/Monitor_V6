#include "Sniffer.h"
#include "JSONGen.h"
#include <pcap.h>
#include <iostream>
#include <sstream>
#include <ctime>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>

using json = nlohmann::json;
int icmpCounter = 0;
std::string timestamp()
{
    std::time_t now = std::time(nullptr);
    char buf[30];
    std::strftime(
        buf,
        sizeof(buf),
        "%Y-%m-%dT%H:%M:%SZ",
        std::gmtime(&now)
    );
    return buf;
}
std::string bytesHex(const u_char *packet,int len)
{
    std::stringstream ss;
    for(int i=0;i<len;i++)
    {
        ss<<std::hex<<(int)packet[i]<<" ";
    }
    return ss.str();
}

void packetHandler(
u_char *args,
const struct pcap_pkthdr *header,
const u_char *packet
)
{
struct ether_header *eth =
(struct ether_header *)packet;
json evento;
evento["timestamp"]=timestamp();
evento["header_bytes"]=bytesHex(packet,24);
switch(ntohs(eth->ether_type))
{
case ETHERTYPE_ARP:
evento["event"]="arp_packet";
JSONGen::agregarEvento(evento,"eventos.json");
std::cout<<"ARP detectado"<<std::endl;
break;
case ETHERTYPE_IP:
{
struct ip *ipHeader =
(struct ip *)(packet+14);
switch(ipHeader->ip_p)
{
case IPPROTO_ICMP:
icmpCounter++;
evento["event"]="icmp_packet";
JSONGen::agregarEvento(evento,"eventos.json");
std::cout<<"ICMP detectado"<<std::endl;
if(icmpCounter>10)
{
json anomalia;
anomalia["event"]="anomaly";
anomalia["description"]="Posible ICMP flood";
anomalia["timestamp"]=timestamp();
JSONGen::agregarEvento(anomalia,"eventos.json");
}
break;
case IPPROTO_TCP:
{
struct tcphdr *tcp =
(struct tcphdr *)(packet+14+ipHeader->ip_hl*4);
if(tcp->syn==1 && tcp->ack==0)
{
evento["event"]="tcp_syn";
JSONGen::agregarEvento(evento,"eventos.json");
std::cout<<"TCP SYN detectado"<<std::endl;
}
break;
}
case IPPROTO_UDP:
evento["event"]="udp_packet";
JSONGen::agregarEvento(evento,"eventos.json");
std::cout<<"UDP detectado"<<std::endl;
break;
}
break;
}
}
}
void Sniffer::iniciar(const std::string& iface)
{
char errbuf[PCAP_ERRBUF_SIZE];
pcap_t *handle;
handle = pcap_open_live(
iface.c_str(),
BUFSIZ,
1,
1000,
errbuf
);
if(handle==NULL)
{
    std::cerr<<"Error interfaz"<<std::endl;
    return;
}
struct bpf_program fp;
char filter_exp[] = "arp or icmp or tcp or udp";
bpf_u_int32 net;
pcap_compile(handle,&fp,filter_exp,0,net);
pcap_setfilter(handle,&fp);
std::cout<<"Sniffer iniciado"<<std::endl;
pcap_loop(handle,0,packetHandler,NULL);
pcap_close(handle);
}
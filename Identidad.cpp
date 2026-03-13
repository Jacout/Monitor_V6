#include "Identidad.h"
#include <fstream>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netdb.h>

std::string Identidad::obtenerMAC(const std::string& iface)
{
std::string ruta = "/sys/class/net/" + iface + "/address";
std::ifstream file(ruta);
std::string mac;
if(file.is_open())
getline(file, mac);
return mac;
}
std::string Identidad::obtenerIP(const std::string& iface)
{
struct ifaddrs *ifaddr;
getifaddrs(&ifaddr);
std::string ip="";
for(struct ifaddrs *ifa = ifaddr; ifa!=NULL; ifa=ifa->ifa_next)
{
if(ifa->ifa_addr==NULL)
continue;
if(ifa->ifa_addr->sa_family==AF_INET)
{
if(iface==ifa->ifa_name)
{
char host[NI_MAXHOST];
getnameinfo(
ifa->ifa_addr,
sizeof(struct sockaddr_in),
host,
NI_MAXHOST,
NULL,
0,
NI_NUMERICHOST
);
ip=host;
}
}
}
freeifaddrs(ifaddr);
return ip;
}
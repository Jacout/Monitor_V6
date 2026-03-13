#include "Sniffer.h"
#include <pcap.h>
#include <iostream>

void packetHandler(u_char *args,
                   const struct pcap_pkthdr *header,
                   const u_char *packet)
{
    std::cout << "Paquete capturado - tamaño: "
              << header->len << std::endl;
}

void Sniffer::iniciar(const std::string& iface) {

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_live(
        iface.c_str(),
        BUFSIZ,
        1,
        1000,
        errbuf
    );

    if(handle == nullptr) {
        std::cerr << "Error pcap: " << errbuf << std::endl;
        return;
    }

    pcap_loop(handle, 0, packetHandler, NULL);

    pcap_close(handle);
}
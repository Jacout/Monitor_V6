#include <iostream>
#include <thread>
#include <chrono>

#include "Identidad.h"
#include "Sniffer.h"
#include "Analisis.h"
#include "JSONGen.h"

void monitorIdentidad(
    std::string iface,
    int intervalo,
    std::string archivo)
{
    std::string macPrev = Identidad::obtenerMAC(iface);
    std::string ipPrev = Identidad::obtenerIP(iface);

    while(true)
    {
        std::this_thread::sleep_for(
            std::chrono::milliseconds(intervalo)
        );

        std::string macNew = Identidad::obtenerMAC(iface);
        std::string ipNew = Identidad::obtenerIP(iface);

        if(Analisis::detectarCambio(macPrev, macNew)) {

            std::cout << "Cambio MAC detectado\n";

            JSONGen::guardarEvento(
                archivo,
                "mac_change",
                macPrev + " -> " + macNew
            );

            macPrev = macNew;
        }

        if(Analisis::detectarCambio(ipPrev, ipNew)) {

            std::cout << "Cambio IP detectado\n";

            JSONGen::guardarEvento(
                archivo,
                "ip_change",
                ipPrev + " -> " + ipNew
            );

            ipPrev = ipNew;
        }
    }
}

int main() {

    std::string iface;
    int intervalo;
    std::string archivo;

    std::cout << "Interfaz: ";
    std::cin >> iface;

    std::cout << "Intervalo ms: ";
    std::cin >> intervalo;

    std::cout << "Archivo JSON: ";
    std::cin >> archivo;

    std::thread t1(monitorIdentidad, iface, intervalo, archivo);
    std::thread t2(Sniffer::iniciar, iface);

    t1.join();
    t2.join();
}
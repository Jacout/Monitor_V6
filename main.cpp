#include <iostream>
#include <thread>
#include <chrono>
#include <ctime>
#include "Identidad.h"
#include "Sniffer.h"
#include "JSONGen.h"

using json = nlohmann::json;
int main()
{
    std::string interfaz;
    int intervalo;
    std::string archivoJSON;
    std::cout << "Interfaz: ";
    std::cin >> interfaz;
    std::cout << "Intervalo identidad(ms): ";
    std::cin >> intervalo;
    std::cout << "Archivo JSON: ";
    std::cin >> archivoJSON;
    std::string macPrev = Identidad::obtenerMAC(interfaz);
    std::string ipPrev = Identidad::obtenerIP(interfaz);
    std::thread snifferThread(
        Sniffer::iniciar,
        interfaz
    );
    while(true)
    {
        std::this_thread::sleep_for(
            std::chrono::milliseconds(intervalo)
        );
        std::string macActual =
        Identidad::obtenerMAC(interfaz);
        std::string ipActual =
        Identidad::obtenerIP(interfaz);
        if(macActual != macPrev)
        {
            json evento;
            evento["event"] = "mac_change";
            evento["old_value"] = macPrev;
            evento["new_value"] = macActual;
            std::time_t now = std::time(nullptr);
            char buf[30];
            std::strftime(
                buf,
                sizeof(buf),
                "%Y-%m-%dT%H:%M:%SZ",
                std::gmtime(&now)
            );
            evento["timestamp"] = buf;
            JSONGen::agregarEvento(evento, archivoJSON);
            std::cout << "Cambio MAC detectado\n";
            macPrev = macActual;
        }
        if(ipActual != ipPrev)
        {
            json evento;
            evento["event"] = "ip_change";
            evento["old_value"] = ipPrev;
            evento["new_value"] = ipActual;
            std::time_t now = std::time(nullptr);
            char buf[30];
            std::strftime(
                buf,
                sizeof(buf),
                "%Y-%m-%dT%H:%M:%SZ",
                std::gmtime(&now)
            );
            evento["timestamp"] = buf;
            JSONGen::agregarEvento(evento, archivoJSON);
            std::cout << "Cambio IP detectado\n";
            ipPrev = ipActual;
        }
    }
    snifferThread.join();
    return 0;
}
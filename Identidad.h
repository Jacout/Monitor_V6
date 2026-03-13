#ifndef IDENTIDAD_H
#define IDENTIDAD_H
#include <string>

class Identidad {
public:
static std::string obtenerMAC(const std::string& iface);
static std::string obtenerIP(const std::string& iface);
};

#endif
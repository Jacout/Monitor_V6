#ifndef ANALISIS_H
#define ANALISIS_H

#include <string>

class Analisis {
public:
    static bool detectarCambio(
        const std::string& oldVal,
        const std::string& newVal
    );
};

#endif
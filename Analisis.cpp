#include "Analisis.h"

bool Analisis::detectarCambio(
    const std::string& oldVal,
    const std::string& newVal)
{
    return oldVal != newVal;
}
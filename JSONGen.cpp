#include "JSONGen.h"
#include <fstream>
#include <vector>

using json = nlohmann::json;
std::vector<json> eventos;
void JSONGen::agregarEvento(
    json evento,
    const std::string& archivo
)
{
    eventos.push_back(evento);
    std::ofstream file(archivo);
    json salida = eventos;
    file << salida.dump(4);
}

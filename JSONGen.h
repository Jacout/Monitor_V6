#ifndef JSONGEN_H
#define JSONGEN_H
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

class JSONGen {
public:
static void agregarEvento(
    nlohmann::json evento,
    const std::string& archivo
);
};
#endif

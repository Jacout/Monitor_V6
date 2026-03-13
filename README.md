# Proyecto: Monitor híbrido de identidad digital y tráfico anómalo en C++
## Descripción general
Herramienta en C++ para Linux que monitorea cambios en IP/MAC, captura tráfico relevante
y clasifica eventos anómalos. Genera un reporte JSON con todos los eventos detectados.
## Integrantes del equipo
- Matthew Rosas Lailson — SuperCapish — Módulo Identidad
- Jacob Misael Rodriguez Morales — Jacout — Módulo Sniffer
- Cruz Eduardo Patiño Zuñiga — PapiCruz — Módulo Análisis
- Jahir Guadalupe Salazar Esparza — Naizard — Módulo JSONGen
## Requisitos
- Ubuntu/Debian
- g++ (C++17)
- libpcap
- nlohmann/json
## Compilación
```bash
g++ main.cpp Identidad.cpp Sniffer.cpp Analisis.cpp JSONGen.cpp -o monitor
-lpcap -pthread
```
Ejecución
```bash
./monitor
```
# Interfaz: eth0
# Intervalo identidad: 500 ms
# Archivo JSON: eventos.json
Enfoque técnico
- Lectura de IP/MAC con getifaddrs y archivos del sistema.
- Sniffing con libpcap y filtros BPF.
- Clasificación de anomalías definida por el equipo.
- Serialización JSON con nlohmann/json.
Ejemplo de JSON generado
[
{
"event": "mac_change",
"old_value": "...",
"new_value": "...",
"timestamp": "..."
}
]

#!/usr/bin/env bash
# run_demo.sh -- atajo para la demo automatica de extremo a extremo.
#
# Compila el P4 (si hace falta) y corre la demo completa:
#   topologia + controlador + prueba de latencia.
#
# Uso:
#   sudo bash tests/run_demo.sh
set -e

# Ubicarse en la raiz del proyecto (un nivel arriba de tests/).
cd "$(dirname "$0")/.."

if [ ! -f build/dns_cache.json ]; then
    echo ">> Compilando el programa P4..."
    make build
fi

echo ">> Lanzando la demo automatica (necesita sudo)..."
sudo python3 tests/demo_auto.py

# IA
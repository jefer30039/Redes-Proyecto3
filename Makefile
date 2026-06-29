# Makefile del proyecto Cache DNS en P4
# -------------------------------------
# Objetivos:
#   make            -> compila el programa P4 a build/dns_cache.json
#   make run        -> levanta la topologia Mininet (correr SIN sudo: el sudo va adentro)
#   make controller -> corre el control plane (otra terminal, sin sudo)
#   make clean      -> borra los archivos generados
#
# Nota sobre PYTHON: 'run' y 'controller' usan $(PYTHON), que se resuelve con
# `which python3`. Asi, si estas en el entorno virtual de la VM de P4
# (p4dev-python-venv), se usa ESE interprete aunque el comando lleve sudo.
# Con "sudo python3" a secas, sudo se sale del venv y no encuentra
# Mininet/Scapy; por eso usamos `which python3`.

P4C        ?= p4c-bm2-ss
PYTHON     ?= $(shell which python3)
P4_SRC      = p4/dns_cache.p4
BUILD_DIR   = build
P4_JSON     = $(BUILD_DIR)/dns_cache.json

.PHONY: all build run controller clean

all: build

# Compilar el P4 al formato JSON que entiende BMv2.
build: $(P4_JSON)

$(P4_JSON): $(P4_SRC)
	@mkdir -p $(BUILD_DIR)
	$(P4C) --p4v 16 \
	       --p4runtime-files $(BUILD_DIR)/dns_cache.p4info.txt \
	       -o $(P4_JSON) $(P4_SRC)
	@echo ">> Compilado OK: $(P4_JSON)"

# Levantar la red (deja la consola de Mininet abierta).
run: build
	sudo $(PYTHON) src/topology.py --json $(P4_JSON)

# Correr el controlador (en otra terminal, con la red ya levantada).
controller:
	sudo $(PYTHON) src/controller.py

clean:
	rm -rf $(BUILD_DIR) results __pycache__ src/__pycache__ tests/__pycache__
	rm -f /tmp/p4s.*.log /tmp/dns_server.log /tmp/controller*.log
	@echo ">> Limpio."
	
#IA
"""
    Diagnostico: muestra que hay en el cache del switch

    - Para cada dominio de prueba calcula el indice y la huella que DEBERIA tener usando common.py -> la misma logica que el switch y los comparamos con lo que realmente esta guardado en los registers del switch

    (Esto se lo preguntamos a la IA como hacerlo porque no teniamos idea como debia hacerlo)
    Asi sabemos si un dominio:
    - No esta en cache (valid=0) -> problema del controlador que no poblo
    - Esta con huella distinta-> problema de HASH que no coincide
    - Esta correcto pero igual no acierta -> problema del DATA PLANE o sea la mala respuesta

    Correr>
    sudo $(which python3) tests/dump_cache.py
"""

import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
import common

JSON = os.path.join(ROOT, "build", "dns_cache.json")
THRIFT = common.THRIFT_PORT

# Los dominios a inspeccionar son los mismos de la prueba de latencia.
DOMINIOS = ["p4.org", "www.example.com", "redes.lab", "test.local"]


def resolve_reg_names():
    # Lee del JSON el nombre real de los registers con o sin prefijo.
    names = {n: n for n in ["cache_valid", "cache_fp", "cache_ip", "hit_counter", "miss_counter"]}
    if os.path.exists(JSON):
        with open(JSON) as f:
            j = json.load(f)
        regs = [r.get("name", "") for r in j.get("register_arrays", [])]
        for n in list(names):
            for r in regs:
                if r == n or r.endswith("." + n):
                    names[n] = r
                    break
    return names


def reg_read(name, index):
    out = subprocess.run(["simple_switch_CLI", "--thrift-port", str(THRIFT)], input="register_read {} {}\n".format(name, index), capture_output=True, text=True).stdout
    m = re.search(r"=\s*(\d+)", out)
    return int(m.group(1)) if m else None


def main():
    names = resolve_reg_names()
    print("Registers detectados:", {k: names[k] for k in ["cache_valid", "cache_fp", "cache_ip"]})
    print()

    hits = reg_read(names["hit_counter"], 0)
    misses = reg_read(names["miss_counter"], 0)
    print("Contadores: hits={} misses={}".format(hits, misses))
    print()

    for dom in DOMINIOS:
        idx = common.cache_index(dom)
        exp_fp = common.fnv1a_32(dom)
        valid = reg_read(names["cache_valid"], idx)
        fp = reg_read(names["cache_fp"], idx)
        ip = reg_read(names["cache_ip"], idx)

        ip_str = common.int_to_ip(ip) if ip else "-"

        if not valid:
            estado = "NO POBLADO (revisar controlador)"
        elif fp != exp_fp:
            estado = "HUELLA DISTINTA (hash no coincide)"
        else:
            estado = "OK (deberia acertar)"

        fp_str = "0x{:08X}".format(fp) if fp is not None else "-"
        print("{}: idx={} valid={} fp_switch={} fp_esperado=0x{:08X} ip={} -> {}"
              .format(dom, idx, valid, fp_str, exp_fp, ip_str, estado))


if __name__ == "__main__":
    main()

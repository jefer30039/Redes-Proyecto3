"""
    Prueba de latencia HIT vs MISS usando la MEDIANA como metrica

    Para cada dominio hace varias consultas seguidas:
    - la 1a consulta es un MISS cache vacio -> va al servidor real
    - las siguientes son HIT responde el switch desde el cache

    Por que decidimos usar MEDIANA y no el promedio:
    - El HIT dura < 1 ms, asi que un solo pico de jitter del switch por software BMv2 lo distorsiona muchisimo. El promedio se contamina con esos picos y encontramos que a veces empeoraba 
    al aumentar el numero de consultas -> la MEDIANA ignora los picos raros y da un valor estable y representativo.

    - Se descartan las primeras WARMUP consultas tras el MISS porque a veces el controlador todavia no escribio el cache.

    - los "HIT" anormalmente altos >UMBRAL_REMISS_MS se cuentan aparte como re-MISS para que no ensucien la mediana.

    Corre con:
    h1 python3 tests/latency_test.py
"""

import os
import socket
import statistics
import sys
import time

# permitir importar common.py y dns_client.py desde src/
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import common
from dns_client import query_once

# dominios a probar
DOMINIOS = ["p4.org", "www.example.com", "redes.lab", "test.local",]

CONSULTAS_POR_DOMINIO = 30
PAUSA = 0.3 # segundos entre consultas
TIMEOUT = 2.0
WARMUP = 1 # consultas tras el MISS que se descartan
UMBRAL_REMISS_MS = 5.0  # un "HIT" por encima de esto se cuenta como re-MISS


def resumen_hits(valores):
    # devuelve -> mediana, p90, minimo, cantidad de una lista de RTT en ms.
    if not valores:
        return None, None, None, 0
    s = sorted(valores)
    mediana = statistics.median(s)
    idx_p90 = max(0, int(round(0.9 * (len(s) - 1)))) # percentil 90 simple
    return mediana, s[idx_p90], s[0], len(s)


def main():
    server = common.DNS_SERVER_IP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)

    print()
    print("PRUEBA DE LATENCIA - servidor DNS: {}".format(server))
    print("metrica principal: MEDIANA (se descartan {} de calentamiento)" .format(WARMUP))
    print()

    filas = [] # un dict de resultados por dominio
    miss_global = [] # los MISS de cada dominio
    hits_global = [] # todos los HIT juntos para calcular la mediana global

    for dom in DOMINIOS:
        rtts = []
        for i in range(CONSULTAS_POR_DOMINIO):
            rtt, ip = query_once(sock, server, dom, TIMEOUT)
            rtts.append(rtt)
            time.sleep(PAUSA)

        miss = rtts[0] # 1a consulta = MISS
        post = [r for r in rtts[1 + WARMUP:] if r is not None]
        hits = [r for r in post if r <= UMBRAL_REMISS_MS] # HIT reales
        remiss = [r for r in post if r > UMBRAL_REMISS_MS] # re-MISS

        mediana, p90, minimo, n = resumen_hits(hits)
        speedup = (miss / mediana) if (miss and mediana) else None

        if miss is not None:
            miss_global.append(miss)
        hits_global.extend(hits)

        filas.append({"dom": dom, "miss": miss, "mediana": mediana, "p90": p90, "min": minimo, "speedup": speedup, "remiss": len(remiss), "n": n})

        print("Dominio: {}".format(dom))
        print("MISS (1a consulta): {}".format(
            "{:.3f} ms".format(miss) if miss is not None else "timeout"))
        if mediana is not None:
            print("HIT mediana: {:.3f} ms".format(mediana))
            print("HIT p90/min: {:.3f} / {:.3f} ms".format(p90, minimo))
            print("HIT muestras: {}".format(n))
        if remiss:
            print("re-MISS detectados: {} (posible expiracion por TTL)"
                  .format(len(remiss)))
        if speedup:
            print("speedup (MISS/HIT): {:.1f}x".format(speedup))
        print()

    sock.close()

    # Resumen de resultados
    print("RESUMEN (HIT por mediana)")
    print()

    def fmt(x):
        return "{:.3f}".format(x) if x is not None else "-"

    for f in filas:
        sp = "{:.1f}x".format(f["speedup"]) if f["speedup"] else "-"
        print("{}: MISS={} ms, HIT med={} ms, p90={}, min={}, speedup={}, reMISS={}" .format(f["dom"], fmt(f["miss"]), fmt(f["mediana"]), fmt(f["p90"]), fmt(f["min"]), sp, f["remiss"]))

    if miss_global and hits_global:
        g_miss = statistics.median(miss_global)
        g_hit = statistics.median(hits_global)
        print()
        print("GLOBAL (medianas): MISS={:.3f} ms, HIT={:.3f} ms, speedup={:.1f}x" .format(g_miss, g_hit, g_miss / g_hit))
        print()
        print("Interpretacion:")
        print("sin cache (va al servidor): MISS = {:.3f} ms".format(g_miss))
        print("con cache (responde switch): HIT = {:.3f} ms".format(g_hit))

    # Guardar CSV
    results_dir = os.path.join(ROOT, "results")
    os.makedirs(results_dir, exist_ok=True)
    csv_path = os.path.join(results_dir, "latency.csv")
    with open(csv_path, "w") as fcsv:
        fcsv.write("dominio,miss_ms,hit_mediana_ms,hit_p90_ms,hit_min_ms," "speedup,re_miss,n_muestras\n")
        for f in filas:
            fcsv.write("{},{},{},{},{},{},{},{}\n".format(f["dom"], fmt(f["miss"]), fmt(f["mediana"]), fmt(f["p90"]), fmt(f["min"]), "{:.2f}".format(f["speedup"]) if f["speedup"] else "", f["remiss"], f["n"]))
    print("\n(OK) CSV guardado en {}".format(csv_path))

    # Guardar grafica
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        doms = [f["dom"] for f in filas if f["miss"] is not None and f["mediana"] is not None]
        miss_vals = [f["miss"] for f in filas if f["miss"] is not None and f["mediana"] is not None]
        hit_vals = [f["mediana"] for f in filas if f["miss"] is not None and f["mediana"] is not None]

        x = range(len(doms))
        w = 0.35
        plt.figure(figsize=(8, 5))
        plt.bar([i - w / 2 for i in x], miss_vals, w, label="MISS (sin cache)")
        plt.bar([i + w / 2 for i in x], hit_vals, w, label="HIT mediana (con cache)")
        plt.xticks(list(x), doms, rotation=20)
        plt.ylabel("Latencia (ms)")
        plt.title("Latencia DNS: con cache vs sin cache (mediana)")
        plt.legend()
        plt.tight_layout()
        png_path = os.path.join(results_dir, "latency.png")
        plt.savefig(png_path)
        print("(OK) Grafica guardada en {}".format(png_path))
    except ImportError:
        print("(i) matplotlib no esta instalado: se omite la grafica "
              "(usa el CSV).")

# Se aclara que para mejorar legibilidad de los datos los prints tienen IA

if __name__ == "__main__":
    main()

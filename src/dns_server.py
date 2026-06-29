"""
    servidor DNS simulado con Scapy:
    1. Corre en el host dns de la topologia y escucha en UDP puerto 53 y responde consultas tipo A con las IPs de una pequena zona.
    2. Para que la mejora del cache se note de verdad, el servidor agrega un pequeno retardo artificial por defecto de 20 ms que imita la latencia para medir bien el experimento.

    Esto se lanza desde la topologia de forma auto
"""

import argparse
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common

from scapy.all import DNS, DNSQR, DNSRR  # noqa: E402


# Zona DNS -> dominios que el servidor "conoce" y su IP registro A.
# Agregar mas dominios aqui si son necesarios para las pruebas.
ZONE = {
    "www.example.com.": "93.184.216.34",
    "example.com.":     "93.184.216.34",
    "p4.org.":          "198.51.100.10",
    "redes.lab.":       "10.0.1.200",
    "test.local.":      "203.0.113.5",
    "uno.lab.":         "10.0.1.201",
    "dos.lab.":         "10.0.1.202",
    "tres.lab.":        "10.0.1.203",
    "cuatro.lab.":      "10.0.1.204",
}

DEFAULT_TTL = 30  # TTL (seg) de los registros que entrega el servidor.

def build_response(query_pkt, delay):
    """Recibe los bytes de una consulta DNS y devuelve los bytes de la respuesta."""
    dns = DNS(query_pkt)
    if dns.qr != 0 or dns.qd is None:
        return None # No es una consulta valida

    qname = dns.qd.qname
    qname_str = qname.decode() if isinstance(qname, bytes) else qname
    if not qname_str.endswith("."):
        qname_str += "."

    ip = ZONE.get(qname_str)
    if ip is None:
        return None # Dominio desconocido -> sin respuesta.

    # Simular la latencia de un resolver real.
    if delay > 0:
        time.sleep(delay)

    # Construir la respuesta -> copia el ID y la pregunta y agrega el A.
    resp = DNS( id=dns.id, qr=1, aa=1, rd=dns.rd, ra=1, qd=dns.qd, an=DNSRR(rrname=qname, type="A", rclass="IN", ttl=DEFAULT_TTL, rdata=ip))
    return bytes(resp)


def main():
    ap = argparse.ArgumentParser(description="Servidor DNS simulado (Scapy)")
    ap.add_argument("--bind", default="0.0.0.0", help="IP donde escuchar (por defecto todas)")
    ap.add_argument("--delay", type=float, default=0.02, help="retardo artificial por consulta, en segundos " "(simula latencia del resolver real)")
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, 53))

    print("(DNS) Servidor escuchando en {}:53 (retardo={:.0f} ms)".format(args.bind, args.delay * 1000))
    print("(DNS) Dominios conocidos: {}".format(", ".join(d.rstrip(".") for d in ZONE)))

    try:
        while True:
            data, addr = sock.recvfrom(2048)
            resp = build_response(data, args.delay)
            if resp is not None:
                sock.sendto(resp, addr)
    except KeyboardInterrupt:
        print("\n(DNS) Servidor detenido.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()

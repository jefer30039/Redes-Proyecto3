"""
    cliente DNS sencillo que mide latencia:
    - envia consultas DNS tipo A a un servidor y mide la latencia.

    correr con los ejemplos:
    python3 src/dns_client.py --server 10.0.1.53 --domain p4.org
    python3 src/dns_client.py --server 10.0.1.53 --domain p4.org --count 5
"""

import argparse
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common

from scapy.all import DNS, DNSQR


def query_once(sock, server_ip, domain, timeout):
    #hace 1 consulta y devuelve rtt_ms, ip_resuelta o (None, None).
    pkt = DNS(rd=1, qd=DNSQR(qname=domain, qtype="A"))
    data = bytes(pkt)

    t0 = time.perf_counter()
    sock.sendto(data, (server_ip, 53))
    try:
        resp, _ = sock.recvfrom(2048)
    except socket.timeout:
        return None, None
    t1 = time.perf_counter()

    rtt_ms = (t1 - t0) * 1000.0

    # sacar la primera IP de la respuesta si hay.
    dns = DNS(resp)
    ip = None
    if dns.ancount and dns.an is not None:
        rr = dns.an
        for _ in range(int(dns.ancount)):
            if rr is None:
                break
            if int(getattr(rr, "type", 0)) == 1:
                ip = rr.rdata
                ip = ip.decode() if isinstance(ip, bytes) else ip
                break
            rr = rr.payload if rr.payload else None
    return rtt_ms, ip


def main():
    ap = argparse.ArgumentParser(description="Cliente DNS con medicion de RTT")
    ap.add_argument("--server", default=common.DNS_SERVER_IP, help="IP del servidor DNS")
    ap.add_argument("--domain", required=True, help="dominio a consultar")
    ap.add_argument("--count", type=int, default=1, help="cuantas consultas hacer")
    ap.add_argument("--timeout", type=float, default=2.0, help="timeout por consulta (segundos)")
    ap.add_argument("--gap", type=float, default=0.3, help="pausa entre consultas (segundos)")
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)

    print("Consultando '{}' a {} ({} veces):".format(args.domain, args.server, args.count))
    for i in range(args.count):
        rtt, ip = query_once(sock, args.server, args.domain, args.timeout)
        etiqueta = "MISS (1a vez)" if i == 0 else "HIT esperado"
        if rtt is None:
            print("consulta {}: sin respuesta (timeout)".format(i + 1))
        else:
            print("consulta {}: {:.3f} ms -> {} ({})".format(
                i + 1, rtt, str(ip), etiqueta))
        if i < args.count - 1:
            time.sleep(args.gap)

    sock.close()


if __name__ == "__main__":
    main()

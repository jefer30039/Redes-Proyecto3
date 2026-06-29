"""
    controlador del switch:
    - llena la tabla de reenvio del switch con MAC de cada host -> puerto
    - SNIFF a la interfaz que da al servidor DNS para que cada vez que el servidor real responde una consulta, el controlador aprenda el dominio -> IP y escriba esa entrada en el cache del switch
    - maneja el TTL -> si una entrada del cache ya expiro la invalida
    - muestra un dashboard en consola con hits, misses y hit rate

"""

import argparse
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time

# importa las constantes y la funcion de hash compartidas
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common

from scapy.all import sniff, DNS, DNSRR


# capa de comunicacion con el switch -> simple_switch_CLI por THRIFT
class SwitchCLI:
    # envoltorio sencillo alrededor de simple_switch_CLI

    def __init__(self, thrift_port, cli_bin="simple_switch_CLI"):
        self.thrift_port = thrift_port
        self.cli_bin = cli_bin

    def run(self, commands):
        # esto ejecuta uno o varios comandos y devuelve la salida
        proc = subprocess.run([self.cli_bin, "--thrift-port", str(self.thrift_port)], input=commands + "\n", capture_output=True, text=True)
        
        if proc.returncode != 0 and proc.stderr.strip():
            print("(CLI) aviso:", proc.stderr.strip())
        
        return proc.stdout

    def register_write(self, name, index, value):
        self.run("register_write {} {} {}".format(name, index, value))

    def register_read(self, name, index):
        out = self.run("register_read {} {}".format(name, index))
        
        # la salida trae algo como nombre[indice]= 42
        m = re.search(r"=\s*(\d+)", out)
        return int(m.group(1)) if m else 0

    def table_add(self, table, action, key, params):
        self.run("table_add {} {} {} => {}".format(table, action, key, params))


# controlador principal
class DnsCacheController:

    def __init__(self, thrift_port, iface, json_path, show_dashboard=True):
        self.sw = SwitchCLI(thrift_port)
        self.iface = iface
        self.show_dashboard = show_dashboard

        # nombres reales leidos del JSON de BMv2
        self.names = self._resolve_names(json_path)

        # entradas vivas en el cache con indice -> instante_de_expiración - dominio
        self.entries = {}
        self.lock = threading.Lock()
        self.running = True

        # cola de escrituras pendientes -> SNIFF solo encola y un hilo writer_loop 
        # aparte hace la escritura lenta en el switch para evitar que el SNIFF se atrase
        self.write_q = queue.Queue()

    def _resolve_names(self, json_path):
        # IA para arreglar problemas de obtener el nombre de los register tabla action que se caía

        wanted = ["cache_valid", "cache_fp", "cache_ip",
                  "hit_counter", "miss_counter", "dmac_forward", "set_egress"]
        names = {w: w for w in wanted}

        if not os.path.exists(json_path):
            print("(!) No encontre {}; uso nombres cortos.".format(json_path))
            return names

        with open(json_path) as f:
            j = json.load(f)

        def pick(candidatos, suffix):
            for n in candidatos:
                if n == suffix or n.endswith("." + suffix):
                    return n
            return suffix

        reg_names = [r.get("name", "") for r in j.get("register_arrays", [])]
        
        for r in ["cache_valid", "cache_fp", "cache_ip", "hit_counter", "miss_counter"]:
            names[r] = pick(reg_names, r)

        act_names = [a.get("name", "") for a in j.get("actions", [])]
        names["set_egress"] = pick(act_names, "set_egress")

        tbl_names = []
        for pipe in j.get("pipelines", []):
            for t in pipe.get("tables", []):
                tbl_names.append(t.get("name", ""))
        names["dmac_forward"] = pick(tbl_names, "dmac_forward")

        return names

    # se carga la tabla de reenvio
    def setup_forwarding(self):
        print("- Cargando tabla de reenvio (MAC -> puerto)...")
        for name, (ip, mac, port) in common.HOSTS.items():
            key = common.mac_to_hex(mac)
            self.sw.table_add(self.names["dmac_forward"],
                              self.names["set_egress"], key, str(port))
            print("{} {} -> puerto {}".format(name, mac, port))

    # se reinician los contadores
    def reset_counters(self):
        self.sw.register_write(self.names["hit_counter"], 0, 0)
        self.sw.register_write(self.names["miss_counter"], 0, 0)
        print("- Contadores hit/miss reiniciados a 0.")

    # se llena el cache al ver respuestas DNS
    def on_dns_response(self, pkt):
        
        # el callback de Scapy se llama por cada paquete capturado
        if not pkt.haslayer(DNS):
            return
        dns = pkt[DNS]

        # solo tomamos respuestas que traigan al menos 1 answer
        if dns.qr != 1 or dns.ancount < 1 or dns.qd is None:
            return

        domain = dns.qd.qname  # nombre consultado (bytes)

        # busca el primer registro A con type == 1 en la seccion de respuestas
        answer_ip = None
        rr = dns.an

        for _ in range(int(dns.ancount)):
            if rr is None:
                break
            
            if isinstance(rr, DNSRR) and int(rr.type) == 1: # 1 = A
                answer_ip = rr.rdata
                ttl = int(rr.ttl)
                break
            rr = rr.payload if rr.payload else None

        if answer_ip is None:
            return # no habia un registro A

        if isinstance(answer_ip, bytes):
            answer_ip = answer_ip.decode()

        # calcular indice y huella igual que como lo hace el switch
        idx = common.cache_index(domain)
        fp = common.fnv1a_32(domain)
        ip_int = common.ip_to_int(answer_ip)


        # esto lo descubrimos con IA
        # se encola la escritura y regresa de inmediato porque el sniff no debe hacer trabajo lento porque si no Scapy descarta los paquetes que llegan mientras tanto -> el hilo que tenemos writer_loop se encarga de escribir en el switch
        self.write_q.put((idx, fp, ip_int, ttl, domain, answer_ip))

    def writer_loop(self):
        # hilo que escribe en el switch lo que el sniff va encolandole para las 3 escrituras de registers en una sola llamada a la CLI
        
        while self.running:
            try:
                idx, fp, ip_int, ttl, domain, answer_ip = \
                    self.write_q.get(timeout=0.5)
            except queue.Empty:
                continue

            cmds = "\n".join(["register_write {} {} {}".format(self.names["cache_ip"], idx, ip_int), "register_write {} {} {}".format(self.names["cache_fp"], idx, fp), "register_write {} {} 1".format(self.names["cache_valid"], idx),])
            self.sw.run(cmds)

            with self.lock:
                self.entries[idx] = (time.time() + ttl, domain)

            dom_str = domain.decode() if isinstance(domain, bytes) else domain
            
            print("\n(CACHE+) {} -> {} (idx={}, ttl={}s)".format(dom_str.rstrip("."), answer_ip, idx, ttl))

    def sniff_loop(self):
        print("- Escuchando respuestas DNS en la interfaz '{}'...".format(self.iface))
        
        # filtro BPF para solo UDP con puerto origen 53, o sea solo respuestas del servidor admitidas
        sniff(iface=self.iface, filter="udp src port 53", prn=self.on_dns_response, store=False, stop_filter=lambda p: not self.running)

    # expiracion por TTL
    def ttl_loop(self):
        while self.running:
            now = time.time()
            expirados = []
            
            with self.lock:
                for idx, (exp, dom) in list(self.entries.items()):
                    if now >= exp:
                        expirados.append((idx, dom))
                        del self.entries[idx]
            
            for idx, dom in expirados:
                self.sw.register_write(self.names["cache_valid"], idx, 0)
                dom_str = dom.decode() if isinstance(dom, bytes) else dom
                print("\n(CACHE-) expiro {} (idx={})".format(dom_str.rstrip("."), idx))
            time.sleep(1)

    # dashboard
    def dashboard_loop(self):
        while self.running:
            hits = self.sw.register_read(self.names["hit_counter"], 0)
            misses = self.sw.register_read(self.names["miss_counter"], 0)
            total = hits + misses
            rate = (100.0 * hits / total) if total else 0.0
           
            with self.lock:
                activos = len(self.entries)
            sys.stdout.write("\r(DASHBOARD) hits={} misses={} total={} hit-rate={:.1f}% " "cache={}   ".format(hits, misses, total, rate, activos))
            sys.stdout.flush()
            time.sleep(1)

    # on start
    def start(self):
        self.setup_forwarding()
        self.reset_counters()

        # hilo que escribe en el switch separado del SNIFF
        threading.Thread(target=self.writer_loop, daemon=True).start()
        threading.Thread(target=self.ttl_loop, daemon=True).start()
        
        if self.show_dashboard:
            threading.Thread(target=self.dashboard_loop, daemon=True).start()

        print("- Controlador listo. Ctrl+C para salir.\n")

        try:
            self.sniff_loop()
        except KeyboardInterrupt:
            pass
        finally:
            self.running = False
            print("\n- Controlador detenido.")


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    default_json = os.path.join(root, "build", "dns_cache.json")

    ap = argparse.ArgumentParser(description="Control plane del cache DNS en P4")
    ap.add_argument("--thrift-port", type=int, default=common.THRIFT_PORT)
    ap.add_argument("--iface", default=common.DNS_SNIFF_IFACE, help="interfaz del switch que mira al servidor DNS")
    ap.add_argument("--json", default=default_json, help="programa P4 compilado")
    ap.add_argument("--no-dashboard", action="store_true", help="sin dashboard")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("Debe ejecutar el programa con permisos de superusuario")
        sys.exit(1)

    ctrl = DnsCacheController(args.thrift_port, args.iface, args.json, show_dashboard=not args.no_dashboard)
    ctrl.start()

    # para darle formato muchos prints se pasaron por IA para que la informacion se entendiera a simple vista

if __name__ == "__main__":
    main()

import argparse
import os
import shlex
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common

from mininet.net import Mininet
from mininet.node import Switch, Host
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_JSON = os.path.join(ROOT, "build", "dns_cache.json")


# Nodo mininet que corre el switch BMv2

class P4Switch(Switch):
    """Switch de Mininet que ejecuta el modelo de software BMv2."""

    def __init__(self, name, json_path=DEFAULT_JSON, thrift_port=9090, sw_path="simple_switch", device_id=0, **kwargs):
        Switch.__init__(self, name, **kwargs)
        self.json_path = json_path
        self.thrift_port = thrift_port
        self.sw_path = sw_path
        self.device_id = device_id
        self.logfile = "/tmp/p4s.%s.log" % name

    def start(self, controllers):
        # Construye la linea de comando de simple_switch.
        args = [self.sw_path]
        for port, intf in self.intfs.items():
            if intf.name != "lo": # saltar la interfaz loopback
                args.extend(["-i", "%d@%s" % (port, intf.name)])

        args.extend(["--thrift-port", str(self.thrift_port)])
        args.extend(["--device-id", str(self.device_id)])
        args.append(shlex.quote(self.json_path))

        cmd = " ".join(args) + " >" + shlex.quote(self.logfile) + " 2>&1 &"
        print("(s1) arrancando BMv2: " + " ".join(args))
        self.cmd(cmd)
        time.sleep(1) # darle tiempo a levantar THRIFT

    def stop(self, deleteIntfs=True):
        self.cmd("kill %" + self.sw_path)
        self.cmd("wait")
        super(P4Switch, self).stop(deleteIntfs)


def build_network(json_path, delay):
    net = Mininet(controller=None, link=TCLink, host=Host, switch=P4Switch)

    print("*** Creando el switch P4")
    s1 = net.addSwitch(common.SWITCH_NAME, cls=P4Switch, json_path=json_path, thrift_port=common.THRIFT_PORT)

    print("*** Creando hosts y enlaces")
    hosts = {}
    for name, (ip, mac, port) in common.HOSTS.items():
        h = net.addHost(name, ip=ip + "/24", mac=mac)
        net.addLink(h, s1, port2=port) # fija el puerto del switch
        hosts[name] = h

    net.start()

    print("*** Configurando hosts (offload, IPv6, ARP estatico)")
    for name, h in hosts.items():
        intf = h.defaultIntf().name

        # Apagar offload para que los checksums viajen correctos.
        h.cmd("ethtool --offload %s rx off tx off > /dev/null 2>&1" % intf)
        h.cmd("ethtool -K %s gro off gso off tso off > /dev/null 2>&1" % intf)

        # Apagar IPv6 para que no aparezca trafico NDP suelto.
        h.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null 2>&1")
        h.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1 > /dev/null 2>&1")

    # cada host conoce de antemano la MAC de los demas por ARP estatico.
    for name, h in hosts.items():
        for other, (oip, omac, oport) in common.HOSTS.items():
            if other != name:
                h.setARP(oip, omac)

    print("*** Iniciando el servidor DNS en el host 'dns' (retardo=%.0f ms)" % (delay * 1000))
    dns_host = hosts["dns"]
    server = os.path.join(ROOT, "src", "dns_server.py")

    # Esto de abajo no servia y lo modificamos con IA.

    # Usar el mismo interprete que corre esta topologia (en un entorno virtual, el servidor DNS tambien tiene Scapy disponible).
    dns_host.cmd("%s %s --delay %f > /tmp/dns_server.log 2>&1 &"
                 % (shlex.quote(sys.executable), shlex.quote(server), delay))

    return net


def main():
    ap = argparse.ArgumentParser(description="Topologia Mininet del cache DNS")
    ap.add_argument("--json", default=DEFAULT_JSON, help="programa P4 compilado (.json de BMv2)")
    ap.add_argument("--delay", type=float, default=0.02, help="retardo del servidor DNS en segundos")
    args = ap.parse_args()

    if not os.path.exists(args.json):
        print("ERROR: no existe '%s'." % args.json)
        print("       Compila primero el P4 con:  make")
        sys.exit(1)

    setLogLevel("info")
    net = build_network(args.json, args.delay)

    py = sys.executable
    print()
    print("Red lista. AHORA, en OTRA terminal, ejecuta el controlador:")
    print("sudo %s src/controller.py" % py)
    print("(sin el controlador no hay conectividad: la tabla esta vacia)")
    print()
    print("Ejemplos para probar desde la consola de Mininet:")
    print("h1 %s src/dns_client.py --domain p4.org --count 4" % py)
    print("h1 %s tests/latency_test.py" % py)
    print()

    CLI(net)
    net.stop()


if __name__ == "__main__":
    main()

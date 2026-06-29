# cantidad de entradas del cache
# sacar el indice con una mascara (h & (CACHE_SIZE - 1)) en vez de un modulo      ESTO LO ENCONTRAMOS CON IA
CACHE_SIZE = 1024
CACHE_MASK = CACHE_SIZE - 1

# cuantos bytes del nombre de dominio en formato DNS se usan
HASH_BYTES = 32

# constantes del hash FNV-1a de 32 bits
FNV_OFFSET_BASIS = 0x811C9DC5  # 2166136261
FNV_PRIME = 0x01000193  # 16777619
MASK32 = 0xFFFFFFFF

# puerto THRIFT donde escucha el switch BMv2
THRIFT_PORT = 9090

# TTL que el switch pone en la respuesta DNS de los HITs
DNS_ANSWER_TTL = 30

# todo en la misma subred 10.0.1.0/24 para no tener que enrutar
# nombre de la forma -> ip, mac, puerto_del_switch
HOSTS = {
    "h1":  ("10.0.1.1",  "08:00:00:00:01:01", 1), # cliente 1
    "h2":  ("10.0.1.2",  "08:00:00:00:01:02", 2), # cliente 2
    "h3":  ("10.0.1.3",  "08:00:00:00:01:03", 3), # cliente 3
    "h4":  ("10.0.1.4",  "08:00:00:00:01:04", 4), # cliente 4
    "dns": ("10.0.1.53", "08:00:00:00:00:53", 5), # servidor DNS real usado
}

# datos comodos del servidor DNS
DNS_SERVER_IP = HOSTS["dns"][0]
DNS_SERVER_MAC = HOSTS["dns"][1]
DNS_SERVER_PORT_SW = HOSTS["dns"][2]

# el controlador hace SNIFF ahi para ver las respuestas del servidor y poblar el cache -> nombre por defecto de mininet es s1-eth<puerto>
SWITCH_NAME = "s1"
DNS_SNIFF_IFACE = "{}-eth{}".format(SWITCH_NAME, DNS_SERVER_PORT_SW)


def encode_qname(domain):

    # convierte un nombre de dominio al formato de DNS.
    if isinstance(domain, bytes):
        domain = domain.decode("ascii", "ignore")

    domain = domain.rstrip(".") # quitar el punto final si viene uno
    out = bytearray()

    if domain: # dominio vacio
        for label in domain.split("."):
            label_bytes = label.encode("ascii", "ignore")
            out.append(len(label_bytes)) # byte de longitud
            out.extend(label_bytes) # bytes de la etiqueta

    out.append(0x00) # terminador
    return bytes(out)


def fnv1a_32(domain):
    
    """esta funcion es basicamente el codigo P4:
        - encode_qname
        - toma exactamente HASH_BYTES bytes
        - en el switch los bytes que no existen se leen como 0 -> aqui hacemos lo mismo para que coincida
        - aplicar FNV-1a byte por byte
        - devuelve un entero de 32 bits
    """
    wire = encode_qname(domain)
    buf = wire[:HASH_BYTES]

    if len(buf) < HASH_BYTES:
        buf = buf + b"\x00" * (HASH_BYTES - len(buf))

    h = FNV_OFFSET_BASIS
    
    for byte in buf:
        h = ((h ^ byte) * FNV_PRIME) & MASK32
    return h


def cache_index(domain):

    # indice dentro del arreglo de registers del cache
    return fnv1a_32(domain) & CACHE_MASK


def ip_to_int(ip):

    # IP tipo 10.0.1.53 -> 167772469 entero de 32 bits
    a, b, c, d = (int(x) for x in ip.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def int_to_ip(value):

    # lo contrario de entero 167772469 -> a IP 10.0.1.53
    value &= MASK32

    return "{}.{}.{}.{}".format((value >> 24) & 0xFF, (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF)


def mac_to_hex(mac):
    # cambia direccion MAC tipo 08:00:00:00:01:01 -> a HEX 0x080000000101 que es un formato que entiende simple_switch_CLI para una clave de 48 bits
    return "0x" + mac.replace(":", "").lower()


# prueba rapida -> python3 common.py nos imprime los hashes de unos dominios. Cambienlo si nos les sirve xd
if __name__ == "__main__":
    print("CACHE_SIZE = {} (mascara 0x{:X})".format(CACHE_SIZE, CACHE_MASK))
    print("HASH_BYTES = {}".format(HASH_BYTES))
    
    for d in ["www.example.com", "example.com", "p4.org",
              "redes.lab", "test.local"]:
        h = fnv1a_32(d)
        print("{} hash=0x{:08X} indice={}".format(d, h, h & CACHE_MASK))

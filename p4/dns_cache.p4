/* 
 *  Cache DNS dentro del plano de datos
 *
 *  El switch intercepta las consultas DNS UDP puerto 53 -> Para cada consulta tipo A
 *
 *    - Calcula un hash del nombre de dominio y lo usa como indice en un arreglo de registers.
 *
 *    - Si el dominio ya esta en cache -> HIT: el switch arma la respuesta DNS el mismo y la devuelve al cliente.
 *
 *    - Si no esta -> MISS: reenvia la consulta al servidor DNS real.
 *    
 *    La respuesta del servidor sera vista por el controlador SNIFF, que la mete en el cache para la proxima vez.
 *
 *  El cache se llena desde el controller.py. El plano de datos solo lee el cache para decidir hit o miss.
 *
 *  Arquitectura: v1model, ya que esta es la que se usa en todos los ejercicios que encontramos en el repo p4lang/tutorials. 
 *  Link al repo: https://github.com/p4lang/tutorials 
 */

#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8> PROTO_UDP = 17;
const bit<16> DNS_PORT = 53;
const bit<16> DNS_TYPE_A = 1; //tipo A -> IPv4

// Tamano del cache. debe ser potencia de 2 y coincidir con common.py.
#define CACHE_SIZE 1024
const bit<32> CACHE_MASK = 1023; // CACHE_SIZE - 1

// Maximo de bytes del nombre DNS que el parser puede leer.
#define MAX_QNAME 64

// Cuantos bytes del nombre se usan para el hash.
#define HASH_BYTES 32

// Constantes del hash FNV-1a de 32 bits igual que common.py.
const bit<32> FNV_OFFSET = 0x811C9DC5;
const bit<32> FNV_PRIME = 0x01000193;

// TTL en la respuesta de un HIT.
const bit<32> ANSWER_TTL = 30;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

// Encabezado fijo de dns, 12 bytes.
header dns_t {
    bit<16> id;
    bit<16> flags;
    bit<16> qdcount; // numero de preguntas
    bit<16> ancount; // numero de respuestas
    bit<16> nscount;
    bit<16> arcount;
}

// byte del nombre de dominio (QNAME) es parseado byte por byte usando header stack porque el nombre es de longitud variable.
header qbyte_t {
    bit<8> b;
}

// Lo que va justo despues del QNAME tipo y clase de la pregunta.
header dns_qtail_t {
    bit<16> qtype;
    bit<16> qclass;
}

// Registro de respuesta que se agrega en un HIT
// Son 16 bytes en total.
header dns_answer_t {
    bit<16> name; // 0xC00C = puntero de compresion a la pregunta
    bit<16> atype; // 1 = A
    bit<16> aclass; // 1 = IN
    bit<32> ttl; // tiempo de vida
    bit<16> rdlength; // 4 -> longitud IPv4
    bit<32> rdata; // la IP cacheada
}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    udp_t udp;
    dns_t dns;
    qbyte_t[MAX_QNAME] qname; // nombre de dominio de longitud variable
    dns_qtail_t dns_qtail;
    dns_answer_t dns_answer;
}

// variables temporales que viajan con el paquete
struct metadata {
    bit<32> hash; // hash del dominio que se usa como huella
    bit<32> index; // indice
    bit<1> is_dns_q; // 1 si es una consulta DNS tipo A
}

parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet { packet.extract(hdr.ethernet); transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 { packet.extract(hdr.ipv4); transition select(hdr.ipv4.protocol) {
            PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_udp { 
        packet.extract(hdr.udp);
        // Solo se parsea DNS cuando es una consulta hacia el puerto 53.
        transition select(hdr.udp.dstPort) {
            DNS_PORT: parse_dns;
            default:  accept;
        }
    }

    state parse_dns {
        packet.extract(hdr.dns);
        // Solo se manejan consultas de una sola pregunta.
        transition select(hdr.dns.qdcount) {
            1: parse_qname;
            default: accept;
        }
    }

    // Lee el QNAME byte por byte hasta encontrar el terminador 0x00.
    state parse_qname {
        packet.extract(hdr.qname.next);
        transition select(hdr.qname.last.b) {
            0: parse_qtail; // 0x00 -> fin del nombre
            default: parse_qname; // sigue otro byte del nombre
        }
    }

    state parse_qtail {
        packet.extract(hdr.dns_qtail);
        transition accept;
    }
}

// Verificacion de checksum
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

// logica del cache
control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    // cache_valid[i] = 1 si la entrada i tiene un dominio valido
    register<bit<8>>(CACHE_SIZE) cache_valid;

    // cache_fp[i] = hash completo del dominio
    register<bit<32>>(CACHE_SIZE) cache_fp;

    // cache_ip[i] = IP
    register<bit<32>>(CACHE_SIZE) cache_ip;

    // Contadores de hits y miss
    register<bit<32>>(1) hit_counter;
    register<bit<32>>(1) miss_counter;

    // Acciones basicas de reenvio L2
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_egress(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    // Tabla de reenvio que por MAC destino decide a que puerto va
    table dmac_forward {
        key = { hdr.ethernet.dstAddr: exact; }
        actions = { set_egress; drop; }
        size = 64;
        default_action = drop();
    }

    // Hash FNV-1a
    // funcion hecha con claude, revisada manualmente para asegurar que coincide con la del codigo de python
    // Calcula el hash del nombre de dominio
    action compute_hash() {
        // Para CADA posicion usamos el byte solo si fue parseado en ESTE
        // paquete (isValid()); si no, contribuye 0. Esto es indispensable:
        // BMv2 no pone en cero los slots no parseados (conservan basura de
        // paquetes anteriores), lo que corromperia el hash de los nombres
        // cortos. Con isValid() el resultado coincide EXACTO con el relleno
        // de ceros que hace common.py en Python.
        bit<32> h = FNV_OFFSET;
        h = (h ^ (hdr.qname[0].isValid()  ? (bit<32>)hdr.qname[0].b  : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[1].isValid()  ? (bit<32>)hdr.qname[1].b  : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[2].isValid()  ? (bit<32>)hdr.qname[2].b  : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[3].isValid()  ? (bit<32>)hdr.qname[3].b  : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[4].isValid()  ? (bit<32>)hdr.qname[4].b  : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[5].isValid()  ? (bit<32>)hdr.qname[5].b  : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[6].isValid()  ? (bit<32>)hdr.qname[6].b  : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[7].isValid()  ? (bit<32>)hdr.qname[7].b  : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[8].isValid()  ? (bit<32>)hdr.qname[8].b  : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[9].isValid()  ? (bit<32>)hdr.qname[9].b  : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[10].isValid() ? (bit<32>)hdr.qname[10].b : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[11].isValid() ? (bit<32>)hdr.qname[11].b : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[12].isValid() ? (bit<32>)hdr.qname[12].b : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[13].isValid() ? (bit<32>)hdr.qname[13].b : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[14].isValid() ? (bit<32>)hdr.qname[14].b : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[15].isValid() ? (bit<32>)hdr.qname[15].b : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[16].isValid() ? (bit<32>)hdr.qname[16].b : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[17].isValid() ? (bit<32>)hdr.qname[17].b : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[18].isValid() ? (bit<32>)hdr.qname[18].b : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[19].isValid() ? (bit<32>)hdr.qname[19].b : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[20].isValid() ? (bit<32>)hdr.qname[20].b : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[21].isValid() ? (bit<32>)hdr.qname[21].b : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[22].isValid() ? (bit<32>)hdr.qname[22].b : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[23].isValid() ? (bit<32>)hdr.qname[23].b : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[24].isValid() ? (bit<32>)hdr.qname[24].b : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[25].isValid() ? (bit<32>)hdr.qname[25].b : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[26].isValid() ? (bit<32>)hdr.qname[26].b : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[27].isValid() ? (bit<32>)hdr.qname[27].b : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[28].isValid() ? (bit<32>)hdr.qname[28].b : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[29].isValid() ? (bit<32>)hdr.qname[29].b : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[30].isValid() ? (bit<32>)hdr.qname[30].b : 32w0)) * FNV_PRIME;
        h = (h ^ (hdr.qname[31].isValid() ? (bit<32>)hdr.qname[31].b : 32w0)) * FNV_PRIME;
        meta.hash  = h;
        meta.index = h & CACHE_MASK;
    }

    // construye la respuesta DNS en un HIT
    action build_dns_response(in bit<32> answer_ip) {
        // se invierte MAC origen y destino
        bit<48> tmp_mac = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmp_mac;

        // se invierte IP origen y destino 
        bit<32> tmp_ip = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = tmp_ip;

        // se invierte puertos UDP.
        bit<16> tmp_port = hdr.udp.dstPort;
        hdr.udp.dstPort = hdr.udp.srcPort;
        hdr.udp.srcPort = tmp_port;

        // se marca el DNS como respuesta
        // 0x8180 = QR=1 (respuesta), RD=1, RA=1, rcode=0
        hdr.dns.flags = 0x8180;
        hdr.dns.ancount = 1; // 1 respuesta
        hdr.dns.nscount = 0;

        // se agrega el registro de respuesta de 16 bytes
        hdr.dns_answer.setValid();
        hdr.dns_answer.name = 0xC00C; // puntero al nombre de la pregunta
        hdr.dns_answer.atype = DNS_TYPE_A;
        hdr.dns_answer.aclass = 1; // IN
        hdr.dns_answer.ttl = ANSWER_TTL;
        hdr.dns_answer.rdlength = 4;
        hdr.dns_answer.rdata = answer_ip;

        // se corrige longitudes y se anula checksum UDP
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 16;
        hdr.udp.length = hdr.udp.length + 16;
        hdr.udp.checksum = 0; // checksum UDP opcional en IPv4 -> 0

        // se devuelve el paquete por el puerto de entrada
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    apply {
        // variables para leer el cache
        bit<8> valid = 0;
        bit<32> fp = 0;
        bit<32> ip = 0;
        bit<32> c = 0;

        meta.is_dns_q = 0;

        if (hdr.ipv4.isValid()) {

            // se comprueba si es una consulta DNS tipo A con una sola pregunta
            if (hdr.dns.isValid() &&
                hdr.dns.qdcount == 1 &&
                hdr.dns_qtail.qtype == DNS_TYPE_A) {

                meta.is_dns_q = 1;
                compute_hash();

                // se lee la entrada del cache en el indice calculado
                cache_valid.read(valid, meta.index);
                cache_fp.read(fp, meta.index);
                cache_ip.read(ip, meta.index);

                // HIT solo si la entrada es valida y la huella coincide
                if (valid == 1 && fp == meta.hash) {
                    // HIT: se responde nosotros
                    build_dns_response(ip);
                    hit_counter.read(c, 0);
                    hit_counter.write(0, c + 1);
                } else {
                    // MISS: va al servidor real
                    miss_counter.read(c, 0);
                    miss_counter.write(0, c + 1);
                    dmac_forward.apply();
                }
            } else {
                // trafico IPv4 normal o respuestas DNS -> reenvio L2
                dmac_forward.apply();
            }
        } else {
            // no es IPv4 -> reenvio L2
            dmac_forward.apply();
        }
    }
}

// egress no hace nada al reenvio
control MyEgress(inout headers hdr,inout metadata meta,inout standard_metadata_t standard_metadata) {
    apply { }
}

// recalculo del checksum IPv4
control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


// deparser serializa los headers en orden
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.dns);
        packet.emit(hdr.qname); // todo el nombre -> etiquetas + 0x00
        packet.emit(hdr.dns_qtail);
        packet.emit(hdr.dns_answer); // solo se emite si es valido
    }
}

// switch v1model creado
V1Switch(MyParser(),MyVerifyChecksum(),MyIngress(),MyEgress(),MyComputeChecksum(),MyDeparser()) main;

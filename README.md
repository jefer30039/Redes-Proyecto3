# Caché DNS en el Plano de Datos con P4

Proyecto Final de Redes de Computadoras — **Opción A**.

## 1. Requisitos

Usamos la **VM oficial de P4** (`p4lang`), que ya trae todo. Se necesita:

- `p4c` (compilador P4, binario `p4c-bm2-ss`)
- `BMv2` (`simple_switch`, `simple_switch_CLI`)
- `Mininet`
- `Python 3` con:
  - `scapy`
  - `matplotlib` (opcional para la gráfica de latencia)

Instalar las dependencias de Python:

```bash
pip3 install scapy matplotlib
```

> usamos el entorno virtual de la VM (`p4dev-python-venv`), los `make run` / `make controller` usan `which python3` para no salirse del venv aunque requieren sudo.

---

## 2. Instalación y compilación

compilar con:

```bash
make
```

al compilar correctamente se verá `>> Compilado OK: build/dns_cache.json`.

---

## 3. Ejecución

Se necesitan dos terminales, la red en una, el controlador en otra.

### Terminal 1

```bash
make run
```

Esto arranca la topologia de Mininet (switch P4 `s1`, clientes `h1`–`h4` y el host `dns`), lanza automáticamente el servidor DNS y deja abierta la consola de Mininet.

### Terminal 2

```bash
make controller
```

El controlador carga la tabla de reenvío, escucha las respuestas del servidor para poblar la caché, expira entradas por TTL y muestra un dashboard en vivo.

Sin el controlador no hay conectividad la tabla de reenvío arranca vacía

### En la terminal 1 con Mininet

Una consulta de prueba:

```bash
mininet> h1 python3 src/dns_client.py --domain p4.org --count 4
```

Prueba de latencia completa:

```bash
mininet> h1 python3 tests/latency_test.py
```

Inspeccionar el contenido de la caché del switch:

```bash
sudo $(which python3) tests/dump_cache.py
```

Dominios que el servidor conoce: `p4.org`, `www.example.com`, `example.com`,
`redes.lab`, `test.local`, `uno.lab`, `dos.lab`, `tres.lab`, `cuatro.lab`.

### Limpiar

```bash
make clean
```
---

## 4. Declaratoria de uso de IA

Hicimos uso de IA generativa para escribir y ajustar partes del código. La lógica central (programa P4, hash FNV-1a, poblado de la caché, lógica hit/miss, mediciones) es propio. Las partes asistidas por IA y cómo se verificaron son:

| # | Archivo / parte | Qué se generó o ajustó con IA | Cómo se verificó |
|---|---|---|---|
| 1 | `common.py` | Uso de máscara de bits (`h & (CACHE_SIZE-1)`) en lugar de módulo para obtener el índice de la caché. | `common.py` imprime índices entonces se compararon con los que calcula el switch con `dump_cache.py`. |
| 2 | `controller.py` → `_resolve_names()` | Leer del JSON de BMv2 los nombres reales de los registers/acciones/tabla con o sin prefijo. | Se levantó el switch y se comprobó que `table_add` y `register_write` no fallan por nombres inválidos. |
| 3 | `controller.py` → cola `write_q` + hilo `writer_loop` | Patrón de escritura asíncrona, el sniff solo encola y un hilo aparte escribe en el switch, para que Scapy no pierda paquetes. | En varias consultas no se pierden respuestas y el dashboard refleja correctamente los hits. |
| 4 | `controller.py` y `/latency_test.py` | Formato/redacción de los mensajes `print`. | Revisión visual de la salida en consola. |
| 5 | `topology.py` | Lanzar el servidor DNS con el mismo intérprete (`sys.executable`) para que funcione dentro del venv. | Se confirmó que el servidor responde a consultas desde dentro de Mininet. |
| 6 | `dump_cache.py` | Herramienta de diagnóstico completa, comparar huella esperada vs. la guardada en el switch. | Se usó para detectar y corregir el bug del hash de nombres cortos en BMv2. |
| 7 | `Makefile` y `run_demo.sh` | Estos archivos fueron hechos con IA. | Se ejecutaron los *targets* y el script. |
| 8 | `dns_cache.p4` → `compute_hash()` | Toda la funcion. | Se verificó que el hash del data plane coincide con el de Python comparando huellas con `tests/dump_cache.py`. |

Esta tabla fue formateada con IA 
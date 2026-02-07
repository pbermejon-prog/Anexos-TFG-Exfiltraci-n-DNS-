import math
import sys
import time
import os
import statistics
from collections import Counter, defaultdict
from scapy.all import sniff, DNS, DNSQR, IP

# ==========================================
# CONFIGURACIÓN DEL MOTOR DE DETECCIÓN
# ==========================================
INTERFAZ = "eth0"

# --- LISTA BLANCA (WHITELIST) ---
DOMINIOS_WHITELIST = {
    "google.com", "googleapis.com", "google.es", "doubleclick.net",
    "googletagmanager.com", "facebook.com", "microsoft.com", "azure.com",
    "github.com", "stackoverflow.com", "reddit.com", "wikipedia.org",
    "amazon.es", "amazon.com",
    "marca.com", "elmundo.es", "bbc.com",
    "piano.io", "cxense.com", "tinypass.com", "tradedoubler.com"
}

# 1. Detección por Payload
UMBRAL_ENTROPIA = 4.2
UMBRAL_LONGITUD = 58

# 2. Detección Volumétrica
BURST_WINDOW = 5.0
BURST_THRESHOLD = 60

# 3. Detección de Anomalía de Tipos
QTYPE_TXT = 16
QTYPE_NULL = 10
UMBRAL_TIPOS_RAROS = 5
VENTANA_TIEMPO_RAROS = 60.0

# 4. Detección de Beaconing
UMBRAL_COV = 0.5
MIN_MUESTRAS_BEACON = 10

# 5. Respuesta Activa
LIMITE_PARA_BLACKLIST = 60
LIMITE_PARA_BLOQUEO = 120

# ==========================================
# MEMORIA VOLÁTIL
# ==========================================
historial_beacon = defaultdict(list)
historial_rafaga = defaultdict(list)
historial_tipos_raros = defaultdict(list)

# Gestión de reputación
alertas_por_dominio = defaultdict(int)
dominios_maliciosos = set()
ips_bloqueadas = set()

# Estadísticas (Aseguramos que 'tipo' está a 0)
stats = {
    "alertas": 0,
    "falsos_positivos": 0,
    "entropia": 0, "longitud": 0, "rafaga": 0, "beacon": 0, "tipo": 0
}

# ==========================================
# INICIO
# ==========================================
os.system('clear')
print(f"[*] MOTOR DE DETECCIÓN DE EXFILTRACIÓN DNS (TFG P. Bermejo)")
print(f"[*] Whitelist: {len(DOMINIOS_WHITELIST)} dominios (Modo: Visualización Verde)")
print("-" * 190)
# He ampliado la columna de estadísticas a 40 caracteres para que quepa la T
print(f"{'TIME':<8} | {'SRC IP':<14} | {'TRAMA / PAYLOAD (QNAME)':<35} | {'FACTORES DETECTADOS':<25} | {'ESTADÍSTICAS (E,L,R,B,T)':<40} | {'ESTADO'}")
print("-" * 190)

def obtener_dominio_base(qname):
    partes = qname.split('.')
    if len(partes) >= 2:
        return f"{partes[-2]}.{partes[-1]}"
    return qname

def calcular_entropia(texto):
    if not texto: return 0
    cnt = Counter(texto)
    l = len(texto)
    return -sum((c/l) * math.log(c/l, 2) for c in cnt.values())

def bloquear_ip(ip):
    if ip in ips_bloqueadas: return
    print(f"\n[!!!] BLOQUEO ACTIVO: {ip} AÑADIDA A IPTABLES [!!!]\n")
    ips_bloqueadas.add(ip)

def detectar_beacon_segregado(ip, dominio, tiempo):
    clave = (ip, dominio)
    historial_beacon[clave].append(tiempo)
    if len(historial_beacon[clave]) > 20: historial_beacon[clave].pop(0)
    history = historial_beacon[clave]
    if len(history) < MIN_MUESTRAS_BEACON: return False, 0.0
    deltas = [history[i] - history[i-1] for i in range(1, len(history))]
    try:
        media = statistics.mean(deltas)
        dev = statistics.stdev(deltas)
        if media == 0: return False, 0.0
        cov = dev / media
        if cov < UMBRAL_COV: return True, cov
    except: pass
    return False, 0.0

def procesar_paquete(pkt):
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt.haslayer(IP):
        try:
            qname = pkt[DNSQR].qname.decode('utf-8').rstrip('.')
            qtype = pkt[DNSQR].qtype
            ip_src = pkt[IP].src
            full_time = float(pkt.time)
            dominio_base = obtener_dominio_base(qname)

            # Detectamos si es whitelist pero NO retornamos (para analizar falsos positivos)
            es_whitelist = dominio_base in DOMINIOS_WHITELIST

            razones = []

            # 1. ANÁLISIS DE PAYLOAD
            partes = qname.split('.')
            payload = max(partes, key=len) if partes else ""
            ent = calcular_entropia(payload)
            if ent > UMBRAL_ENTROPIA: razones.append(f"ENT({ent:.1f})")
            if len(payload) > UMBRAL_LONGITUD: razones.append(f"LEN({len(payload)})")

            # 2. ANÁLISIS VOLUMÉTRICO
            historial_rafaga[ip_src].append(full_time)
            historial_rafaga[ip_src] = [t for t in historial_rafaga[ip_src] if t > (full_time - BURST_WINDOW)]
            if len(historial_rafaga[ip_src]) > BURST_THRESHOLD:
                razones.append(f"BURST({len(historial_rafaga[ip_src])})")

            # 3. ANÁLISIS DE TIPOS (Aquí se genera la alerta TYPE)
            if qtype == QTYPE_TXT or qtype == QTYPE_NULL:
                historial_tipos_raros[ip_src].append(full_time)
                historial_tipos_raros[ip_src] = [t for t in historial_tipos_raros[ip_src] if t > (full_time - VENTANA_TIEMPO_RAROS)]
                cantidad_raros = len(historial_tipos_raros[ip_src])
                if cantidad_raros >= UMBRAL_TIPOS_RAROS:
                    tipo_str = "TXT" if qtype == QTYPE_TXT else "NULL"
                    razones.append(f"TYPE({tipo_str}-N{cantidad_raros})")

            # 4. ANÁLISIS COMPORTAMENTAL
            es_beacon, cov = detectar_beacon_segregado(ip_src, dominio_base, full_time)
            if es_beacon: razones.append(f"BEACON(CoV={cov:.2f})")

            # =========================================================
            # DECISIÓN FINAL Y VISUALIZACIÓN
            # =========================================================
            if razones:
                # Contabilizar métricas (tanto si es whitelist como si no)
                if not es_whitelist:
                    stats["alertas"] += 1
                else:
                    stats["falsos_positivos"] += 1

                # Sumar contadores específicos
                if "ENT" in str(razones): stats["entropia"] += 1
                if "LEN" in str(razones): stats["longitud"] += 1
                if "BURST" in str(razones): stats["rafaga"] += 1
                if "BEACON" in str(razones): stats["beacon"] += 1
                # AQUÍ ESTÁ LA CLAVE PARA LA T:
                if "TYPE" in str(razones): stats["tipo"] += 1

                # Calcular porcentajes
                total_eventos = stats["alertas"] + stats["falsos_positivos"]

                # Evitar división por cero
                p_e = stats["entropia"] / total_eventos if total_eventos else 0
                p_l = stats["longitud"] / total_eventos if total_eventos else 0
                p_r = stats["rafaga"] / total_eventos if total_eventos else 0
                p_b = stats["beacon"] / total_eventos if total_eventos else 0
                p_t = stats["tipo"] / total_eventos if total_eventos else 0

                # Formatear la cadena de texto con la T incluida
                st_txt = f"E:{p_e:.0%} L:{p_l:.0%} R:{p_r:.0%} B:{p_b:.0%} T:{p_t:.0%}"

                # LÓGICA DE ESTADO Y COLOR
                if es_whitelist:
                    # Verde para Whitelist (Falso Positivo)
                    estado = "FALSO POSITIVO"
                    color = "\033[92m"
                else:
                    # Lógica de riesgo real
                    alertas_por_dominio[dominio_base] += 1
                    total_dom = alertas_por_dominio[dominio_base]

                    estado = "SOSPECHOSO"
                    color = "\033[93m" # Amarillo

                    if total_dom >= LIMITE_PARA_BLACKLIST:
                        dominios_maliciosos.add(dominio_base)
                        estado = "MALICIOSO"
                        color = "\033[91m" # Rojo

                    if (dominio_base in dominios_maliciosos) and (total_dom >= LIMITE_PARA_BLOQUEO):
                        estado = "BLOQUEADO"
                        color = "\033[41m" # Fondo Rojo
                        bloquear_ip(ip_src)

                factores = "+".join(razones)
                RESET = "\033[0m"
                trama_visible = qname[:35]

                # Imprimir línea (con espacio extra para la T)
                print(f"{color}{full_time%10000:<8.1f} | {ip_src:<14} | {trama_visible:<35} | {factores:<25} | {st_txt:<40} | {estado}{RESET}")

        except Exception as e:
            pass

# Iniciar escucha
print(f"[*] Iniciando escucha en {INTERFAZ} (Puertos 53 y 5353)...")
sniff(iface=INTERFAZ, filter="udp port 53 or udp port 5353", prn=procesar_paquete, store=0)

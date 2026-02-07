import time
import re
import base64
import sys
import os

# --- CONFIGURACIÓN ---
LOG_FILE = "/var/cache/bind/dns_queries.log"
OUTPUT_FILE = "/datos_recuperados.txt"

def decode_payload(payload):
    """Intenta decodificar. Si falla, devuelve el original LIMPIO."""
    # Guardamos una copia del original por si acaso
    original = payload

    try:
        # 1. Intentamos arreglar padding para Base64
        padding = len(payload) % 4
        if padding:
            payload += '=' * (4 - padding)

        # 2. Intentamos decodificar
        decoded_bytes = base64.b64decode(payload)
        decoded_string = decoded_bytes.decode('utf-8')

        # Si funciona, limpiamos el resultado
        return decoded_string.strip().rstrip('=')

    except:
        # 3. ¡AQUÍ ESTABA EL ERROR!
        # Si falla (porque era texto plano), devolvemos el ORIGINAL
        # y nos aseguramos de quitarle cualquier basura
        return original.strip().rstrip('=')

def follow(thefile):
    thefile.seek(0, os.SEEK_END)
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line

def main():
    print(f"[*] INICIANDO RECONSTRUCTOR V3.1 (Bug Fix)")

    # Borramos el fichero viejo
    with open(OUTPUT_FILE, "w") as f:
        f.write("--- INICIO DE DATOS RECUPERADOS ---\n")

    print(f"[*] Monitorizando logs en tiempo real...")

    regex = re.compile(r'\((.*?)\.tunnel\.lab\)')

    try:
        with open(LOG_FILE, "r") as logfile:
            with open(OUTPUT_FILE, "a", buffering=1) as outfile:
                for line in follow(logfile):
                    match = regex.search(line)
                    if match:
                        full_subdomain = match.group(1)

                        if "C2_HEARTBEAT" in full_subdomain: continue

                        clean_data = decode_payload(full_subdomain)

                        if clean_data:
                            outfile.write(clean_data + "\n")
                            outfile.flush()
                            print(f"[+] Dato limpio: {clean_data}")

    except KeyboardInterrupt:
        print("\n[*] Deteniendo.")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()
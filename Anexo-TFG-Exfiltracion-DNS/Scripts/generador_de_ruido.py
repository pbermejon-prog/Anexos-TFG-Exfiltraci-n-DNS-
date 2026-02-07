import time
import random
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By

# Lista de sitios
SITIOS = [
    "https://www.marca.com", "https://www.elmundo.es",
    "https://www.amazon.es", "https://www.wikipedia.org",
    "https://www.reddit.com", "https://stackoverflow.com",
    "https://www.github.com", "https://www.bbc.com"
]

print("[*] Configurando navegador Chrome Headless (Modo Humano)...")
options = Options()
options.add_argument("--headless")
options.add_argument("--no-sandbox")
options.add_argument("--disable-dev-shm-usage")
options.add_argument("--disable-gpu")
options.page_load_strategy = 'eager'

service = Service(ChromeDriverManager().install())
driver = webdriver.Chrome(service=service, options=options)
driver.set_page_load_timeout(20)
driver.set_script_timeout(20)

print("[*] Iniciando navegación realista (Lenta)...")

while True:
    try:
        sitio = random.choice(SITIOS)
        try:
            dominio_base = sitio.split("www.")[-1].split("://")[-1].split("/")[0]
        except:
            dominio_base = sitio

        print(f"\n--> Visitando: {sitio}")

        try:
            driver.get(sitio)
        except Exception:
            print("    [!] Timeout de carga (normal en webs pesadas)...")

        # 1. Tiempo de "Primera Impresión" (El humano mira la portada)
        # Antes era 0s, ahora 3-6s
        time.sleep(random.uniform(3, 6))

        # 2. Lectura y Scroll (Más lento)
        print("    Leyendo (Scroll)...")
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight/3);")
        time.sleep(random.uniform(2, 5)) # Lee la parte de arriba

        driver.execute_script("window.scrollTo(0, document.body.scrollHeight/1.5);")
        time.sleep(random.uniform(2, 5)) # Lee la parte del medio

        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        time.sleep(random.uniform(2, 5)) # Lee el final

        # 3. Navegación Interna (Clic)
        elementos_a = driver.find_elements(By.TAG_NAME, "a")
        urls_encontradas = []
        for e in elementos_a:
            try:
                url = e.get_attribute("href")
                if url and dominio_base in url:
                    urls_encontradas.append(url)
            except:
                continue

        if urls_encontradas:
            # Solo hacemos clic el 70% de las veces (a veces el humano se va)
            if random.random() > 0.3:
                destino = random.choice(urls_encontradas)
                print(f"    Clic interno: {destino[:50]}...")
                try:
                    driver.get(destino)
                    # Tiempo de lectura del artículo interior (¡Largo!)
                    # 10 a 20 segundos de "silencio" DNS relativo
                    time.sleep(random.uniform(10, 20))
                except:
                    pass
            else:
                print("    (Usuario decide no hacer clic)")

        # 4. Pausa entre sitios (Cambiar de pestaña, ir al baño, etc.)
        # 5 a 15 segundos de silencio total antes de la siguiente web
        print("    Descansando...")
        time.sleep(random.uniform(5, 15))

    except Exception as e:
        print(f"[!] Error en bucle: {e}")
        time.sleep(5)
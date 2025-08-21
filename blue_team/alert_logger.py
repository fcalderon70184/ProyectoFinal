#!/usr/bin/env python3
import logging
import subprocess
import socket
from datetime import datetime
from time import time
""" Este script recibe alertas de IPs sospechosas desde el script sniffer_defense por medio de udp,
revisa si la IP ya está bloqueada o si está en la whitelist, y si corresponde, 
bloquea la IP en iptables y guarda el evento en el archivo eventos.log.
Tambien evita que se realizen bloqueos repetidos """


# Archivo de logs y configuraciones
LOG_FILE = "/home/Adminluis/blue_team/eventos.log"
WHITELIST = ["190.2.221.216"] 
PORT = 5050  # Puerto local UDP para recibir eventos del sniffer
ips_bloqueadas = set()
ultimo_evento = {} 

# Configuración de logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def registrar_evento(mensaje, nivel="info"):
    """
    Registra un evento en el log y lo imprime en la pantalla
    """
    if nivel == "info":
        logging.info(mensaje)
    elif nivel == "warning":
        logging.warning(mensaje)
    elif nivel == "error":
        logging.error(mensaje)

    print(f"[{datetime.now()}] {mensaje}")

def cargar_ips_bloqueadas():
    """
    Carga las IPs bloqueadas
    """
    try:
        resultado = subprocess.run(
            ["iptables", "-L", "INPUT", "-n"],
            capture_output=True,
            text=True
        )
        for linea in resultado.stdout.splitlines():
            partes = linea.split()
            if len(partes) >= 4 and partes[0] == "DROP":
                ips_bloqueadas.add(partes[3])
    except Exception as e:
        registrar_evento(f"Error al cargar IPs bloqueadas: {e}", "error")

def bloquear_ip(ip):
    """
    Bloquear una IP si no está en la whitelist y si no fue bloqueada recientemente.
    """
    if ip in WHITELIST:
        registrar_evento(f"IP {ip} está en whitelist, no se bloquea.")
        return

    ahora = time()
    # Evita que se registren varias veces la misma IP en menos de 60s
    if ip in ultimo_evento and ahora - ultimo_evento[ip] < 60:
        return
    ultimo_evento[ip] = ahora

    # Verifica si ya existe la regla en iptables
    existe = subprocess.run(
        ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True,
        text=True
    )
    if existe.returncode == 0:
        return

    # Agregar la regla en iptables
    resultado = subprocess.run(
        ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True,
        text=True
    )
    if resultado.returncode == 0:
        registrar_evento(f"IP bloqueada: {ip}", "warning")
        ips_bloqueadas.add(ip)
    else:
        registrar_evento(f"Error al bloquear {ip}: {resultado.stderr}", "error")

def iniciar_servidor():
    """
    Inicia el servidor UDP que escucha alertas del sniffer
    """
    cargar_ips_bloqueadas()
    registrar_evento("Alert Logger iniciado en tiempo real. Esperando eventos...")
    
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as servidor:
        servidor.bind(("127.0.0.1", PORT))
        while True:
            data, _ = servidor.recvfrom(1024)
            ip = data.decode().strip()
            if ip and ip.count(".") == 3:
                registrar_evento(f"Evento recibido: {ip}")
                bloquear_ip(ip)

if __name__ == "__main__":
    iniciar_servidor()

#!/usr/bin/env python3
"""Alert_logger"""
import logging
import subprocess
from datetime import datetime
from collections import Counter
import os
import re

LOG_FILE = "eventos.log"
DETECCION_LOG = "deteccion.log"
WHITELIST = ["190.2.221.216"]

"""
Configuración del logging
"""
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def registrar_evento(mensaje, nivel="info"):
    """
    Registrar evento con nivel e imprimir en consola
    """
    if nivel == "info":
        logging.info(mensaje)
    elif nivel == "warning":
        logging.warning(mensaje)
    elif nivel == "error":
        logging.error(mensaje)
    else:
        logging.debug(mensaje)

    print(f"[{datetime.now()}] Evento registrado: {mensaje}")

    # Notificación en consola
    try:
        os.system(f'echo "[ALERTA] {mensaje}" | wall')
    except Exception as e:
        print(f"ERROR No se pudo enviar la notificación: {e}")


def bloquear_ip(ip):
    """
    Bloquear IPs con iptables
    """
    if ip in WHITELIST:
        registrar_evento(f"La IP {ip} está en whitelist, no se bloquea.", nivel="info")
        return
    try:
        resultado = subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True,
            text=True
        )
        if resultado.returncode == 0:
            registrar_evento(f"IP bloqueada: {ip}", nivel="warning")
        else:
            registrar_evento(f"Error al bloquear IP {ip}: {resultado.stderr}", nivel="error")
    except Exception as e:
        registrar_evento(f"Excepción al bloquear IP {ip}: {str(e)}", nivel="error")


def analizar_logs_y_bloquear(log_file=DETECCION_LOG):
    """
    Analisis del log de detección y bloqueo de IPs con muchos eventos
    """
    try:
        with open(log_file, "r") as f:
            lineas = f.readlines()

        ips = []
        for linea in lineas:
            partes = linea.strip().split()
            for i, palabra in enumerate(partes):
                if palabra == "de" and i + 1 < len(partes):
                    ip = partes[i + 1]
                    if ip.count(".") == 3:
                        ips.append(ip)

        conteo = Counter(ips)

        for ip, cantidad in conteo.items():
            if cantidad >= 10:
                registrar_evento(f"La IP {ip} registro muchos eventos. Bloqueando...", nivel="warning")
                bloquear_ip(ip)

    except FileNotFoundError:
        registrar_evento(f"No se encontró el archivo {log_file}", nivel="error")
    except Exception as e:
        registrar_evento(f"Error al analizar logs: {e}", nivel="error")


if __name__ == "__main__":
    registrar_evento("Inicio del análisis de logs para detección de amenazas.")
    analizar_logs_y_bloquear()
    registrar_evento("Análisis de logs finalizado.")
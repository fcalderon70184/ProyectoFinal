#!/usr/bin/env python3
from scapy.all import IP, TCP, sniff
import logging, time, socket
from collections import defaultdict, deque

"""Este script analiza el tráfico TCP y detecta posibles ataques de SYN flood, ACK scan, conexiones a puertos sospechosos y
cuando detecta algo, lo registra en eventos.log y envía la IP sospechosa al alert_logger.py"""

# Configuración de seguridad
WHITELIST = ["190.2.221.216"] 
historial_SYN = defaultdict(lambda: deque(maxlen=20))  # Historial de tiempos de syn por ip
PUERTOS_SOSPECHOSOS = {31337, 4444, 6667}  # Puertos usados en ataques
LOGGER_PORT = 5050  # Puerto UDP del alert_logger

# Configuración de logs
logging.basicConfig(
    filename='/home/Adminluis/blue_team/eventos.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

def enviar_alerta(ip):
    """
    Envía una alerta al alert_logger 
    """
    if ip in WHITELIST:
        print(f"IP {ip} en whitelist, no se envía alerta")
        return
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(ip.encode(), ("127.0.0.1", LOGGER_PORT))
    print(f"[+] Alerta enviada al logger para IP {ip}")

def analisis_de_paquetes(paquete):
    """
    Analiza cada paquete TCP para ver patrones sospechosos
    """
    if paquete.haslayer(IP) and paquete.haslayer(TCP):
        ip_src = paquete[IP].src
        tcp_layer = paquete[TCP]
        flags = tcp_layer.flags
        port_src = tcp_layer.sport
        port_dst = tcp_layer.dport
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

        # Deteccion de SYN flood
        if flags & 0x02: 
            ahora = time.time()
            historial_SYN[ip_src].append(ahora)
            recientes = [t for t in historial_SYN[ip_src] if ahora - t < 5]
            if len(recientes) > 10:
                logging.warning(f"[{timestamp}] Posible SYN flood de {ip_src} ({len(recientes)} SYN en 5s)")
                enviar_alerta(ip_src)

        # Deteccion de ACK scan
        elif flags & 0x10:  
            logging.info(f"[{timestamp}] Posible ACK scan de {ip_src} puerto {port_src}")
            enviar_alerta(ip_src)

        # Conexión a puertos sospechosos
        if port_dst in PUERTOS_SOSPECHOSOS:
            logging.info(f"[{timestamp}] Tráfico sospechoso hacia puerto {port_dst} desde {ip_src}")
            enviar_alerta(ip_src)

if __name__ == "__main__":
    print("Iniciando detección de tráfico (sniffer)")
    sniff(filter="tcp", prn=analisis_de_paquetes) 

#!/usr/bin/env python3

from scapy.all import IP, TCP, sniff
import logging, time, subprocess

WHITELIST = ["190.2.221.216"]
contador_SYN = {}

logging.basicConfig(
    filename='deteccion.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

def bloquear_ip(ip):
    if ip in WHITELIST:
        print(f"IP {ip} en whitelist, no se bloquea")
        return
    print(f"Bloqueando ip: {ip}")
    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], stderr=subprocess.DEVNULL)

def analisis_de_paquetes(paquete):
    if paquete.haslayer(IP) and paquete.haslayer(TCP):
        ip_src = paquete[IP].src
        tcp_layer = paquete[TCP] 
        flags = tcp_layer.flags
        port_src = tcp_layer.sport
        port_dst = tcp_layer.dport
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

        if tcp_layer.flags == "S":
            contador_SYN[ip_src] = contador_SYN.get(ip_src, 0) + 1
            if contador_SYN[ip_src] > 10:
                logging.info(f"[{timestamp}] Posible SYN flood de {ip_src} puerto {port_src}")
                bloquear_ip(ip_src)

        elif flags == 'A':
            logging.info(f"[{timestamp}] Posible ACK scan de {ip_src} puerto {port_src}")

        if port_dst > 1024:
            logging.info(f"[{timestamp}] Tráfico hacia puerto inusual {port_dst} desde {ip_src}")
            
if __name__ == "__main__":
    print("Iniciando detección de tráfico")
    sniff(filter="tcp", prn=analisis_de_paquetes)       
            
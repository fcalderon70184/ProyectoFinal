# Proyecto Final de Ciberseguridad: "Red Team vs Blue Team en la Nube: Ataque y Defensa en Azure" 

## Propósito

Este proyecto simula un escenario de ciberseguridad en el que un equipo atacante (Red Team) ejecuta diferentes técnicas ofensivas contra una máquina, mientras que un equipo defensor (Blue Team) implementa medidas de detección, auditoría y protección.
El objetivo es aprender cómo se ven los ataques en la práctica, cómo defenderse y cómo registrar la actividad para su análisis.

---

## Roles de los equipos:
### Red Team:

Encargado de simular ataques: Todos los compañeros

packet_attack.py → Simulación de ataques de red:

- SYN Flood
- ARP Spoofing
- DNS Spoofing
- Sniffing HTTP

scanner.py → Escaneo de puertos y servicios con Nmap.

ssh_brute.py → Ataque de fuerza bruta a servidores SSH.

### Blue Team

Encargado de la defensa de la infraestructura: Luis Angel Cordero Granados

sniffer_defense.py → Detecta ataques como SYN flood, ACK scan y conexiones sospechosas.

alert_logger.py → Recibe alertas del sniffer, bloquea IPs con iptables y genera logs.

firewall_hardening.sh → Configura reglas de firewall UFW (HTTP, HTTPS, SSH).

os_audit.py → Auditoría de usuarios, servicios, puertos y configuraciones críticas.

---

## Requisitos

### Lenguajes y librerías:

- Python 3
- Scapy
- Nmap (y librería python-nmap)
- Paramiko

Herramientas en el sistema:

- iptables
- UFW (para firewall)
- ss, ps, crontab (para auditoría OS)

Entorno:

- Máquina virtual en Azure.

## Instrucciones de ejecución
### Red Team

packet_attack.py

python3 packet_attack.py


Selecciona el tipo de ataque desde el menú.

scanner.py

python3 scanner.py


Introduce la IP objetivo. Se genera un archivo de reporte con la fecha y hora.

ssh_brute.py

python3 ssh_brute.py


Requiere: IP de la víctima, usuario y diccionario de contraseñas.

### Blue Team

sniffer_defense.py

sudo python3 sniffer_defense.py


Detecta tráfico malicioso y envía IPs sospechosas al logger.

alert_logger.py

sudo python3 alert_logger.py


Bloquea automáticamente IPs sospechosas con iptables y guarda eventos.

firewall_hardening.sh

sudo bash firewall_hardening.sh


Configura el firewall con reglas seguras.

os_audit.py

sudo python3 os_audit.py


Genera un reporte de auditoría del sistema en /home/Adminluis/blue_team/os_audit_report.log.

---

### Evaluación del éxito

Ataques exitosos (Red Team):

- Acceso no autorizado a SSH.
- Manipulación de tráfico (ARP/DNS spoofing).
- Saturación de recursos con SYN flood.
- Descubrimiento de servicios vulnerables.

### Defensas efectivas (Blue Team):

- Bloqueo automático de IPs sospechosas.
- Detección y registro de ataques en eventos.log.
- Configuración de firewall limitando accesos.
- Auditoría de configuraciones y servicios inseguros.

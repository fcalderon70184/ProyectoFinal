# Reporte de Ataques – Red Team

## Objetivo del ataque
El propósito del Red Team fue evaluar la seguridad de la máquina virtual del Blue Team desplegada en Azure. Para ello se implementaron diferentes técnicas ofensivas con scripts desarrollados en Python, con el fin de detectar debilidades, probar accesos no autorizados y simular ataques de red que pudieran comprometer la disponibilidad o confidencialidad de los servicios.

---

## Metodología empleada

### 1. Escaneo de servicios (`scanner.py`)
- Se ejecutó un escaneo con **Nmap automatizado desde Python**.  
- **Objetivo:** identificar puertos abiertos y servicios activos en la VM del Blue Team.  
- **Resultado:**  
  - Puerto **22 (SSH)** Abierto - Open SSH 8.9p1 Ubuntu 3ubuntu0.13.
  - Puerto **53 (DNS)** Filtrado.
  - Puerto **80 (HTTP)** Filtrado.
  - Puerto **443 (HTTPS)** Filtrado.
  - Puerto **8080 (HTTP-Proxy)** Filtrado

### 2. Ataque de diccionario SSH (`ssh_brute.py`)
- Se realizó un ataque de **fuerza bruta** sobre el servicio SSH utilizando un diccionario de contraseñas débiles.  
- **Resultado:**  
  - Se encontró una contraseña válida en pruebas iniciales *Blueteam5484*.  
  - Esto demuestra la importancia de **políticas de contraseñas seguras** y el uso de **Fail2Ban** u otros mecanismos de protección.  

### 3. Simulación de ataques de red (`packet_attack.py`)
Se desarrolló un script en **Scapy** con distintas opciones de ataque:

- **SYN Flood:** saturación de peticiones TCP para afectar la disponibilidad del servicio.  
- **ARP Spoofing:** intento de manipular el tráfico local redirigiendo paquetes.  
- **DNS Spoofing:** responder consultas DNS con direcciones falsas.  
- **Sniffing HTTP:** captura de tráfico en claro para identificar contraseñas o cookies.  

**Principal demostración:**  
El **SYN Flood** generó tráfico masivo que fue registrado por los sistemas de defensa.

---

## Evidencia
- **Logs generados por el Blue Team** (`alert_logger.py` y `sniffer_defense.py`):
  - Detección de múltiples paquetes **SYN sospechosos**.  
  - Registro de **intentos fallidos de acceso SSH**.  
- **Consola del Red Team**:
  - Confirmación de paquetes enviados.  
  - Detección de **tráfico sensible HTTP** en pruebas de sniffing.  

---

## Reflexión sobre la eficacia del Blue Team
- El Blue Team implementó **reglas de firewall** y mecanismos de **detección de tráfico anómalo**.  
- Durante los ataques:  
  - Los intentos de fuerza bruta fueron **detectados y bloqueados** tras varios intentos.  
  - El **sniffer defensivo** identificó patrones de escaneo y SYN Flood.  
- Esto demuestra que los mecanismos defensivos fueron **efectivos para registrar y alertar** sobre los ataques.  
- **Debilidad identificada:** si las contraseñas son débiles, el acceso inicial puede lograrse, reforzando la necesidad de una **política estricta de credenciales**.  

---

## Recomendaciones de mejora

### 1. Políticas de contraseñas más estrictas
- Evitar credenciales por defecto o comunes.  
- Implementar **autenticación multifactor (MFA)** en SSH.  

### 2. Fortalecimiento del firewall
- Reglas de **rate-limiting** para SSH y HTTP.  
- Monitorear **conexiones concurrentes sospechosas**.  

### 3. Mayor visibilidad en logs
- **Centralizar alertas y registros** para facilitar el análisis.  
- Automatizar **notificaciones inmediatas** al administrador.  

### 4. Uso de cifrado en todo el tráfico
- Deshabilitar **HTTP** y migrar completamente a **HTTPS**.  
- Evitar sniffing exitoso en tráfico en claro.  

---

## ✅ Conclusión
El propósito del Red Team fue evaluar la seguridad de la máquina virtual del Blue Team desplegada en Azure. Para ello se implementaron diferentes técnicas ofensivas con scripts desarrollados en Python, con el fin de detectar debilidades, probar accesos no autorizados y simular ataques de red que pudieran comprometer la disponibilidad o confidencialidad de los servicios.

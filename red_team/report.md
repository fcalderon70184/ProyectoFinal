# Reporte Red Team

## Objetivo
Evaluar la exposición de la VM de Azure (Ubuntu 22.04 LTS) y evidenciar cómo responden las defensas del Blue Team.

## Metodología
1. Escaneo con `scanner.py` (Nmap: -sS -sV -Pn -T4).
2. Fuerza bruta controlada con `ssh_brute.py` (delays y límite de intentos).
3. ARP spoof (si aplica misma red) y SYN demo con `packet_attack.py`.

## Evidencia
- CSVs en `reportes/` con resultados de Nmap.
- Logs en `logs/` de fuerza bruta y detección/bloqueo.

## Hallazgos
- Puertos expuestos:
- Versiones de servicios:
- Respuesta de defensa (detecciones y bloqueos):

## Recomendaciones
- Reducir superficie de ataque (NSG/UFW).
- Políticas de contraseñas y autenticación por claves.
- Monitoreo continuo y alertas proactivas.

#!/bin/bash
"""Este script aplica una configuración básica de firewall con UFW que verifica si UFW está instalado y lo instala si es necesario
restablece reglas y establece políticas, tambien habilita puertos esenciales HTTP, HTTPS y limita los intentos SSH
y por ultimo activa el firewall"""

# Configuración básica de firewall con UFW para proteger una VM en Azure
# Descripción: Este script aplica reglas de firewall para limitar la superficie de ataque
set -euo pipefail

# Función para mostrar mensajes en pantalla
log() { echo "[INFO] $*"; }


# Verifica si UFW está instalado
if ! command -v ufw >/dev/null 2>&1; then
  log "Instalando UFW..."
  sudo apt-get update -y
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ufw
else
  log "UFW ya está instalado."
fi

# Establece las políticas por defecto
log "Reseteando reglas y aplicando políticas por defecto..."
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Permitir puertos esenciales
log "Permitendo HTTP/HTTPS y limitando SSH..."
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw limit 22/tcp

# Habilita el firewall
log "Activando UFW con las reglas definidas..."
sudo ufw --force enable

# Muestra el estado final del firewall
log "Estado final de UFW:"
sudo ufw status verbose
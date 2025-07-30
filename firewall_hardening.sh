#!/bin/bash

# firewall_hardening.sh
# Configuración básica de firewall con UFW para proteger una VM en Azure
# Autor: Francisco Calderón
# Descripción: Este script aplica reglas de firewall para limitar la superficie de ataque.

# Función para mostrar mensajes en pantalla
mostrar_mensaje() {
    echo "[INFO] $1"
}

# Verifica si UFW está instalado
if ! command -v ufw > /dev/null; then
    mostrar_mensaje "UFW no está instalado. Instalando..."
    sudo apt update && sudo apt install -y ufw
else
    mostrar_mensaje "UFW ya está instalado."
fi

# Deshabilita UFW antes de aplicar reglas nuevas
sudo ufw disable

# Establece las políticas por defecto
mostrar_mensaje "Estableciendo políticas por defecto..."
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Permitir puertos esenciales
mostrar_mensaje "Permitendo tráfico SSH (puerto 22)..."
sudo ufw allow 22/tcp

mostrar_mensaje "Permitendo tráfico HTTP (puerto 80)..."
sudo ufw allow 80/tcp

mostrar_mensaje "Permitendo tráfico HTTPS (puerto 443)..."
sudo ufw allow 443/tcp

# (Opcional) Limitar intentos al puerto SSH para evitar fuerza bruta
mostrar_mensaje "Aplicando limitación de conexiones SSH..."
sudo ufw limit 22/tcp

# Habilita el firewall
mostrar_mensaje "Activando UFW con las reglas definidas..."
sudo ufw enable

# Muestra el estado final del firewall
mostrar_mensaje "Estado del firewall:"
sudo ufw status verbose
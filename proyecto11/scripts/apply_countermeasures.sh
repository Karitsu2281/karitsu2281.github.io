#!/bin/bash
# Contramedidas para mitigar ataques detectados por Infection Monkey
# Proyecto 11 - Aplicar despues de la primera simulacion

set -e

echo "=============================================="
echo " Aplicando Contramedidas de Mitigacion"
echo " Proyecto 11 - Emulacion de Adversarios"
echo "=============================================="

FIREWALL="${1:-firewall}"
VICTIM="${2:-victim-1}"

BLOCK_IPS=(
  "192.168.100.20"
)

BLOCK_PORTS=(
  "22"
  "445"
  "135"
  "3389"
)

echo "[*] Aplicando contramedidas en el firewall..."

# 1. Bloquear IPs maliciosas
for ip in "${BLOCK_IPS[@]}"; do
  echo "  [+] Bloqueando IP: ${ip}"
  docker exec "${FIREWALL}" iptables -I INPUT 1 -s "${ip}" -j DROP
done

# 2. Limitar SSH a solo IPs autorizadas
echo "  [+] Restringiendo SSH a red interna unicamente"
docker exec "${FIREWALL}" iptables -D INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || true
docker exec "${FIREWALL}" iptables -I INPUT -p tcp --dport 22 -s 10.0.0.0/24 -j ACCEPT
docker exec "${FIREWALL}" iptables -A INPUT -p tcp --dport 22 -j DROP

# 3. Aplicar rate limiting mas agresivo
echo "  [+] Aplicando rate limiting agresivo en SSH"
docker exec "${FIREWALL}" iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
docker exec "${FIREWALL}" iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 120 --hitcount 3 -j DROP

# 4. Bloquear puertos SMB/RPC comunes en ataques de propagacion
echo "  [+] Bloqueando puertos de propagacion lateral"
for port in 135 139 445 3389 5985 5986; do
  docker exec "${FIREWALL}" iptables -A INPUT -p tcp --dport ${port} -j DROP
done

# 5. Guardar reglas persistentes
echo "  [+] Guardando reglas persistentes (sobreviven reinicio)"
docker exec "${FIREWALL}" bash -c 'iptables-save > /etc/iptables/rules.v4'

echo ""
echo "[*] Aplicando medidas de hardening adicionales en victimas..."

# 6. Deshabilitar password authentication via SSH
for victim in victim-1 victim-2; do
  echo "  [+] Hardening SSH en ${victim}"
  docker exec "${victim}" sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
  docker exec "${victim}" sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
  docker exec "${victim}" service ssh restart
done

# 7. Aplicar fail2ban en victimas
for victim in victim-1 victim-2; do
  echo "  [+] Configurando fail2ban en ${victim}"
  docker exec "${victim}" bash -c 'cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = 22
logpath = /var/log/auth.log
maxretry = 3
EOF'
  docker exec "${victim}" service fail2ban restart 2>/dev/null || true
done

# 8. Deshabilitar servicios de red innecesarios
for victim in victim-1 victim-2; do
  echo "  [+] Deshabilitando servicios innecesarios en ${victim}"
  docker exec "${victim}" service telnet stop 2>/dev/null || true
  docker exec "${victim}" service ftp stop 2>/dev/null || true
done

echo ""
echo "=============================================="
echo " Contramedidas aplicadas correctamente"
echo "=============================================="
echo ""

echo "[*] Verificando contramedidas..."
echo ""
echo "--- Reglas de iptables activas ---"
docker exec "${FIREWALL}" iptables -L INPUT -n -v --line-numbers 2>/dev/null | head -30
echo ""
echo "--- Estado de fail2ban ---"
for victim in victim-1 victim-2; do
  echo "  [${victim}]"
  docker exec "${victim}" fail2ban-client status sshd 2>/dev/null || echo "    fail2ban no disponible en Docker (esperado)"
done
echo ""
echo "--- Verificacion SSH ---"
for victim in victim-1 victim-2; do
  echo "  [${victim}] PermitRootLogin: $(docker exec ${victim} grep '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null)"
  echo "  [${victim}] PasswordAuth: $(docker exec ${victim} grep '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null)"
done
echo ""
echo "=============================================="
echo " VERIFICACION COMPLETADA"
echo "=============================================="
echo ""
echo "Resumen de medidas implementadas:"
echo "  1. Bloqueo de IPs maliciosas (Monkey Island)"
echo "  2. Restriccion de SSH a red interna (10.0.0.0/24)"
echo "  3. Rate limiting agresivo (3 intentos/120s)"
echo "  4. Bloqueo de puertos de propagacion lateral (135,139,445,3389,5985,5986)"
echo "  5. Deshabilitada autenticacion por password en SSH"
echo "  6. Deshabilitado acceso root via SSH"
echo "  7. Configurado fail2ban (baneo 1h tras 3 fallos)"
echo "  8. Servicios inseguros deshabilitados"
echo ""
echo "[!] Ahora vuelve a ejecutar Infection Monkey para verificar la efectividad."
echo "[!] Compara los logs en Kibana: http://localhost:5601"

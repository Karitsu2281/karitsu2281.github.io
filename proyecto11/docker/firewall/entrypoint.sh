#!/bin/bash

echo "[*] Iniciando Firewall + Suricata IDS (Proyecto 11)"

# Docker already applies sysctls from docker-compose
# Verificar forwarding
if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]; then
    sysctl -w net.ipv4.ip_forward=1 2>/dev/null || echo "  [!] No se pudo habilitar ip_forward (ya gestionado por Docker)"
fi

if [ -s /etc/iptables/rules.v4 ]; then
    echo "  [+] Restaurando reglas de iptables persistentes..."
    iptables-restore < /etc/iptables/rules.v4
else
    echo "  [+] Creando reglas base de iptables..."
    iptables -F
    iptables -t nat -F
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
    iptables -A INPUT -j LOG --log-prefix "FW-INPUT-DROP: " --log-level 4
    iptables -A FORWARD -j LOG --log-prefix "FW-FORWARD-DROP: " --log-level 4
    iptables-save > /etc/iptables/rules.v4
fi

cat > /etc/rsyslog.d/50-elk.conf << 'EOF'
*.* @logstash:5515
EOF

service rsyslog start 2>/dev/null || rsyslogd 2>/dev/null || echo "  [!] rsyslog no pudo iniciarse (logs locales no disponibles)"
echo "  [+] rsyslog iniciado"

suricata -c /etc/suricata/suricata.yaml -i "${SURICATA_IFACE:-eth1}" -D
echo "  [+] Suricata IDS corriendo en ${SURICATA_IFACE:-eth1}"

echo "  [+] Verificando reglas de Suricata..."
sleep 3
RULES_COUNT=$(grep -c 'sid:' /var/lib/suricata/rules/suricata.rules 2>/dev/null || echo 0)
CUSTOM_COUNT=$(grep -c 'PROYECTO11' /var/lib/suricata/rules/custom.rules 2>/dev/null || echo 0)
echo "      Reglas oficiales cargadas: ${RULES_COUNT}"
echo "      Reglas personalizadas cargadas: ${CUSTOM_COUNT}"

/opt/filebeat/filebeat -e -c /etc/filebeat/filebeat.yml &
echo "  [+] Filebeat iniciado (eve.json -> Logstash:5044)"

echo ""
echo "=============================================="
echo " Firewall operativo"
echo "   Interfaz externa: eth0 (192.168.100.0/24)"
echo "   Interfaz interna: eth1 (10.0.0.0/24)"
echo "   Suricata IDS: ${SURICATA_IFACE:-eth1}"
echo "   Logs -> Logstash:5515 (syslog) + :5044 (filebeat)"
echo "=============================================="

tail -f /var/log/suricata/fast.log /var/log/syslog 2>/dev/null &
wait

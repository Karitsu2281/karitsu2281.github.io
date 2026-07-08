Write-Host "=============================================="
Write-Host " Aplicando Contramedidas de Mitigacion"
Write-Host " Proyecto 11 - Emulacion de Adversarios (Windows)"
Write-Host "=============================================="

$FIREWALL = "firewall"
$VICTIMS = @("victim-1", "victim-2")
$BLOCK_IPS = @("10.0.0.50")
$PORTS = @("135", "139", "445", "3389", "5985", "5986")

Write-Host "[*] Aplicando contramedidas de red (iptables) en las victimas..."

foreach ($victim in $VICTIMS) {
    Write-Host "--- Configuracion de red para $victim ---"
    
    # 1. Bloquear IPs maliciosas
    foreach ($ip in $BLOCK_IPS) {
        Write-Host "  [+] Bloqueando IP: $ip"
        docker exec $victim iptables -I INPUT 1 -s $ip -j DROP
    }

    # 2. Limitar SSH a solo IPs autorizadas
    Write-Host "  [+] Restringiendo SSH"
    docker exec $victim iptables -D INPUT -p tcp --dport 22 -j ACCEPT 2>$null
    docker exec $victim iptables -I INPUT -p tcp --dport 22 -s 10.0.0.0/24 -j ACCEPT
    
    # 3. Aplicar rate limiting mas agresivo
    Write-Host "  [+] Aplicando rate limiting agresivo en SSH"
    docker exec $victim iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
    docker exec $victim iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 120 --hitcount 3 -j DROP

    # 4. Bloquear puertos de propagacion lateral
    Write-Host "  [+] Bloqueando puertos de propagacion lateral"
    foreach ($port in $PORTS) {
        docker exec $victim iptables -A INPUT -p tcp --dport $port -j DROP
    }
}

Write-Host "`n[*] Aplicando medidas de hardening adicionales en victimas..."

foreach ($victim in $VICTIMS) {
    Write-Host "  [+] Hardening SSH en $victim"
    docker exec $victim sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    docker exec $victim sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    docker exec $victim service ssh restart
}

foreach ($victim in $VICTIMS) {
    Write-Host "  [+] Configurando fail2ban en $victim"
    $fail2banConfig = @"
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = 22
logpath = /var/log/auth.log
maxretry = 3
"@
    docker exec $victim bash -c "echo `"$fail2banConfig`" > /etc/fail2ban/jail.local"
    docker exec $victim service fail2ban restart 2>$null
}

foreach ($victim in $VICTIMS) {
    Write-Host "  [+] Deshabilitando servicios innecesarios en $victim"
    docker exec $victim service telnet stop 2>$null
    docker exec $victim service ftp stop 2>$null
}

Write-Host "`n=============================================="
Write-Host " Contramedidas aplicadas correctamente"
Write-Host "=============================================="
Write-Host "`n[!] Ahora vuelve a ejecutar Infection Monkey para verificar la efectividad."
Write-Host "[!] Compara los logs en Kibana: http://localhost:5601"

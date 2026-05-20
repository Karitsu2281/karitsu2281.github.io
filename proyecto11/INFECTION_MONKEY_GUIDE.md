# Guia de Infection Monkey - Proyecto 11

## Comportamientos esperados y artefactos en logs

Cuando ejecutes Infection Monkey contra las victimas, la herramienta realizara automaticamente estos comportamientos.
Cada uno deja trazas especificas en los logs que debes capturar para tu presentacion.

---

## Tabla de comportamientos, deteccion y contramedidas

| # | Comportamiento | Fase MITRE | Artefacto en logs | Query Kibana | Contramedida |
|---|---|---|---|---|---|
| **1** | Escaneo de puertos (network scan) | Discovery (T1046) | Múltiples paquetes SYN a distintos puertos en corto tiempo. Firewall logs con `FW-INPUT-DROP` para puertos cerrados. Suricata SID 1000003, 1000004. | `tags: firewall_drop` + aggregar por `src_ip` | Rate limiting iptables, cerrar puertos innecesarios |
| **2** | Fuerza bruta SSH (brute force) | Credential Access (T1110.001) | `/var/log/auth.log`: `Failed password for root from X.X.X.X`. Logstash tag: `ssh_failed_attempt`, `MITRE_T1110.001`. Suricata SID 1000001 | `tags: ssh_failed_attempt` + histograma temporal | fail2ban, clave SSH obligatoria, MaxAuthTries=3 |
| **3** | Login SSH exitoso (si la fuerza bruta tiene exito) | Initial Access (T1078) | `/var/log/auth.log`: `Accepted password for root from X.X.X.X`. Tag: `ssh_login_success` | `tags: ssh_login_success` | Deshabilitar PasswordAuthentication, deshabilitar root login |
| **4** | Propagacion lateral via SMB (Lateral Movement) | Lateral Movement (T1021.002) | Conexiones al puerto 445 entre victimas. Suricata SID 1000005 (MS17-010), 1000006 (SMB anonimo), 1000013 (PsExec). Tag: `lateral_movement`, `suricata_smb_log` | `tags: smb_attack` OR `tags: lateral_movement` | Bloquear puertos 135,139,445 en firewall, deshabilitar SMBv1 |
| **5** | Propagacion via WMI/RPC | Lateral Movement (T1047) | Conexiones al puerto 135. Suricata SID 1000012 | `tags: smb_attack` + filtrar por puerto 135 | Bloquear puerto 135, restringir DCOM |
| **6** | Ejecucion de comandos remotos (exploitation) | Execution (T1203) | Auditd registra `execve` syscalls. Suricata SID 1000014. Logs de procesos inusuales. | `tags: auditd_event` | Restringir sudo, deshabilitar servicios innecesarios |
| **7** | Comunicacion C2 (beaconing al Monkey Island) | Command and Control (T1071.001) | Conexiones HTTP/HTTPS periodicas a `192.168.100.20:5000`. Suricata SID 1000015. User-Agent sospechoso SID 1000010 | `tags: suricata_alert` AND `alert_sid: 1000015` | Bloquear IP del Monkey Island en firewall, filtrado egress |
| **8** | Dumpeo de credenciales (/etc/shadow, /etc/passwd) | Credential Access (T1003.008) | Auditd: `-w /etc/shadow -p wa -k identity`. Suricata SID 1000020 (exfiltracion) | `tags: auditd_event` + filtrar path=`/etc/shadow` | Permisos restrictivos en /etc/shadow (0600), auditd activo |
| **9** | Persistencia (modificar cron, SSH authorized_keys) | Persistence (T1543.003) | Auditd registra escritura en cron/authorized_keys. Procesos nuevos inusuales. | `tags: auditd_event` + path=`/etc/cron*` | cron.allow restringido, monitorizar authorized_keys |
| **10** | Escaneo web (HTTP fuzzing) | Discovery (T1592) | `/var/log/nginx/access.log`: multiples peticiones 404/403. Suricata SID 1000008 (SQLi), 1000009 (path traversal) | `tags: suricata_http_log` | WAF, deshabilitar directory listing, limitar rate HTTP |

---

## Configuracion recomendada de Infection Monkey

1. Accede a `https://localhost:5000` (acepta el certificado autofirmado)
2. Ve a **Configuration** (icono del engranaje)
3. Configura:
   - **Network scan**: Habilita `Ping sweep`, `TCP scan` (puertos 1-1000, 3306, 3389, 445, 135, 5000, 8080)
   - **Exploits**: Habilita `SSH Exploiter`, `SMB Exploiter`, `WMI Exploiter`, `PowerShell Exploiter`
   - **Propagation**: `maximum_depth = 2`
   - **Post-breach actions**: Habilita `Backdoor user`, `Modify shell startup`, `Scheduled tasks`
4. Ve a **Run Monkey** y selecciona los agentes
5. Despliega via SSH a las victimas:
   - victim-1: `10.0.0.10`, usuario `root`, password `toor`
   - victim-2: `10.0.0.11`, usuario `root`, password `toor`

---

## Queries avanzadas de Elasticsearch para el analisis

### Query 1: Correlacion fuerza bruta + login exitoso (compromiso de credenciales)
```
POST proyecto11-logs-*/_search
{
  "query": {
    "bool": {
      "must": [
        {"term": {"tags": "ssh_failed_attempt"}},
        {"range": {"@timestamp": {"gte": "now-15m"}}}
      ]
    }
  },
  "aggs": {
    "attacker_ips": {
      "terms": {"field": "src_ip.keyword", "size": 10},
      "aggs": {
        "failed_count": {"value_count": {"field": "src_ip.keyword"}},
        "successful_login": {
          "filter": {"term": {"tags": "ssh_login_success"}}
        }
      }
    }
  }
}
```

### Query 2: Deteccion de anomalias (significant terms)
```
POST proyecto11-logs-*/_search
{
  "query": {"match_all": {}},
  "aggs": {
    "anomalous_src_ips": {
      "significant_terms": {"field": "src_ip.keyword", "size": 20}
    }
  }
}
```

### Query 3: Timeline de ataque completo
Filtra en Kibana Discover con: `tags:(firewall_drop OR ssh_failed_attempt OR suricata_alert OR ssh_login_success)` y visualiza el histograma temporal.

### Query 4: Suricata alerts agrupadas por severidad y firma
```
POST proyecto11-logs-*/_search
{
  "size": 0,
  "query": {"term": {"tags": "suricata_alert"}},
  "aggs": {
    "by_severity": {
      "terms": {"field": "alert_severity.keyword", "size": 5},
      "aggs": {
        "top_signatures": {
          "terms": {"field": "alert_signature.keyword", "size": 10}
        }
      }
    }
  }
}
```

---

## Comandos utiles durante la simulacion

```bash
# Ver en tiempo real los intentos de fuerza bruta
docker exec victim-1 tail -f /var/log/auth.log | grep "Failed password"

# Ver en tiempo real las alertas de Suricata
docker exec firewall tail -f /var/log/suricata/fast.log

# Ver paquetes bloqueados por el firewall
docker exec firewall tail -f /var/log/kern.log | grep "FW-"

# Ver conexiones activas en el firewall
docker exec firewall netstat -antp

# Ver eventos de auditd
docker exec victim-1 tail -f /var/log/audit/audit.log

# Contar intentos de fuerza bruta por IP
docker exec victim-1 grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn
```

author: Hugo Flores
summary: Informe final del Proyecto 11 — Emulación de adversarios con Infection Monkey, monitorización con ELK y bastionado de infraestructura.
id: 11
categories: codelab,markdown
environments: Web
status: Published
feedback link: https://github.com/karitsu2281/karitsu2281.github.io/issues
analytics account: ID de Google Analytics

# Proyecto 11 — Informe Final: Emulación de Adversarios, Monitorización y Bastionado

---

## 1. Arquitectura del Laboratorio

La infraestructura se despliega completamente en Docker con 8 contenedores:

```
┌─────────────────────────────────────────────────────────────────────┐
│                         DOCKER HOST                                 │
│  ┌───────────────────┐          ┌──────────────────────────────┐   │
│  │ Infection Monkey  │          │        ELK STACK             │   │
│  │ Island (C2)       │          │ - Elasticsearch :9200        │   │
│  │ :5000             │          │ - Kibana        :5601        │   │
│  └────────┬──────────┘          └───────────────┬──────────────┘   │
│           │                                     │                  │
│  ┌────────▼─────────────────────────────────────▼──────────────┐  │
│  │           Red Externa (192.168.100.0/24)                     │  │
│  └───────────────────────────────┬──────────────────────────────┘  │
│                                  │                                 │
│  ┌───────────────────────────────▼──────────────────────────────┐  │
│  │     FIREWALL (iptables + Suricata)                           │  │
│  │     - Ext: 192.168.100.10  - Int: 10.0.0.2                  │  │
│  │     - Políticas: INPUT DROP, FORWARD DROP                    │  │
│  └───────────────────────────────┬──────────────────────────────┘  │
│                                  │                                 │
│  ┌───────────────────────────────▼──────────────────────────────┐  │
│  │           Red Interna (10.0.0.0/24)                           │  │
│  │                                                               │  │
│  │   victim-1 (Web)           victim-2 (BD)                      │  │
│  │   10.0.0.10                10.0.0.11                          │  │
│  │   SSH:22 | Nginx:80        SSH:22 | MySQL:3306               │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### Contenedores y servicios

```bash
$ docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```
```
NAMES           STATUS              PORTS
monkey_island   Up                  :5000
monkey_mongo    Up
firewall        Up
logstash        Up                  :5044, :5515
kibana          Up                  :5601
elasticsearch   Up                  :9200
victim-1        Up                  22/tcp, 80/tcp, 3306/tcp
victim-2        Up                  22/tcp, 80/tcp, 3306/tcp
```

### Reglas iniciales del firewall

El firewall se inicializa con política DROP en INPUT y FORWARD:

```bash
$ docker exec firewall iptables -L -n -v --line-numbers
```
```
Chain INPUT (policy DROP)
num   pkts bytes target     prot opt in     out     source     destination
1      138 10316 ACCEPT     all  --  lo     *       0.0.0.0/0  0.0.0.0/0
2        0     0 ACCEPT     all  --  *      *       0.0.0.0/0  0.0.0.0/0  ctstate RELATED,ESTABLISHED
3        2   168 LOG        all  --  *      *       0.0.0.0/0  0.0.0.0/0  prefix "FW-INPUT-DROP: "

Chain FORWARD (policy DROP)
num   pkts bytes target     prot opt in     out     source     destination
1        0     0 ACCEPT     all  --  *      *       0.0.0.0/0  0.0.0.0/0  ctstate RELATED,ESTABLISHED
2        0     0 ACCEPT     all  --  eth1   eth0    0.0.0.0/0  0.0.0.0/0
3        0     0 LOG        all  --  *      *       0.0.0.0/0  0.0.0.0/0  prefix "FW-FORWARD-DROP: "
```

---

## 2. Configuración y Lanzamiento del Ataque

Configuramos Infection Monkey para escanear la red interna `10.0.0.0/24` con los siguientes parámetros:

- **Server IP**: `10.0.0.1` (Gateway interno Docker)
- **Network Scan**: Ping sweep + TCP scan activados
- **Puertos**: `22, 80, 135, 139, 443, 445, 3306, 5000, 8080`
- **Exploits**: SSH Exploiter, SMB Exploiter, WMI Exploiter
- **Post-Breach**: Recolección de credenciales, persistencia

![Configuración de subred en Infection Monkey](img/dsdsd.png)
*Figura 1: Configuración del escaneo de red en Infection Monkey apuntando a 10.0.0.0/24.*

### Generación del payload

Desde la interfaz "Run Monkey", generamos el payload malicioso de despliegue manual para sistemas Linux.

![Generación del Payload](img/sdadas.png)
*Figura 2: Interfaz de Infection Monkey generando el comando curl para la inyección manual del agente.*

### Inyección en víctimas

Inyectamos el malware en las víctimas usando las credenciales por defecto `root`/`toor`:

- **victim-1** (10.0.0.10) — Servidor Web
- **victim-2** (10.0.0.11) — Servidor Base de Datos

![Inyección Exitosa en Victim-1](img/ksakaskas.png)
*Figura 3: Ejecución y despliegue exitoso del agente malicioso en victim-1.*

![Inyección Exitosa en Victim-2](img/dadssd.png)
*Figura 4: Ejecución y despliegue exitoso del agente malicioso en victim-2.*

Ambos agentes se descargaron, instalaron y establecieron comunicación con la isla de comando y control (C2), demostrando la vulnerabilidad de una red sin bastionar.

---

## 3. Monitorización y Análisis de Logs en Kibana

Mientras los ataques se ejecutaban, toda la actividad de red era registrada por el firewall y enviada al stack ELK (Logstash → Elasticsearch → Kibana).

### Configuración del Data View

1. Acceder a `http://localhost:5601`
2. Management → Stack Management → Data Views
3. Crear data view: `proyecto11-logs-*` con campo temporal `@timestamp`

### Visualización en Discover

![Visualización en Kibana](img/saasasa.png)
*Figura 5: Interfaz Discover de Kibana mostrando los logs de sistema en tiempo real.*

### Queries de detección

| Query Tag | Qué detecta | Evidencia |
|---|---|---|
| `tags: firewall_drop` | Escaneo de puertos bloqueados por iptables | IPs atacantes y puertos destino |
| `tags: ssh_failed_attempt` | Fuerza bruta SSH (miles de intentos) | Múltiples fallos para usuario `root` |
| `tags: ssh_login_success` | Compromiso exitoso vía SSH | `Accepted password for root` |
| `tags: suricata_alert` | Alertas del IDS Suricata | Firmas de escaneo y exploits |

---

## 4. Bastionado y Contramedidas

### Ejecución del script de hardening

Aplicamos el script `apply_countermeasures.sh` que implementa múltiples capas de defensa:

![Script de Hardening](img/script_hardening.png)
*Figura 6: Ejecución del script de contramedidas.*

### Reglas iptables aplicadas

```bash
$ docker exec victim-1 iptables -L INPUT -n -v --line-numbers
```
```
Chain INPUT (policy ACCEPT)
num   pkts bytes target     prot opt in     out     source     destination
1        0     0 DROP       tcp  --  *      *       0.0.0.0/0  0.0.0.0/0  tcp dpt:22 state NEW recent: UPDATE seconds: 120 hit_count: 3
2        0     0            tcp  --  *      *       0.0.0.0/0  0.0.0.0/0  tcp dpt:22 state NEW recent: SET
3        0     0 ACCEPT     tcp  --  *      *       10.0.0.0/24 0.0.0.0/0 tcp dpt:22
4        0     0 DROP       all  --  *      *       10.0.0.50  0.0.0.0/0
5        0     0 DROP       tcp  --  *      *       0.0.0.0/0  0.0.0.0/0  tcp dpt:135
6        0     0 DROP       tcp  --  *      *       0.0.0.0/0  0.0.0.0/0  tcp dpt:139
7        0     0 DROP       tcp  --  *      *       0.0.0.0/0  0.0.0.0/0  tcp dpt:445
8        0     0 DROP       tcp  --  *      *       0.0.0.0/0  0.0.0.0/0  tcp dpt:3389
9        0     0 DROP       tcp  --  *      *       0.0.0.0/0  0.0.0.0/0  tcp dpt:5985
10       0     0 DROP       tcp  --  *      *       0.0.0.0/0  0.0.0.0/0  tcp dpt:5986
```

### Medidas implementadas

1. **Bloqueo de IP maliciosa** — IP de Monkey Island (`10.0.0.50`) bloqueada en INPUT
2. **Rate limiting SSH** — Máximo 3 intentos cada 120 segundos
3. **Restricción de SSH a red interna** — Solo tráfico desde `10.0.0.0/24`
4. **Bloqueo de puertos de propagación** — 135 (RPC), 139 (NetBIOS), 445 (SMB), 3389 (RDP), 5985/5986 (WinRM)
5. **Hardening SSH** — `PermitRootLogin no`, `PasswordAuthentication no`
6. **Fail2ban** — Baneo de 1 hora tras 3 intentos fallidos en 10 minutos

### Verificación SSH

```bash
$ docker exec victim-1 grep -E '^(PermitRootLogin|PasswordAuthentication)' /etc/ssh/sshd_config
```
```
PermitRootLogin no
PasswordAuthentication no
```

---

## 5. Auditoría con InSpec

Para certificar el bastionado, ejecutamos el perfil de Chef InSpec contra las víctimas.

### Controles verificados

| ID | Descripción | Estado |
|---|---|---|
| ssh-01 | Puerto SSH 22 abierto y protocolo seguro | ✔ |
| ssh-02 | Login root deshabilitado (`PermitRootLogin no`) | ✔ |
| ssh-03 | Autenticación por contraseña deshabilitada | ✔ |
| fw-01 | iptables operativo | ✔ |
| fw-02 | Puertos de propagación bloqueados (445, 135) | ✔ |
| svc-01 | Permisos `/etc/shadow` en 0600 | ✔ |
| svc-02 | Servicios inseguros deshabilitados (telnet, ftp) | ✔ |

### Resultados Victim-1

![InSpec Victim-1](img/test_inspec_victim1.png)
*Figura 7: Auditoría InSpec en victim-1 — 8 controles exitosos, 0 fallos.*

### Resultados Victim-2

![InSpec Victim-2](img/test_inspec_victim2.png)
*Figura 8: Auditoría InSpec en victim-2 — 8 controles exitosos, 0 fallos.*

---

## 6. Verificación del Bloqueo

Para demostrar la efectividad de las contramedidas, intentamos reinyectar el agente malicioso.

### Ataque después del bastionado

![Ataque Bloqueado](img/comando_despues_bloqueo.png)
*Figura 9: Intento de inyección después del bastionado. La conexión queda bloqueada indefinidamente por iptables.*

### Logs post-bloqueo en Kibana

![Logs post-bloqueo](img/despues_bloqueo.png)
*Figura 10: Registros en Kibana tras el bastionado — actividad limpia sin compromisos.*

### Mapa de infección final

![Verificación Monkey](img/monkey_verification.png)
*Figura 11: Mapa de infección tras el bastionado — nodos inalcanzables para el atacante.*

---

## 7. Mapeo MITRE ATT&CK

| # | Ataque | Fase MITRE | Técnica | Evidencia en ELK | Contramedida |
|---|---|---|---|---|---|
| 1 | Escaneo de puertos | Discovery | T1046 | `firewall_drop` | Política INPUT DROP |
| 2 | Fuerza bruta SSH | Credential Access | T1110.001 | `ssh_failed_attempt` | Rate limiting + Fail2ban |
| 3 | Login SSH exitoso | Initial Access | T1078 | `ssh_login_success` | Deshabilitar root + clave pública |
| 4 | Propagación SMB | Lateral Movement | T1021.002 | `lateral_movement` | Bloqueo puertos 135/139/445 |
| 5 | Propagación RPC/WMI | Lateral Movement | T1047 | Conexiones puerto 135 | Bloqueo puerto 135 |
| 6 | Dumpeo credenciales | Credential Access | T1003.008 | `auditd_event` en /etc/shadow | Permisos 0600 en shadow |
| 7 | Persistencia local | Persistence | T1543.003 | Escrituras en cron | Restricción cron.allow |
| 8 | Servicios obsoletos | Discovery | T1592 | Puertos 21/23 abiertos | Desactivación ftp/telnet |

---

## 8. Conclusión

El proyecto ha demostrado el ciclo completo de emulación de adversarios:

1. **Detección de vulnerabilidades** — Inyección y movimiento de Infection Monkey en una red no asegurada
2. **Monitorización centralizada** — Captura de evidencias del comportamiento anómalo mediante el stack ELK
3. **Mitigación efectiva** — Aislamiento de la infraestructura mediante reglas de firewalling interno y bastionado de servicios, bloqueando ataques subsecuentes

El resultado es una infraestructura que no solo es más segura, sino que puede auditarse y verificarse técnicamente con herramientas como Chef InSpec.

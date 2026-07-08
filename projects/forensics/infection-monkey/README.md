# Proyecto 11 — Emulación de Adversarios, Monitorización y Bastionado

Ciclo completo de emulación de adversarios utilizando **Infection Monkey**, monitorización centralizada con **ELK Stack** (Elasticsearch, Logstash, Kibana) y bastionado de infraestructura con **iptables, SSH hardening, Fail2ban** y verificación mediante **Chef InSpec**.

---

## Arquitectura

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
│  │     FIREWALL (iptables + Suricata IDS)                       │  │
│  │     - Ext: 192.168.100.10  - Int: 10.0.0.2                  │  │
│  │     - Políticas: INPUT DROP, FORWARD DROP                    │  │
│  │     - NAT / Masquerade                                       │  │
│  │     - Rate limiting SSH                                      │  │
│  │     - Logging → Logstash                                     │  │
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

---

## Requisitos

- Docker Desktop (o Docker Engine + Docker Compose)
- 8 GB RAM disponibles
- InSpec >= 4.46 (para verificación de cumplimiento, instalado en `C:\opscode\inspec`)

---

## Despliegue Rápido

### 1. Levantar el entorno

```bash
cd docker
docker compose up -d
```

Esto levanta 8 contenedores:
- `firewall` — iptables + Suricata IDS
- `victim-1` — Servidor web (Nginx)
- `victim-2` — Servidor base de datos (MySQL)
- `elasticsearch`, `logstash`, `kibana` — Stack ELK
- `monkey_island`, `monkey_mongo` — Infection Monkey

### 2. Verificar

```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
docker exec victim-1 ping -c 2 victim-2
docker exec firewall iptables -L -n -v
```

### 3. Acceder a Infection Monkey

1. Abre `https://localhost:5000`
2. Acepta el certificado autofirmado
3. Crea usuario (ej: `admin` / `BastionadoProyecto11`)
4. Configura el ataque:
   - **Server IP**: `10.0.0.1`
   - **Network Scan**: `10.0.0.0/24`
   - **Exploits**: SSH Exploiter, SMB Exploiter
5. Despliega agentes vía SSH:
   - `victim-1`: `10.0.0.10` — `root` / `toor`
   - `victim-2`: `10.0.0.11` — `root` / `toor`

### 4. Monitorizar en Kibana

1. Abre `http://localhost:5601`
2. Crea un Data View: `proyecto11-logs-*` (campo temporal: `@timestamp`)

**Queries de detección:**

| Query | Qué detecta |
|---|---|
| `tags: firewall_drop` | Paquetes bloqueados por iptables |
| `tags: ssh_failed_attempt` | Fuerza bruta SSH |
| `tags: ssh_login_success` | Compromiso SSH exitoso |
| `tags: suricata_alert` | Alertas del IDS Suricata |

### 5. Aplicar contramedidas

```bash
cd scripts
# En Bash:
./apply_countermeasures.sh

# O manualmente en cada víctima (ver scripts/)
```

### 6. Re-ejecutar simulación y comparar

Vuelve a Infection Monkey, lanza otra simulación y compara el mapa de infección (antes rojo vs después verde) y los logs en Kibana.

---

## Verificación con InSpec

```bash
cd inspec

# En Windows con Chef InSpec instalado en C:\opscode\inspec
$env:CHEF_LICENSE="accept"
& "C:\opscode\inspec\bin\inspec.bat" exec profiles/hardening -t docker://victim-1
& "C:\opscode\inspec\bin\inspec.bat" exec profiles/hardening -t docker://victim-2
```

**Resultado esperado:** 8 controles exitosos, 0 fallos.

| ID | Control | Descripción |
|---|---|---|
| ssh-01 | SSH Protocol and Port | Puerto 22 abierto |
| ssh-02 | SSH Root Login Disabled | `PermitRootLogin no` |
| ssh-03 | SSH Password Auth Disabled | `PasswordAuthentication no` |
| fw-01 | iptables operational | Firewall activo |
| fw-02 | Propagation ports blocked | Puertos 445, 135 bloqueados |
| svc-01 | Shadow file permissions | `/etc/shadow` en 0600 |
| svc-02 | Insecure services disabled | Telnet/FTP desactivados |

Si InSpec falla por el transporte Docker en Windows (named pipe), usa el script alternativo:

```powershell
.\scripts\run_inspec_checks.ps1       # Para victim-1
.\scripts\run_inspec_checks_victim2.ps1  # Para victim-2
```

---

## Mapeo MITRE ATT&CK

| # | Ataque | Fase MITRE | Técnica | Contramedida |
|---|---|---|---|---|
| 1 | Escaneo de puertos | Discovery | T1046 | Política INPUT DROP |
| 2 | Fuerza bruta SSH | Credential Access | T1110.001 | Rate limiting + Fail2ban |
| 3 | Login SSH exitoso | Initial Access | T1078 | Deshabilitar root + clave pública |
| 4 | Propagación SMB | Lateral Movement | T1021.002 | Bloqueo puertos 135/139/445 |
| 5 | Propagación RPC/WMI | Lateral Movement | T1047 | Bloqueo puerto 135 |
| 6 | Dumpeo credenciales | Credential Access | T1003.008 | Permisos 0600 en shadow |
| 7 | Persistencia local | Persistence | T1543.003 | Restricción cron.allow |
| 8 | Servicios obsoletos | Discovery | T1592 | Desactivación ftp/telnet |

---

## Informe en formato Codelabs

El informe final está disponible como Google Codelab:

```
proyecto11/11/index.html
```

Generado con `claat` a partir de `codelab.md`.

---

## Estructura del proyecto

```
proyecto11/
├── 11/                    # Codelab generado (HTML)
├── docker/                # Entorno de simulación
│   ├── docker-compose.yml
│   ├── victim/Dockerfile
│   ├── firewall/
│   │   ├── Dockerfile
│   │   ├── entrypoint.sh
│   │   ├── suricata.yaml
│   │   └── custom.rules
│   └── elk/
│       ├── logstash.conf
│       └── kibana_saved_searches.ndjson
├── scripts/
│   ├── apply_countermeasures.sh
│   ├── apply_countermeasures.ps1
│   ├── analyze_logs.sh
│   ├── run_inspec_checks.ps1
│   └── run_inspec_checks_victim2.ps1
├── inspec/
│   └── profiles/hardening/
│       ├── inspec.yml
│       └── controls/
│           ├── ssh.rb
│           ├── firewall.rb
│           └── services.rb
├── ansible/               # Hardening automatizado
│   ├── ansible.cfg
│   ├── inventory.ini
│   ├── playbooks/hardening.yml
│   └── roles/hardening/
│       ├── tasks/main.yml
│       ├── handlers/main.yml
│       ├── templates/
│       │   ├── sshd_config.j2
│       │   ├── iptables.rules.j2
│       │   └── rsyslog.conf.j2
│       └── vars/main.yml
├── terraform/             # Infraestructura como código
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   └── terraform.tfvars
├── img/                   # Capturas de pantalla
├── INFORME_FINAL.md       # Informe final del proyecto
├── INFORME_EJECUCION_Y_CAPTURAS.md  # Guía de ejecución y capturas
├── GUION_PRESENTACION.md  # Guión para la presentación
├── INFECTION_MONKEY_GUIDE.md
├── codelab.md             # Fuente del Codelab
├── codelab.json
├── claat-windows-amd64.exe
└── README.md
```

---

## Comandos útiles

```bash
# Ver logs del firewall
docker exec firewall tail -f /var/log/suricata/fast.log

# Ver intentos de SSH en víctimas
docker exec victim-1 tail -f /var/log/auth.log

# Ver reglas de iptables
docker exec victim-1 iptables -L INPUT -n -v --line-numbers

# Acceder a una víctima
docker exec -it victim-1 bash

# Verificar SSH hardening
docker exec victim-1 grep -E '^(PermitRootLogin|PasswordAuthentication)' /etc/ssh/sshd_config

# Testear conectividad
docker exec monkey_island ping 10.0.0.10

# Reiniciar todo
cd docker
docker compose down
docker compose up -d
```

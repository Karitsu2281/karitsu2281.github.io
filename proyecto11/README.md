# Proyecto 11 - Emulacion de Adversarios y Contramedidas

## Arquitectura

```
┌──────────────────────────────────────────────────────────────────┐
│                      Docker Host (tu maquina)                     │
│                                                                  │
│  ┌─────────────────┐     ┌────────────────────────────────────┐ │
│  │ Infection Monkey │     │         ELK Stack                  │ │
│  │  (monkey_island) │     │  Elasticsearch :9200              │ │
│  │  http://:5000    │     │  Logstash     :5515/:5044         │ │
│  └────────┬─────────┘     │  Kibana       :5601               │ │
│           │               └────────────────────────────────────┘ │
│           │                                                      │
│  ┌────────▼──────────────────────────────────────────────────┐   │
│  │              Red Externa (192.168.100.0/24)                │   │
│  └────────────────────────┬───────────────────────────────────┘   │
│                           │                                      │
│  ┌────────────────────────▼───────────────────────────────────┐   │
│  │  FIREWALL (iptables + Suricata IDS)                        │   │
│  │  - NAT/Masquerade                                         │   │
│  │  - Rate limiting SSH                                      │   │
│  │  - Logging → Logstash                                     │   │
│  │  - Forwarding                                              │   │
│  └────────────────────────┬───────────────────────────────────┘   │
│                           │                                      │
│  ┌────────────────────────▼───────────────────────────────────┐   │
│  │              Red Interna (10.0.0.0/24)                     │   │
│  │                                                            │   │
│  │  ┌──────────────┐    ┌──────────────┐                     │   │
│  │  │  victim-1     │    │  victim-2    │                     │   │
│  │  │  .10          │    │  .11         │                     │   │
│  │  │  SSH:22       │    │  SSH:22      │                     │   │
│  │  │  HTTP:80      │    │  MySQL:3306  │                     │   │
│  │  │  NGINX        │    │  SMB:445     │                     │   │
│  │  └──────────────┘    └──────────────┘                     │   │
│  └────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

## Requisitos

- Docker Desktop (o Docker Engine + Docker Compose)
- Terraform >= 1.3.0 (opcional, alternativa a docker-compose)
- Ansible >= 2.12 (para hardening automatizado)
- InSpec >= 5 (para verificacion de cumplimiento)
- Al menos 8 GB de RAM disponibles
- Python 3 (para scripts de analisis)

## Despliegue Rapido (Docker Compose)

### Paso 1: Levantar el entorno

```bash
cd proyecto11/docker
docker compose up -d
```

Esto levanta:
- Firewall con iptables + Suricata IDS
- 2 maquinas victima (Ubuntu con SSH, HTTP, MySQL)
- ELK Stack (Elasticsearch, Logstash, Kibana)
- Infection Monkey Island + MongoDB

### Paso 2: Verificar el entorno

```bash
# Ver contenedores
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Comprobar red interna
docker exec victim-1 ping -c 2 victim-2

# Verificar firewall
docker exec firewall iptables -L -n -v
```

### Paso 3: Acceder a Infection Monkey

1. Abre http://localhost:5000 en tu navegador
2. Configura la simulacion:
   - **Island mode**: Accede a la configuracion
   - **PBA (Post-Breach Assessment)**: Habilita la evaluacion
   - **Network scan**: Escanea la red 10.0.0.0/24
   - **Exploits**: Habilita los que quieras probar
3. Despliega Monkey Agents via SSH a las victimas:
   ```
   Host: 10.0.0.10 (victim-1)  Usuario: root  Password: toor
   Host: 10.0.0.11 (victim-2)  Usuario: root  Password: toor
   ```
4. Ejecuta la simulacion

### Paso 4: Analizar los logs

```bash
# Acceder a Kibana
# Abre http://localhost:5601

# O ejecuta el script de analisis automatico
cd proyecto11/scripts
chmod +x analyze_logs.sh
./analyze_logs.sh
```

#### Consultas utiles en Kibana:
- `tags: firewall_drop` — Paquetes bloqueados por el firewall
- `tags: ssh_failed_attempt` — Intentos de fuerza bruta SSH
- `tags: suricata_alert` — Alertas del IDS
- `tags: ssh_login_success` — Logins SSH exitosos

### Paso 5: Aplicar contramedidas

```bash
cd proyecto11/scripts
chmod +x apply_countermeasures.sh
./apply_countermeasures.sh
```

### Paso 6: Re-ejecutar simulacion

Vuelve a Infection Monkey y lanza otra simulacion. Compara los resultados antes/despues de las contramedidas en Kibana.

---

## Despliegue con Terraform (alternativa)

```bash
cd proyecto11/terraform
terraform init
terraform plan
terraform apply -auto-approve

# Para destruir
terraform destroy -auto-approve
```

---

## Hardening con Ansible

```bash
cd proyecto11/ansible

# Aplicar hardening a las victimas
ansible-playbook -i inventory.ini playbooks/hardening.yml

# Solo a una victima
ansible-playbook -i inventory.ini playbooks/hardening.yml --limit victim-1
```

---

## Verificar hardening con InSpec

```bash
cd proyecto11/inspec

# Ejecutar perfil de hardening contra una victima
inspec exec profiles/hardening -t docker://victim-1

# Generar reporte
inspec exec profiles/hardening -t docker://victim-1 --reporter json:report.json
```

---

## Analisis de resultados para la presentacion

Documenta los siguientes puntos en tu presentacion:

1. **Proceso de despliegue**
   - Capturas de `docker ps`, `iptables -L`
   - Evidencia de que los servicios estan corriendo

2. **Emulacion de adversarios**
   - Configuracion usada en Infection Monkey
   - Tipos de ataques ejecutados (fuerza bruta, propagacion, escaneo)
   - Captura del informe de Infection Monkey

3. **Deteccion en registros**
   - Capturas de Kibana mostrando:
     - Paquetes bloqueados por el firewall
     - Intentos de fuerza bruta SSH
     - Alertas de Suricata con firmas activadas
   - Tabla de comportamientos detectados vs origen

4. **Medidas de mitigacion**
   - Reglas de iptables implementadas
   - Configuracion de fail2ban
   - Hardening SSH
   - Comparativa antes/despues (graficas de Kibana)

---

## Comandos utiles

```bash
# Ver logs del firewall en tiempo real
docker exec firewall tail -f /var/log/suricata/fast.log
docker exec firewall tail -f /var/log/syslog

# Ver intentos de SSH en victimas
docker exec victim-1 tail -f /var/log/auth.log

# Entrar en una victima
docker exec -it victim-1 bash

# Ver reglas de iptables en el firewall
docker exec firewall iptables -L -n -v --line-numbers

# Ver alerts de Suricata
docker exec firewall cat /var/log/suricata/fast.log

# Testear conectividad desde Monkey Island
docker exec monkey_island ping 10.0.0.10
docker exec monkey_island nmap 10.0.0.10

# Reiniciar todo
cd proyecto11/docker
docker compose down
docker compose up -d
```

---

## Estructura del proyecto

```
proyecto11/
├── terraform/           # Infraestructura como codigo (Docker provider)
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   └── terraform.tfvars
├── ansible/             # Automatizacion de hardening
│   ├── ansible.cfg
│   ├── inventory.ini
│   ├── playbooks/
│   │   └── hardening.yml
│   └── roles/hardening/
│       ├── tasks/main.yml
│       ├── handlers/main.yml
│       ├── templates/
│       │   ├── sshd_config.j2
│       │   ├── iptables.rules.j2
│       │   └── rsyslog.conf.j2
│       └── vars/main.yml
├── inspec/              # Verificacion de cumplimiento
│   └── profiles/hardening/
│       ├── inspec.yml
│       └── controls/
│           ├── ssh.rb
│           ├── firewall.rb
│           └── services.rb
├── docker/              # Entorno de simulacion
│   ├── docker-compose.yml
│   ├── victim/Dockerfile
│   ├── firewall/
│   │   ├── Dockerfile
│   │   ├── entrypoint.sh
│   │   └── suricata.yaml
│   └── elk/
│       └── logstash.conf
├── scripts/             # Analisis y contramedidas
│   ├── analyze_logs.sh
│   └── apply_countermeasures.sh
└── README.md
```

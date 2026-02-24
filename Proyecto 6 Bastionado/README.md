# Proyecto 6: Un dashboard imprescindible en el SOC

## Fundamentación teórica
A lo largo de las diferentes unidades se ha destacado una y otra vez la importancia de la monitorización en cualquier infraestructura de seguridad. Sin monitorización activa, no sabremos qué es lo que está pasando, no podremos actuar con la celeridad necesaria y, por lo tanto, estaremos ciegos ante cualquier problema. Un buen sistema de monitorización debe ser exhaustivo y mostrar las alertas que nos permitan solucionar cualquier incidencia antes incluso de que los usuarios se percaten de que existe.

## Objetivos del proyecto
Realizar una comparativa entre diferentes sistemas de monitorización (Zabbix y Prometheus) y documentar pruebas de concepto instalando y monitorizando dispositivos.

---

## 1. Comparativa de Sistemas de Monitorización

| Característica | Zabbix | Prometheus |
| :--- | :--- | :--- |
| **Arquitectura** | Basado en un servidor central que recolecta datos (Pull o Push) usando agentes pesados o SNMP/JMX. | Basado en métricas temporales (Time-Series) con modelo principal "Pull" (scrapea métricas expuestas). |
| **Agentes** | Usa "Zabbix Agent" oficial instalado en los sistemas operativos a monitorizar. | Usa múltiples "Exporters" específicos (Node Exporter para Linux, Windows Exporter, etc). |
| **Curva de Aprendizaje** | Curva moderada-alta, tiene una interfaz web integrada completa pero compleja inicialmente. | Curva pronunciada para PromQL (lenguaje de consultas), requiere integrar Grafana para cuadros de mando. |
| **Gestión de Alertas** | Integrado de forma nativa en la plataforma web, fácil configuración visual de *triggers*. | Requiere configuración de *Alertmanager* (componente separado) y reglas por código (YAML). |
| **Escalabilidad** | Escala muy bien usando "Zabbix Proxies" para entornos distribuidos y sucursales. | Diseñado nativamente de forma distribuida, permite federación y encaja perfecto con entornos efímeros (Kubernetes). |
| **Almacenamiento (BBDD)**| Requiere bases de datos relacionales tradicionales (MySQL, PostgreSQL). | Usa su propia base de datos de series temporales (TSDB) en disco local, altamente optimizada para métricas. |
| **Complejidad de instalación** | Instalación sencilla mediante paquetes APT (`apt install zabbix-server-mysql …`). Los servicios systemd se crean automáticamente con el paquete. | Instalación manual compilando/descargando binarios, creando usuarios de sistema, copiando ficheros y **escribiendo a mano los ficheros `.service` de systemd** (demonios). Mayor complejidad operativa. |

---

## 2. Prueba de Concepto 1: Monitorización con Zabbix

En esta demostración se instaló Zabbix Server 7.0 en una máquina virtual Linux (Ubuntu 24.04) y se configuraron agentes para monitorizar tanto el propio servidor Ubuntu como un portátil **Dell Latitude 5490** con Windows.

### 2.1 Instalación de Zabbix Server en Ubuntu (P6-Bast)

#### Preparación del entorno: dependencias previas

El primer paso consistió en actualizar los repositorios del sistema e instalar las dependencias necesarias para que Zabbix funcione: el servidor web Apache, los módulos PHP requeridos y el motor de base de datos MySQL.

![Actualizando e instalando actualizaciones del sistema con sudo apt update y sudo apt upgrade -y](img/Captura%20de%20pantalla%202026-02-24%20164934.png)
![Instalando el servidor web Apache2 con sudo apt install apache2 -y](img/Captura%20de%20pantalla%202026-02-24%20165027.png)
![Instalando módulos PHP necesarios: php-cgi, php-common, php-mbstring, php-net-socket, php-gd, php-xml-util, php-mysql, php-bcmath, php-imap y php-snmp](img/Captura%20de%20pantalla%202026-02-24%20165104.png)
![Instalando el módulo libapache2-mod-php para integrar PHP con Apache](img/Captura%20de%20pantalla%202026-02-24%20165150.png)
![Instalando el servidor de base de datos MySQL con sudo apt install mysql-server -y](img/Captura%20de%20pantalla%202026-02-24%20165219.png)

#### Configuración de MySQL

Se inicia, habilita y verifica el servicio MySQL. Acto seguido se ejecuta el asistente de securización (`mysql_secure_installation`) para establecer la contraseña de root y eliminar defaults inseguros:

![Iniciando, habilitando y verificando el servicio MySQL con systemctl start, enable y status mysql (Active: active running)](img/Captura%20de%20pantalla%202026-02-24%20170942.png)
![Ejecutando sudo mysql_secure_installation para securizar la instancia de MySQL](img/Captura%20de%20pantalla%202026-02-24%20171124.png)

#### Instalación del repositorio y paquetes de Zabbix

Descargamos el paquete `.deb` del repositorio oficial de Zabbix 7.0 para Ubuntu (Noble) e instalamos los componentes del servidor:

![Descargando el paquete de repositorio Zabbix 7.0 con wget desde repo.zabbix.com](img/Captura%20de%20pantalla%202026-02-24%20171225.png)
![Instalando los paquetes zabbix-server-mysql, zabbix-frontend-php, zabbix-apache-conf, zabbix-sql-scripts y zabbix-agent con apt](img/Captura%20de%20pantalla%202026-02-24%20171313.png)

#### Creación de la base de datos Zabbix en MySQL

Entramos en la consola de MySQL para crear la base de datos `zabbix`, el usuario asociado y otorgar los privilegios necesarios:

![Creando la base de datos zabbix, el usuario zabbix@localhost y otorgando privilegios con CREATE DATABASE, CREATE USER, GRANT ALL PRIVILEGES, SET GLOBAL log_bin_trust_function_creators y FLUSH PRIVILEGES](img/Captura%20de%20pantalla%202026-02-24%20172556.png)

#### Importación del esquema SQL inicial

Poblamos la BBDD recién creada importando el esquema inicial que proporciona Zabbix mediante `zcat`:

![Importando el esquema SQL inicial con sudo zcat /usr/share/zabbix-sql-scripts/mysql/server.sql.gz piped a mysql](img/Captura%20de%20pantalla%202026-02-24%20172908.png)

Tras la importación, se desactiva la variable `log_bin_trust_function_creators` que habíamos habilitado temporalmente:

![Desactivando log_bin_trust_function_creators con SET GLOBAL y ejecutando FLUSH PRIVILEGES en la consola MySQL](img/Captura%20de%20pantalla%202026-02-24%20172936.png)

#### Configuración del archivo zabbix_server.conf

Editamos el fichero de configuración principal de Zabbix Server para introducir las credenciales de conexión a la base de datos:

![Abriendo el fichero de configuración con sudo nano /etc/zabbix/zabbix_server.conf](img/Captura%20de%20pantalla%202026-02-24%20173103.png)
![Vista del editor nano mostrando los parámetros DBUser=zabbix y DBPassword configurados en zabbix_server.conf](img/Captura%20de%20pantalla%202026-02-24%20173144.png)

#### Reinicio y activación de servicios

Reiniciamos y habilitamos los servicios de Zabbix Server, Zabbix Agent y Apache2, y verificamos que todo arranca correctamente:

![Reiniciando e habilitando los servicios zabbix-server, zabbix-agent y apache2 con systemctl restart y systemctl enable](img/Captura%20de%20pantalla%202026-02-24%20173209.png)
![Verificando el estado del servicio zabbix-server con systemctl status: Active running desde 17:31:50 CET, PID 24737](img/Captura%20de%20pantalla%202026-02-24%20173213.png)

#### Finalización mediante Interfaz Web (Instalador UI)

Cumplidos los prerrequisitos en la terminal de Ubuntu, accedemos a `http://localhost/zabbix/setup.php` y seguimos el asistente web oficial de Zabbix 7.0:

![Pantalla de bienvenida del instalador web de Zabbix 7.0, idioma predeterminado Español (es_ES)](img/Captura%20de%20pantalla%202026-02-24%20173252.png)
![Paso Configurar la conexión de BD: tipo MySQL, servidor localhost, base de datos zabbix, usuario zabbix con contraseña](img/Captura%20de%20pantalla%202026-02-24%20173324.png)
![Paso Ajustes: nombre del servidor Monitoreo SOC, zona horaria Europe/Madrid (UTC+01:00), tema Azul](img/Captura%20de%20pantalla%202026-02-24%20173407.png)
![Pantalla de inicio de sesión de Zabbix con usuario Admin y contraseña](img/Captura%20de%20pantalla%202026-02-24%20173427.png)
![Dashboard Global View mostrando Zabbix Server v7.0.23 ejecutándose, 1 equipo habilitado, 354 plantillas y 128 métricas activas](img/Captura%20de%20pantalla%202026-02-24%20173444.png)

#### Configuración del agente local

Una vez en el portal, configuramos el agente Linux local (`zabbix_agentd.conf`) apuntando a `Server=127.0.0.1`, `ServerActive=127.0.0.1` y `Hostname=Ubuntu-VM-SOC`:

![Editor nano mostrando el fichero /etc/zabbix/zabbix_agentd.conf con Server=127.0.0.1 y ServerActive=127.0.0.1](img/Captura%20de%20pantalla%202026-02-24%20173558.png)
![Panel Equipos de Zabbix mostrando el host Zabbix server en 127.0.0.1:10050, estado Activado, con 128 datos recientes y 10 gráficos](img/Captura%20de%20pantalla%202026-02-24%20173819.png)
![Dashboard Global View completo mostrando CPU al 22.89%, reloj Madrid 17:38, 1 equipo disponible y 0 problemas](img/Captura%20de%20pantalla%202026-02-24%20173836.png)

### 2.2 Integración y monitorización del Portátil Dell Latitude 5490 (Windows)

#### Instalación del agente en el portátil Dell

En la parte del portátil **Dell-Latitude-5490**, comprobamos que el **Zabbix Agent 2** esté instalado y corriendo correctamente:

![Buscando el Agente Zabbix en el Menú Inicio de Windows del portátil Dell](img/WhatsApp%20Image%202026-02-24%20at%205.59.14%20PM.jpeg)
![Fichero de configuración zabbix_agent2.conf del equipo cliente Dell mostrando la IP del servidor Zabbix](img/WhatsApp%20Image%202026-02-24%20at%205.59.15%20PM.jpeg)

Observamos los logs del agente corroborando el inicio del *listener* en el puerto 10050 y las comprobaciones activas (active checks) en contacto con la IP del servidor Ubuntu:

![Logs del Zabbix Agent 2 mostrando el inicio del listener en el puerto 10050](img/WhatsApp%20Image%202026-02-24%20at%205.59.15%20PM%20%281%29.jpeg)
![Logs del Zabbix Agent 2 reportando peticiones satisfactorias hacia el servidor](img/WhatsApp%20Image%202026-02-24%20at%205.59.15%20PM%20%282%29.jpeg)

Hacemos validaciones de conectividad (ICMP) desde el portátil hacia redes externas confirmando acceso a Internet:

![Ping desde el CMD del portátil Dell hacia 8.8.8.8 y la puerta de enlace, verificando respuesta de red](img/WhatsApp%20Image%202026-02-24%20at%205.59.15%20PM%20%283%29.jpeg)

#### Alta del host Dell en la interfaz web de Zabbix

Desde la web de Zabbix creamos el nuevo equipo rellenando nombre, IP del agente, plantilla y grupo de hosts:

![Botones Crear equipo e Importar en la esquina superior derecha del panel de Equipos](img/Captura%20de%20pantalla%202026-02-24%20175329.png)
![Formulario Nuevo equipo vacío con campos Nombre de equipo, Plantillas, Grupos de equipos, Interfaces y Descripción](img/Captura%20de%20pantalla%202026-02-24%20175335.png)
![Equipo Dell-Latitude-5490-AntiJunko configurado con plantilla Windows by Zabbix agent, grupo Portátiles, interfaz Agente IP 192.168.3.51 puerto 10050](img/Captura%20de%20pantalla%202026-02-24%20175346.png)

#### Métricas recolectadas del portátil Dell

Una vez completada la integración, Zabbix comienza a recolectar métricas del portátil y las muestra en sus gráficas internas:

![Gráfica de utilización de memoria del Dell-Latitude-5490-AntiJunko: media ~39.47%, mínimo 39.19%, máximo 39.91%](img/Captura%20de%20pantalla%202026-02-24%20175620.png)
![Gráfica de tiempos de espera de disco (Disk average waiting time) del Dell: lectura media 0.53ms, escritura media 1.22ms](img/Captura%20de%20pantalla%202026-02-24%20175754.png)
![Gráfica de longitud de cola de disco (Disk average queue length) del Dell: lectura media 0.006631, escritura media 0.004185](img/Captura%20de%20pantalla%202026-02-24%20175805.png)
![Gráfica circular de espacio en disco C: del Dell: 237.6 GB total, 65.33 GB usados (27.50%), 172.27 GB disponibles (72.50%)](img/Captura%20de%20pantalla%202026-02-24%20175818.png)
![Gráfica de tráfico de red de la interfaz Intel Dual Band Wireless-AC 8265 (Wi-Fi): recibidos 10.06 Kbps, enviados 6.94 Kbps](img/Captura%20de%20pantalla%202026-02-24%20175827.png)

---

## 3. Prueba de Concepto 2: Monitorización con Prometheus

Para completar la experiencia, replicamos la monitorización usando **Prometheus 2.48.0**, instalado directamente desde binarios en la misma VM Ubuntu. A diferencia de Zabbix, Prometheus **no provee paquetes `.deb`** que creen los servicios de forma automática: fue necesario crear manualmente el usuario de sistema, las carpetas de datos, copiar binarios y **escribir a mano el demonio systemd** (`.service`), lo que supuso una complejidad de instalación notablemente mayor.

### 3.1 Instalación del servidor Prometheus

#### Creación del usuario de sistema y directorios

El primer paso es crear un usuario de sistema sin shell ni directorio home, dedicado exclusivamente a ejecutar Prometheus. Después, creamos las carpetas de configuración y de datos:

![Creando el usuario de sistema prometheus con sudo useradd --system --no-create-home --shell /usr/sbin/nologin prometheus](img/Captura%20de%20pantalla%202026-02-24%20185324.png)
![Creando los directorios /etc/prometheus (configuración) y /var/lib/prometheus (datos TSDB) con sudo mkdir](img/Captura%20de%20pantalla%202026-02-24%20185338.png)

#### Descarga y extracción de Prometheus

Descargamos el tarball oficial de Prometheus v2.48.0 desde GitHub y lo extraemos:

![Descargando prometheus-2.48.0.linux-amd64.tar.gz con wget desde GitHub Releases](img/Captura%20de%20pantalla%202026-02-24%20185416.png)
![Extrayendo el tarball con tar xvfz, mostrando el contenido: prometheus, promtool, consoles, console_libraries, prometheus.yml, etc.](img/Captura%20de%20pantalla%202026-02-24%20185433.png)
![Entrando en el directorio extraído prometheus-2.48.0.linux-amd64](img/Captura%20de%20pantalla%202026-02-24%20185442.png)

#### Copiando binarios y ficheros de configuración

Copiamos los binarios (`prometheus` y `promtool`) a `/usr/local/bin/` y las consolas web a `/etc/prometheus/`. Después asignamos la propiedad al usuario `prometheus`:

![Copiando binarios prometheus y promtool a /usr/local/bin y consoles y console_libraries a /etc/prometheus](img/Captura%20de%20pantalla%202026-02-24%20185524.png)
![Asignando ownership con sudo chown -R prometheus:prometheus en /etc/prometheus, /var/lib/prometheus, /usr/local/bin/prometheus y /usr/local/bin/promtool](img/Captura%20de%20pantalla%202026-02-24%20185539.png)

#### Configuración de prometheus.yml

Editamos el fichero de configuración principal de Prometheus donde definimos los *scrape jobs* para cada target que queremos monitorizar:

![Editor nano mostrando /etc/prometheus/prometheus.yml con scrape_interval: 15s, tres jobs configurados: prometheus (localhost:9090), ubuntu-vm (localhost:9100, instance Ubuntu-VM-SOC), y dell-laptop (192.168.3.51:9100, instance Dell-Latitude-5490)](img/Captura%20de%20pantalla%202026-02-24%20185647.png)

#### Creación manual del demonio systemd

A diferencia de Zabbix (cuyo paquete `.deb` crea los servicios automáticamente), en Prometheus debemos **escribir a mano** el fichero `.service` de systemd. Especificamos el usuario, grupo, ruta del binario, fichero de configuración, ruta de almacenamiento TSDB y las consolas:

![Editor nano mostrando /etc/systemd/system/prometheus.service con secciones Unit (Description=Prometheus, After=network-online.target), Service (User=prometheus, Type=simple, ExecStart=/usr/local/bin/prometheus con flags --config.file, --storage.tsdb.path, --web.console.templates y --web.console.libraries, Restart=on-failure) e Install (WantedBy=multi-user.target)](img/Captura%20de%20pantalla%202026-02-24%20185706.png)

#### Arranque y verificación del servicio

Recargamos los ficheros de systemd, iniciamos y habilitamos el servicio. Verificamos con `systemctl status`:

![Ejecutando sudo systemctl daemon-reload, start prometheus, enable prometheus y status prometheus: Active running desde 18:57:12 CET, PID 28790, Memory 21.0M](img/Captura%20de%20pantalla%202026-02-24%20185743.png)

### 3.2 Cliente Dell Latitude 5490 (Windows): Instalación de Windows Exporter

En el lado del portátil Dell, descargamos **Windows Exporter v0.31.3** desde la página oficial de GitHub Releases. Este exporter es el equivalente de *Node Exporter* pero para sistemas Windows, y expone las métricas del sistema en el puerto `:9182`:

![Página de GitHub Releases de windows_exporter v0.31.3 mostrando los assets disponibles: windows_exporter-0.31.3-amd64.exe, windows_exporter-0.31.3-amd64.msi, versiones arm64, sha256sums.txt y código fuente](img/WhatsApp%20Image%202026-02-24%20at%207.10.20%20PM.jpeg)

Tras instalar el `.msi`, abrimos una ventana de PowerShell como Administrador y creamos una regla de firewall para permitir el tráfico entrante en el puerto `9182`, necesario para que Prometheus pueda scrapear las métricas:

![PowerShell del Dell ejecutando New-NetFirewallRule -DisplayName "Prometheus Exporter" -Direction Inbound -Action Allow -LocalPort 9182, mostrando la regla creada con DisplayName: Prometheus Exporter, Enabled: True, Direction: Inbound, Action: Allow, PrimaryStatus: OK](img/WhatsApp%20Image%202026-02-24%20at%207.10.21%20PM.jpeg)

### 3.3 Interfaz web de Prometheus y verificación de Targets

Accedemos a `http://localhost:9090` y consultamos la página de Targets para verificar la conectividad con cada endpoint. Inicialmente, el target `dell-laptop` aparece en estado **DOWN** porque el puerto de scraping no era correcto (9100 en lugar de 9182 para Windows Exporter):

![Página Targets de Prometheus mostrando dell-laptop DOWN en http://192.168.3.51:9100/metrics con error context deadline exceeded, prometheus UP en localhost:9090, y ubuntu-vm visible](img/Captura%20de%20pantalla%202026-02-24%20190425.png)

### 3.4 Corrección del target Dell: cambio a Windows Exporter (puerto 9182)

El Portátil Dell ejecuta **Windows Exporter**, que expone métricas en el puerto `:9182` (no `:9100` como Node Exporter de Linux). Corregimos el `prometheus.yml` actualizando el job del Dell:

![Editor nano mostrando el job dell-latitude-antijunko corregido con target 192.168.3.51:9182 e instance Dell-Latitude-5490](img/Captura%20de%20pantalla%202026-02-24%20190550.png)

Tras reiniciar Prometheus, el target Dell aparece ahora en estado **UP**:

![Página Targets de Prometheus mostrando dell-latitude-antijunko UP en http://192.168.3.51:9182/metrics (213.598ms), prometheus UP en localhost:9090, ubuntu-vm DOWN en localhost:9100 con error connection refused](img/Captura%20de%20pantalla%202026-02-24%20190720.png)

### 3.5 Consultas PromQL y métricas recolectadas

Desde la interfaz web de Prometheus (`localhost:9090/graph`), ejecutamos consultas PromQL para verificar los datos recolectados:

![Vista tabla de la métrica up mostrando 4 instancias: Dell-Latitude-5490 (dell-laptop), Dell-Latitude-5490 (dell-latitude-antijunko), Ubuntu-VM-SOC (ubuntu-vm) y localhost:9090 (prometheus)](img/Captura%20de%20pantalla%202026-02-24%20190830.png)
![Gráfica de windows_cpu_time_total del Dell-Latitude-5490 mostrando tiempo de CPU por core y modo (dpc, idle, interrupt, privileged, user) con valores hasta 6.00k](img/Captura%20de%20pantalla%202026-02-24%20190902.png)
![Gráfica de la métrica up a lo largo del tiempo mostrando los 4 targets, con Dell-Latitude-5490 y prometheus manteniéndose en valor 1 (UP) desde ~18:00](img/Captura%20de%20pantalla%202026-02-24%20190914.png)

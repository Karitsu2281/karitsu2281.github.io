
summary: Proyecto 6 - Un dashboard imprescindible en el SOC
id: proyecto-6-bastionado
categories: bastionado, monitorización, zabbix, prometheus
environments: Web
status: Published
authors: Karitsu2281
feedback link: https://github.com/karitsu2281

# Proyecto 6: Un dashboard imprescindible en el SOC

## Introducción y Objetivos
Duration: 0:02:00

A lo largo de las diferentes unidades se ha destacado una y otra vez la importancia de la monitorización en cualquier infraestructura de seguridad. Sin monitorización activa, no sabremos qué es lo que está pasando, no podremos actuar con la celeridad necesaria y, por lo tanto, estaremos ciegos ante cualquier problema. Un buen sistema de monitorización debe ser exhaustivo y mostrar las alertas que nos permitan solucionar cualquier incidencia antes incluso de que los usuarios se percaten de que existe.

**Objetivo:** Realizar una comparativa entre diferentes sistemas de monitorización (Zabbix y Prometheus) y documentar pruebas de concepto instalando y monitorizando dispositivos.

## Comparativa de Sistemas de Monitorización
Duration: 0:05:00

| Característica | Zabbix | Prometheus |
| :--- | :--- | :--- |
| **Arquitectura** | Basado en un servidor central que recolecta datos (Pull o Push) usando agentes pesados o SNMP/JMX. | Basado en métricas temporales (Time-Series) con modelo principal "Pull" (scrapea métricas expuestas). |
| **Agentes** | Usa "Zabbix Agent" oficial instalado en los sistemas operativos a monitorizar. | Usa múltiples "Exporters" específicos (Node Exporter para Linux, Windows Exporter, etc). |
| **Curva de Aprendizaje** | Curva moderada-alta, tiene una interfaz web integrada completa pero compleja inicialmente. | Curva pronunciada para PromQL (lenguaje de consultas), requiere integrar Grafana para cuadros de mando. |
| **Gestión de Alertas** | Integrado de forma nativa en la plataforma web, fácil configuración visual de *triggers*. | Requiere configuración de *Alertmanager* (componente separado) y reglas por código (YAML). |
| **Escalabilidad** | Escala muy bien usando "Zabbix Proxies" para entornos distribuidos y sucursales. | Diseñado nativamente de forma distribuida, permite federación y encaja perfecto con entornos efímeros (Kubernetes). |
| **Almacenamiento (BBDD)**| Requiere bases de datos relacionales tradicionales (MySQL, PostgreSQL). | Usa su propia base de datos de series temporales (TSDB) en disco local, altamente optimizada para métricas. |
| **Complejidad de instalación** | Instalación sencilla mediante paquetes APT. Los servicios systemd se crean automáticamente con el paquete. | Instalación manual compilando/descargando binarios, creando usuarios de sistema, copiando ficheros y **escribiendo a mano los ficheros `.service` de systemd** (demonios). Mayor complejidad operativa. |

## Instalación de Zabbix Server en Ubuntu
Duration: 0:10:00

En esta demostración se instaló Zabbix Server 7.0 en una máquina virtual Linux (Ubuntu 24.04) y se configuraron agentes para monitorizar tanto el propio servidor Ubuntu como un portátil **Dell Latitude 5490** con Windows.

### Preparación del entorno: dependencias previas

El primer paso consistió en actualizar los repositorios del sistema e instalar las dependencias necesarias para que Zabbix funcione: el servidor web Apache, los módulos PHP requeridos y el motor de base de datos MySQL.

![Actualizando e instalando actualizaciones del sistema](img/Captura de pantalla 2026-02-24 164934.png)
![Instalando el servidor web Apache2](img/Captura de pantalla 2026-02-24 165027.png)
![Instalando módulos PHP necesarios](img/Captura de pantalla 2026-02-24 165104.png)
![Instalando el módulo libapache2-mod-php](img/Captura de pantalla 2026-02-24 165150.png)
![Instalando el servidor de base de datos MySQL](img/Captura de pantalla 2026-02-24 165219.png)

### Configuración de MySQL

Se inicia, habilita y verifica el servicio MySQL. Acto seguido se ejecuta el asistente de securización (`mysql_secure_installation`) para establecer la contraseña de root y eliminar defaults inseguros:

![Iniciando, habilitando y verificando el servicio MySQL](img/Captura de pantalla 2026-02-24 170942.png)
![Ejecutando mysql_secure_installation](img/Captura de pantalla 2026-02-24 171124.png)

### Instalación del repositorio y paquetes de Zabbix

Descargamos el paquete `.deb` del repositorio oficial de Zabbix 7.0 para Ubuntu (Noble) e instalamos los componentes del servidor:

![Descargando el paquete de repositorio Zabbix 7.0](img/Captura de pantalla 2026-02-24 171225.png)
![Instalando los paquetes zabbix-server-mysql y componentes](img/Captura de pantalla 2026-02-24 171313.png)

### Creación de la base de datos Zabbix en MySQL

Entramos en la consola de MySQL para crear la base de datos `zabbix`, el usuario asociado y otorgar los privilegios necesarios:

![Creando la base de datos zabbix y configurando privilegios](img/Captura de pantalla 2026-02-24 172556.png)

### Importación del esquema SQL inicial

Poblamos la BBDD recién creada importando el esquema inicial que proporciona Zabbix mediante `zcat`:

![Importando el esquema SQL inicial con zcat](img/Captura de pantalla 2026-02-24 172908.png)

Tras la importación, se desactiva la variable `log_bin_trust_function_creators` que habíamos habilitado temporalmente:

![Desactivando log_bin_trust_function_creators](img/Captura de pantalla 2026-02-24 172936.png)

### Configuración del archivo zabbix_server.conf

Editamos el fichero de configuración principal de Zabbix Server para introducir las credenciales de conexión a la base de datos:

![Abriendo el fichero zabbix_server.conf](img/Captura de pantalla 2026-02-24 173103.png)
![Parámetros DBUser y DBPassword en zabbix_server.conf](img/Captura de pantalla 2026-02-24 173144.png)

### Reinicio y activación de servicios

Reiniciamos y habilitamos los servicios de Zabbix Server, Zabbix Agent y Apache2, y verificamos que todo arranca correctamente:

![Reiniciando e habilitando los servicios](img/Captura de pantalla 2026-02-24 173209.png)
![Verificando el estado del servicio zabbix-server: Active running](img/Captura de pantalla 2026-02-24 173213.png)

### Finalización mediante Interfaz Web

Cumplidos los prerrequisitos en la terminal de Ubuntu, accedemos a `http://localhost/zabbix/setup.php` y seguimos el asistente web oficial de Zabbix 7.0:

![Pantalla de bienvenida del instalador web de Zabbix 7.0](img/Captura de pantalla 2026-02-24 173252.png)
![Configurar la conexión de BD: MySQL, localhost](img/Captura de pantalla 2026-02-24 173324.png)
![Ajustes: nombre Monitoreo SOC, zona horaria Europe/Madrid](img/Captura de pantalla 2026-02-24 173407.png)
![Pantalla de inicio de sesión de Zabbix](img/Captura de pantalla 2026-02-24 173427.png)
![Dashboard Global View mostrando Zabbix Server v7.0.23](img/Captura de pantalla 2026-02-24 173444.png)

### Configuración del agente local

Una vez en el portal, configuramos el agente Linux local (`zabbix_agentd.conf`) apuntando a `Server=127.0.0.1`, `ServerActive=127.0.0.1` y `Hostname=Ubuntu-VM-SOC`:

![Fichero zabbix_agentd.conf con Server y ServerActive configurados](img/Captura de pantalla 2026-02-24 173558.png)
![Panel Equipos de Zabbix mostrando el host activo](img/Captura de pantalla 2026-02-24 173819.png)
![Dashboard Global View completo con CPU al 22.89%](img/Captura de pantalla 2026-02-24 173836.png)

## Integración del Portátil Dell con Zabbix
Duration: 0:05:00

### Instalación del agente en el portátil Dell

En la parte del portátil **Dell-Latitude-5490**, comprobamos que el **Zabbix Agent 2** esté instalado y corriendo correctamente:

![Buscando el Agente Zabbix en Windows del portátil Dell](img/WhatsApp Image 2026-02-24 at 5.59.14 PM.jpeg)
![Fichero zabbix_agent2.conf del equipo cliente Dell](img/WhatsApp Image 2026-02-24 at 5.59.15 PM.jpeg)

Observamos los logs del agente corroborando el inicio del *listener* en el puerto 10050 y las comprobaciones activas:

![Logs del Zabbix Agent 2: listener en puerto 10050](img/WhatsApp Image 2026-02-24 at 5.59.15 PM (1).jpeg)
![Logs del Zabbix Agent 2: peticiones satisfactorias](img/WhatsApp Image 2026-02-24 at 5.59.15 PM (2).jpeg)

Hacemos validaciones de conectividad (ICMP) desde el portátil hacia redes externas:

![Ping desde CMD del Dell verificando respuesta de red](img/WhatsApp Image 2026-02-24 at 5.59.15 PM (3).jpeg)

### Alta del host Dell en la interfaz web de Zabbix

Desde la web de Zabbix creamos el nuevo equipo rellenando nombre, IP del agente, plantilla y grupo de hosts:

![Botones Crear equipo e Importar en panel de Equipos](img/Captura de pantalla 2026-02-24 175329.png)
![Formulario Nuevo equipo vacío](img/Captura de pantalla 2026-02-24 175335.png)
![Equipo Dell-Latitude-5490 configurado con plantilla Windows](img/Captura de pantalla 2026-02-24 175346.png)

### Métricas recolectadas del portátil Dell

Una vez completada la integración, Zabbix comienza a recolectar métricas del portátil:

![Gráfica de utilización de memoria del Dell](img/Captura de pantalla 2026-02-24 175620.png)
![Gráfica de tiempos de espera de disco del Dell](img/Captura de pantalla 2026-02-24 175754.png)
![Gráfica de longitud de cola de disco del Dell](img/Captura de pantalla 2026-02-24 175805.png)
![Gráfica circular de espacio en disco C: del Dell](img/Captura de pantalla 2026-02-24 175818.png)
![Gráfica de tráfico de red Wi-Fi del Dell](img/Captura de pantalla 2026-02-24 175827.png)

## Instalación del servidor Prometheus
Duration: 0:10:00

Para completar la experiencia, replicamos la monitorización usando **Prometheus 2.48.0**, instalado directamente desde binarios en la misma VM Ubuntu. A diferencia de Zabbix, Prometheus **no provee paquetes `.deb`** que creen los servicios de forma automática: fue necesario crear manualmente el usuario de sistema, las carpetas de datos, copiar binarios y **escribir a mano el demonio systemd** (`.service`), lo que supuso una complejidad de instalación notablemente mayor.

### Creación del usuario de sistema y directorios

El primer paso es crear un usuario de sistema sin shell ni directorio home, dedicado exclusivamente a ejecutar Prometheus. Después, creamos las carpetas de configuración y de datos:

![Creando el usuario de sistema prometheus](img/Captura de pantalla 2026-02-24 185324.png)
![Creando los directorios /etc/prometheus y /var/lib/prometheus](img/Captura de pantalla 2026-02-24 185338.png)

### Descarga y extracción de Prometheus

Descargamos el tarball oficial de Prometheus v2.48.0 desde GitHub y lo extraemos:

![Descargando prometheus-2.48.0.linux-amd64.tar.gz](img/Captura de pantalla 2026-02-24 185416.png)
![Extrayendo el tarball con tar](img/Captura de pantalla 2026-02-24 185433.png)
![Entrando en el directorio extraído](img/Captura de pantalla 2026-02-24 185442.png)

### Copiando binarios y ficheros de configuración

Copiamos los binarios (`prometheus` y `promtool`) a `/usr/local/bin/` y las consolas web a `/etc/prometheus/`. Después asignamos la propiedad al usuario `prometheus`:

![Copiando binarios y consoles](img/Captura de pantalla 2026-02-24 185524.png)
![Asignando ownership con chown -R](img/Captura de pantalla 2026-02-24 185539.png)

### Configuración de prometheus.yml

Editamos el fichero de configuración principal de Prometheus donde definimos los *scrape jobs* para cada target que queremos monitorizar:

![prometheus.yml con scrape_interval y tres jobs configurados](img/Captura de pantalla 2026-02-24 185647.png)

### Creación manual del demonio systemd

A diferencia de Zabbix (cuyo paquete `.deb` crea los servicios automáticamente), en Prometheus debemos **escribir a mano** el fichero `.service` de systemd:

![prometheus.service con secciones Unit, Service e Install](img/Captura de pantalla 2026-02-24 185706.png)

### Arranque y verificación del servicio

Recargamos los ficheros de systemd, iniciamos y habilitamos el servicio:

![systemctl daemon-reload, start, enable y status prometheus: Active running](img/Captura de pantalla 2026-02-24 185743.png)

## Cliente Dell con Windows Exporter para Prometheus
Duration: 0:05:00

En el lado del portátil Dell, descargamos **Windows Exporter v0.31.3** desde la página oficial de GitHub Releases. Este exporter es el equivalente de *Node Exporter* pero para sistemas Windows, y expone las métricas del sistema en el puerto `:9182`:

![Página de GitHub Releases de windows_exporter v0.31.3](img/WhatsApp Image 2026-02-24 at 7.10.20 PM.jpeg)

Tras instalar el `.msi`, abrimos una ventana de PowerShell como Administrador y creamos una regla de firewall para permitir el tráfico entrante en el puerto `9182`:

![PowerShell creando regla de firewall para Prometheus Exporter](img/WhatsApp Image 2026-02-24 at 7.10.21 PM.jpeg)

## Verificación de Targets y Consultas PromQL
Duration: 0:05:00

### Interfaz web de Prometheus y verificación de Targets

Accedemos a `http://localhost:9090` y consultamos la página de Targets para verificar la conectividad con cada endpoint. Inicialmente, el target `dell-laptop` aparece en estado **DOWN** porque el puerto de scraping no era correcto (9100 en lugar de 9182 para Windows Exporter):

![Página Targets con dell-laptop DOWN](img/Captura de pantalla 2026-02-24 190425.png)

### Corrección del target Dell: cambio a Windows Exporter (puerto 9182)

El Portátil Dell ejecuta **Windows Exporter**, que expone métricas en el puerto `:9182` (no `:9100` como Node Exporter de Linux). Corregimos el `prometheus.yml` actualizando el job del Dell:

![Job dell-latitude-antijunko corregido con target 192.168.3.51:9182](img/Captura de pantalla 2026-02-24 190550.png)

Tras reiniciar Prometheus, el target Dell aparece ahora en estado **UP**:

![Targets con dell-latitude-antijunko UP en puerto 9182](img/Captura de pantalla 2026-02-24 190720.png)

### Consultas PromQL y métricas recolectadas

Desde la interfaz web de Prometheus (`localhost:9090/graph`), ejecutamos consultas PromQL para verificar los datos recolectados:

![Métrica up mostrando 4 instancias activas](img/Captura de pantalla 2026-02-24 190830.png)
![Gráfica de windows_cpu_time_total del Dell](img/Captura de pantalla 2026-02-24 190902.png)
![Gráfica de la métrica up a lo largo del tiempo](img/Captura de pantalla 2026-02-24 190914.png)

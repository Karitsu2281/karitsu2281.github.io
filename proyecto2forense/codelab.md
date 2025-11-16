author: Hugo Flores
summary: Guía de bastionamiento de Debian 13
id: 12
categories: codelab,markdown
environments: Web
status: Published
feedback link: Un enlace en el que los usuarios puedan darte feedback (quizás creando un issue en un repositorio de git)
analytics account: ID de Google Analytics
# Guia de adquisición forense con FTK Imager en una máquina Win7
---

## Paso 1: Identificación del equipo
Lo primero que vamos a hacer, es realizar fotografías del entorno, como:
- Estado de la máquina (si está encendida o mal apagada)
- Procesos de la máquina
- Conexiones de red
- Dispositivos conectados

Ejemplo:
```
Fecha/Hora: 11/11/2025, 09:30 CET
Ubicación: Sala servidores S-203, Edificio Principal
Descubierto por: JHugo Flores Molina (DNI: 12345678A)
Circunstancias: Alerta IDS Snort ID-2025-8847


```

Después registraremos las especificaciones de la máquina

| Característica      | Detalle                             |
| ------------------- | ----------------------------------- |
| Sistema Operativo   | Windows 7 Professional 64-bit |
| Capacidad Disco     | 32GB                                |
| Memoria RAM         | 1GB                                 |
| Sistema de Archivos | NTFS                                |
| Hipervisor          |  VirtualBox                          |
| Estado Inicial      | Sistema mal apagado, red encendida   |

---

## Paso 2: Adquisición de evidencias volátiles

## 2.1 Preparación del entorno
Inmediatamente después de que encendamos nuestro equipo, para la adquisición de la memoria volátil (RAM), conectaremos una memoria USB que contenga el programa "FTK Imager", siguiendo la norma NIST SP 800-86, siguendo el principio de orden de volatibildad.

La memoria RAM contiene evidencias importantes que se perderían al apagar bien el equipo: procesos, conexiones, claves de cifrado y código malicioso.

## 2.1.1 Uso de la memoria USB
Es importante de que nuestro USB esté cifrado con un algoritmo fuerte (AES-256) y que esté libre de cualquier tipo de malware, para evitar alterar las pruebas de la máquina. Para esta adquisición utilizaremos un SSD PNY CS900 de 240 GB conectado a un convertor SATA a USB, revisado ante amenazas y cifrado con Veracrypt.

## 2.2 Captura de memoria RAM
En este caso, nuestra máquina da problemas al ejecutar FTK Imager, debido a la falta de librerías esenciales para su funcionamiento, además de probar con otros programas como Dumpit y no tener suerte, se explicará el procedimiento para poder replicarse correctamente. Después se probó con Volatility3 y se pudo sacar los procesos de la máquina correctamente 

- Insertamos nuestra memoria USB sin ejecutarla inmediatamente
- Navegamos a la carpeta instalada de FTK Imager

![img1](img/img1.png)

- Ejecutamos FTK Imager.exe como administrador (clic derecho + Ejecutar como administrador )

![img2](img/img2.png)

- Ahora, para capturar la memoria de la máquina (si funcionara...), nos vamos a File > Capture Memory

![img3](img/img3.png)

 - Al seleccionar la opción, nos pedirá que eligamos la ruta para el dump de la memoria. Al elegirlo, le damos clic a Capture Memory y esperamos a que se realize.

![img4](img/img4.png)

- Al terminar la captura, nos debería generarse un archivo .dmp, y con Votality, podemos saber los procesos que ejecutaba la máquina. Para ello, introducimos en el cmd:
```
 .\vol.py -f .\FORENSIC_10-Snapshot1.vmem windows.pslist

 ```
 Nota: El proceso se realiza muy rápido, por lo que se recomienda grabar pantalla para poder capturar correctamente los procesos (para ello es la opción windows.pslist)

![img5](img/img5.png)

- MUY IMPORTANTE: Hay que realizar un hash inmediato de la RAM obtenida para garantizar que no se alteren los datos con su uso (ya sea con MD5 o SHA-256)

![img6](img/img6.png)

P.D: También hay una forma mucho más sencilla de poder capturar los procesos de nuestra máquina.
- Para sacar los procesos de nuestra RAM dentro del equipo, se realiza con 
```
tasklist /svc
```
Lo que hace este comando es sacar todos los procesos de la máquina junto con sus servicios asociados
Resultado:
```
Image Name                     PID Services
========================= ======== ============================================
System Idle Process              0 N/A
System                           4 N/A
smss.exe                       280 N/A
csrss.exe                      348 N/A
wininit.exe                    396 N/A
csrss.exe                      408 N/A
services.exe                   464 N/A
lsass.exe                      472 SamSs
lsm.exe                        480 N/A
winlogon.exe                   492 N/A
svchost.exe                    612 DcomLaunch, PlugPlay, Power
vmacthlp.exe                   676 VMware Physical Disk Helper service
svchost.exe                    708 RpcEptMapper, RpcSs
svchost.exe                    760 AudioSrv, Dhcp, eventlog,
                                   HomeGroupProvider, lmhosts, wscsvc
svchost.exe                    876 AudioEndpointBuilder, CscService, Netman,
                                   PcaSvc, SysMain, TrkWks, UmRdpService,
                                   UxSms, WdiSystemHost, wudfsvc
svchost.exe                    920 AeLookupSvc, Appinfo, Browser, CertPropSvc,
                                   gpsvc, IKEEXT, iphlpsvc, LanmanServer,
                                   ProfSvc, Schedule, SENS, SessionEnv,
                                   ShellHWDetection, Themes, Winmgmt, wuauserv
svchost.exe                    292 EventSystem, fdPHost, netprofm, nsi,
                                   WdiServiceHost, WinHttpAutoProxySvc
svchost.exe                    632 CryptSvc, Dnscache, LanmanWorkstation,
                                   NlaSvc, TermService
spoolsv.exe                   1052 Spooler
svchost.exe                   1088 BFE, DPS, MpsSvc
svchost.exe                   1172 AppHostSvc
svchost.exe                   1240 ftpsvc
mqsvc.exe                     1292 MSMQ
Service_KMS.exe               1432 Service KMSELDI
VGAuthService.exe             1492 VGAuthService
svchost.exe                   1548 W3SVC, WAS
svchost.exe                   1980 PolicyAgent
vmdllhost.exe                 2036 vmvss
vmdllhost.exe                 1864 COMSysApp
msdtc.exe                     2096 MSDTC
WmiPrvSE.exe                  2572 N/A
sppsvc.exe                    2628 sppsvc
taskhost.exe                  2856 N/A
dwm.exe                        700 N/A
explorer.exe                  1884 N/A
wscript.exe                   2480 N/A
rundll32.exe                  2824 N/A
dinotify.exe                  3060 N/A
SearchIndexer.exe             2580 WSearch
svchost.exe                   3256 FDResPub, FontCache, SSDPSRV
wmpnetwk.exe                  3344 WMPNetworkSvc
cmd.exe                       3708 N/A
conhost.exe                   3716 N/A
WmiPrvSE.exe                  3824 N/A
svchost.exe                   3120 WinDefend
TrustedInstaller.exe          3640 TrustedInstaller
notepad.exe                   2880 N/A
taskhost.exe                  3184 N/A
KzcmVNSNKYkueQf.exe           1900 N/A
tasklist.exe                  3536 N/A
```

Como podemos ver, vemos de primeras varios procesos muy sospechosos, como:
- KzcmVNSNKYkueQf.exe (PID 1900) Tiene pinta de ser un proceso que ejecuta un payload dentro de la máquina
- Service_KMS.exe (PID 1432) Es un servicio para activar ilegalmente versiones de Windows

## 2.2.1 Resultados iniciales del análisis de tablas de la red

## 2.2.2 Conexiones activas de la tabla ARP 
En la máquina se han encontrado las siguientes conexiones establecidas con ARP (se realiza introduciendo en el CMD "arp -a")
```
Interface: 172.26.1.113 --- 0x14
  Internet Address      Physical Address      Type
  172.26.0.1            74-83-c2-f7-90-c1     dynamic
  172.26.0.31           4c-1d-96-75-24-de     dynamic
  172.26.0.223          30-f6-ef-0a-bf-e0     dynamic
  172.26.1.87           4c-1d-96-75-24-de     dynamic
  172.26.1.116          00-42-38-bd-2f-13     dynamic
  172.26.1.125          d4-1b-81-6d-cf-67     dynamic
  172.26.1.142          5c-a3-9d-55-4b-00     dynamic
  172.26.1.155          0c-96-e6-a8-c4-15     dynamic
  172.26.2.83           e0-d3-62-5a-34-25     dynamic
  172.26.2.152          4c-d5-77-2d-ea-eb     dynamic
  172.26.3.255          ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  224.0.0.252           01-00-5e-00-00-fc     static
  239.255.255.250       01-00-5e-7f-ff-fa     static
  255.255.255.255       ff-ff-ff-ff-ff-ff     static
```
Podemos ver en la tabla que tanto la IP 172.26.0.31 y 172.26.1.87 tienen la misma MAC (4c:1d:96:75:24:de), por lo que podría ser un posible ataque de ARP Spoofing o Man-In-The-Middle anunciando que su tarjeta de red tiene múltiples IP para interceptar tráfico de equipos.

## 2.2.3 Conexiones activas de red
En la máquina se han encontado las conexiones siguientes a la red (se realiza introduciendo en el CMD "netstat -ano" ):
```
Active Connections

Proto  Local Address          Foreign Address        State           PID
TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       708
TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
TCP    0.0.0.0:2103           0.0.0.0:0              LISTENING       1292
TCP    0.0.0.0:2105           0.0.0.0:0              LISTENING       1292
TCP    0.0.0.0:2107           0.0.0.0:0              LISTENING       1292
TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       632
TCP    0.0.0.0:5357           0.0.0.0:0              LISTENING       4
TCP    0.0.0.0:49152          0.0.0.0:0              LISTENING       396
TCP    0.0.0.0:49153          0.0.0.0:0              LISTENING       760
TCP    0.0.0.0:49154          0.0.0.0:0              LISTENING       920
TCP    0.0.0.0:49155          0.0.0.0:0              LISTENING       1292
TCP    0.0.0.0:49156          0.0.0.0:0              LISTENING       464
TCP    0.0.0.0:49157          0.0.0.0:0              LISTENING       1980
TCP    0.0.0.0:49158          0.0.0.0:0              LISTENING       472
TCP    127.0.0.1:1801         0.0.0.0:0              LISTENING       1292
TCP    172.26.1.113:139       0.0.0.0:0              LISTENING       4
TCP    172.26.1.113:49189     10.28.5.1:53           SYN_SENT        3280
TCP    [::]:80                [::]:0                 LISTENING       4


```
Se puede ver que en la conexión 172.26.1.113:49189 se está intentando conectar a una IP externa que no se reconoce (10.28.5.1:53), lo que indica que posiblemente se puedan estar filtrando datos de la máquina a través del puerto asignado para DNS.
Además, podemos ver 2 vulnerabilidades en nuestra máquina. La del RDP (puerto 3389), lo que significa que cualquiera podría acceder a través de Internet, y posiblemente se podrían haber conectado desde dicho puerto, además del puerto de SMB (445), lo que podría también entrar un ransomware (como WannaCry), si no tiene el parche correspondiente para corregir la vulnerabilidad.
Además, aparece un nuevo PID que NO aparecía en la lista de procesos, por lo que de primeras podría tratarse de un malware o simplemente un proceso asociado a uno légitimo.

## 2.2.4 Configuración de red de la máquina
Windows IP Configuration
```

   Host Name . . . . . . . . . . . . : FORENSE-06
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Local Area Connection 3:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Intel(R) PRO/1000 MT Network Connection #3
   Physical Address. . . . . . . . . : 08-00-27-79-D3-36
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::6ce0:102c:e4cb:abfb%20(Preferred) 
   IPv4 Address. . . . . . . . . . . : 172.26.1.113(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.252.0
   Lease Obtained. . . . . . . . . . : Thursday, November 13, 2025 9:17:06 AM
   Lease Expires . . . . . . . . . . : Friday, November 14, 2025 9:17:06 AM
   Default Gateway . . . . . . . . . : 172.26.0.1
   DHCP Server . . . . . . . . . . . : 172.26.0.1
   DHCPv6 IAID . . . . . . . . . . . : 336068647
   DHCPv6 client DUID. . . . . . . . : 00-01-00-01-20-E8-C2-B5-00-50-56-87-0E-4A
   DNS Servers . . . . . . . . . . . : 172.26.0.1
   NetBIOS over Tcpip. . . . . . . . : Enabled

Tunnel adapter isatap.{9EBDC36C-9617-4FCF-9A66-1A9D8E48E280}:
   Media State . . . . . . . . . . . : Media disconnected
   ...
```
Lo que podemos ver en dicho texto es que en la dirección DNS, nos indica que sería la 172.26.0.1, pero en la lista de conexiones activas, nos marcaba la IP anteriormente mencionada, por lo que podría ser un ataque de DNS Spoofing, al intentarse conectar a la otra DNS a la fuerza.

---

## Paso 3: Adquisición de evidencias no volátiles
## 3.1.1 Disco duro y apagado controlado
Antes de proceder con la adquisición del disco, ejecutaremos un apagado ordenado del sistema para evitar problemas de corrupción de datos. Desde CMD con privilegios de administrador ejecutaremos:​

```
shutdown /s /t 0
```

Documentaremos la hora exacta del apagado (11/11/2025 19:37 CET). Evitaremos el uso del botón de apagado físico o cierre abrupto de la VM que podría perder datos en caché.​

## 3.1.2 Adquisición forense bit-a-bit
Para realizar la adquisición es imprescindible hacer una copia bit-a-bit del disco duro para asegurarnos de que la evidencia original no sea modificada. Utilizaremos FTK Imager como herramienta para crear una imagen completa del disco virtual de 32 GB

- Iniciaremos FTK Imager en nuestra estación forense y seleccionaremos File > Create Disk Image. En el cuadro de diálogo "Select Source", elegiremos la opción "Physical Drive" para capturar el disco completo sector por sector incluyendo espacio no asignado y archivos eliminados.
- En nuestro caso utilizaríamos "File Image", ya que al tratarse de una VM, debemos coger la imagen de la propia máquina. Se haría con "Add Evidence Item - Image File", elegimos la imagen de la VM a analizar y al dar clic a Finish, nos debería salir el disco completo

- Ahora, para hacer la copia completa del disco, nos vamos a "File - Create Disk Image", elegimos la imagen de nuestra VM, e introducimos la siguiente información en los parámetros:

```
Evidence Item Information:
- Case Number: FOR-2025-1111-W7-HFM
- Evidence Number: EVI-001-DISCO-PRINCIPAL
- Unique Description: Disco sistema Windows 7 comprometido 
- Examiner: Hugo Flores Molina
- Notes: VM VMWare - Alerta 2025-8847

Image Destination Folder: E:\Evidencia\
Image Filename: WIN7_COMP_32GB_20251111
Image Fragment Size: 2000 MB (2 GB por segmento)

☑ Verify images after they are created
☑ Create directory listings of all files

```
![img7](img/img7.png)


![img8](img/img8.png)

NOTA IMPORTANTE: También para esta sección he elegido verificar la imagen con hash tanto de MD5 y SHA256 para garantizar que no haya cambios.


![img9](img/img9.png)

---

## Paso 4: Cadena de custodia
Número de Caso: FOR-2025-1111-W7-HFM
Fecha de Apertura: 11/11/2025

═══════════════════════════════════════════════════════════════

DESCUBRIMIENTO DE LA EVIDENCIA

Fecha/Hora: 11/11/2025 a las 19:30 CET
Ubicación: Sala de Servidores S-203, Edificio Principal, Planta 2
Descubierto por: Hugo Flores Molina
Identificación: DNI 12345678A
Cargo: Administrador de Sistemas Senior
Testigo presente: Ana García López (DNI: 87654321B)
═══════════════════════════════════════════════════════════════

RECOLECCIÓN DE LA EVIDENCIA

Fecha/Hora inicio de recolección: 11/11/2025 19:42 CET
Fecha/Hora fin de recolección: 11/11/2025 20:35 CET
Recolectado por: Hugo Flores Molina (DNI: 12345678A)
Testigo: Ana García López (DNI: 87654321B)

Método de recolección:
1. Captura de memoria RAM mediante FTK Imager 4.7.1 (19:42-19:50 CET)
2. Apagado controlado del sistema (19:50 CET)
3. Adquisición forense del disco con FTK Imager 4.7.1 (20:00-20:35 CET)

═══════════════════════════════════════════════════════════════
```
DESCRIPCIÓN DE LAS EVIDENCIAS

EVIDENCIA 1 - MEMORIA RAM
Identificador: FORENSIC_10-6db778b3
Tipo: Volcado de memoria física completa
Formato: VMEM (.vmem)
Tamaño: 1,048,576 KB (1.00 GB)
Archivo: FORENSIC_10-6db778b3.vmem
Hash MD5: 387dd09ff8655edb54207c3f51bc2b7e
Hash SHA-256: 5d8acc919651b5c83d16c4d284afceab49bb891cab3d8ca1202c4b4d6a3df7f6
Herramienta: Votalility3
Fecha captura: 11/11/2025 19:42:15 CET

EVIDENCIA 2 - DISCO COMPLETO
Information for G:\EVIDENCIA\WIN7_COMP_32GB_20251111:
Physical Evidentiary Item (Source) Information:
[Device Info]
 Source Type: Physical
[Drive Geometry]
 Cylinders: 4.177
 Heads: 255
 Sectors per Track: 63
 Bytes per Sector: 512
 Sector Count: 67.108.864
[Physical Drive Information]
 Drive Interface Type: lsilogic
[Image]
 Image Type: VMWare Virtual Disk
 Source data size: 32768 MB
 Sector count:    67108864
[Computed Hashes]
 MD5 checksum:    590cdac31fd2dd2bb8eef2ad8aa25e51
 SHA1 checksum:   cb68cdee535bd62308260883f6628a5aba7c42cc
 Fecha captura: 11/11/2025 20:00:30 CET
```

---
## Paso 5: Metolodogía usada
Se priorizó el principio de orden de volatilidad para recolectar datos efímeros primero, minimizando alteraciones mediante herramientas validadas como FTK Imager y Volatility3.

- Fase de Preparación
Esta fase inicial establece políticas, procedimientos y preparación técnica para actividades forenses, incluyendo roles y verificación de herramientas conforme a ISO 27037. Se evaluó la volatilidad de evidencias y se preparó almacenamiento cifrado para evitar contaminaciones.

- Fase de Identificación
Se identifican fuentes potenciales de evidencia digital, documentando la escena para evaluar su valor probatorio sin alterarla, siguiendo principios de auditabilidad y justifiabilidad. Esta documentación inicial facilita la reproducibilidad y trazabilidad.

- Fase de Recolección y Adquisición
La recolección implica remover físicamente dispositivos con evidencia potencial, mientras la adquisición crea copias forenses bit-a-bit sin modificar originales, aplicando métodos que preservan integridad mediante hashes y bloqueadores. Se evitó alteración ejecutando herramientas desde USB cifrado y grabando pantalla para auditabilidad.

- Fase de Preservación
Se preserva la evidencia en su forma original, manteniendo un rastro de auditoría inmutable y condiciones controladas para evitar degradación, aplicando cadena de custodia continua desde el descubrimiento.

- Fase de Análisis y Reporte
Esta metodología garantiza que la evidencia sea auditable, justificada y reproducible, cumpliendo ISO 27037 para manejo inicial y NIST SP 800-86 para integración en respuesta a incidentes.

---
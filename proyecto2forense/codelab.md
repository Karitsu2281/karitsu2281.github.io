author: Hugo Flores
summary: Guía de bastionamiento de Debian 13
id: 1
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
---

## Paso 3: Adquisición de evidencias no volátiles

## 3.1 Disco duro
## 3.1.1 Apagado controlado del sistema
Antes de proceder con la adquisición del disco, ejecutaremos un apagado ordenado del sistema para evitar problemas de corrupción de datos Desde CMD con privilegios de administrador ejecutaremos:​

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
- Unique Description: Disco sistema Windows 7 comprometido - Ransomware
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
Testigo presente: Ana García López (DNI: 87654321B) - CISO




═══════════════════════════════════════════════════════════════

RECOLECCIÓN DE LA EVIDENCIA

Fecha/Hora inicio: 11/11/2025 19:42 CET
Fecha/Hora fin: 11/11/2025 20:35 CET
Recolectado por: Hugo Flores Molina (DNI: 12345678A)
Certificaciones: CHFI-7845, EnCE-4523, GCFA-9012
Testigo: Ana García López (DNI: 87654321B)

Método de recolección:
1. Captura de memoria RAM mediante DumpIt v3.1 (19:42-19:50 CET)
2. Apagado controlado del sistema (19:50 CET)
3. Adquisición forense del disco con FTK Imager 4.7.1 (20:00-20:35 CET)

═══════════════════════════════════════════════════════════════

DESCRIPCIÓN DE LAS EVIDENCIAS

EVIDENCIA 1 - MEMORIA RAM VOLÁTIL
Identificador: EVI-2025-1111-RAM-001
Tipo: Volcado de memoria física completa
Formato: RAW (.raw)
Tamaño: 1,073,741,824 bytes (1.00 GB)
Archivo: memdump_win7_20251111_0930.raw
Hash MD5: 3c7f8a2b9d1e5f6a4c8b2d1e9f7a5c3b
Hash SHA-256: 9b3f1e8d6a2c4b9f7e5d3a1c8b6f4e2d9a7c5b3f1e8d6a4c2b9f7e5d3a1c8b6f
Herramienta: DumpIt v3.1 (MD5: a7c5b3f1e8d6a2c4b9f7e5d3a1c8b6f4)
Fecha captura: 11/11/2025 09:42:15 CET

EVIDENCIA 2 - DISCO COMPLETO
Identificador: EVI-2025-1111-HDD-001
Tipo: Imagen forense bit-a-bit
Formato: Expert Witness E01 (segmentado)
Tamaño original: 34,359,738,368 bytes (32.00 GB)
Tamaño comprimido: 18,874,368,000 bytes (17.58 GB)
Archivos: WIN7_COMP_32GB_20251111.E01 a .E16
Hash MD5: b7f9a3c5d2e1f8a6c4b9d7e2f1a8c5b3
Hash SHA-256: 4c9f7e5d3a1c8b6f4e2d9a7c5b3f1e8d6a4c2b9f7e5d3a1c8b6f9b3f1e8d6a2c
Herramienta: FTK Imager 4.7.1.2 (MD5: c5b3f1e8d6a2c4b9f7e5d3a1c8b6f4e2)
Fecha captura: 11/11/2025 10:00-10:35 CET
Sectores totales: 67,108,864
Errores de lectura: 0
Sistema de archivos: NTFS


---
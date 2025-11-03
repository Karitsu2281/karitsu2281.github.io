author: Hugo Flores
summary: Guía de bastionamiento de PC de alto rendimiento con placa base Aorus B550 Elite AX V2
id: identificador-unico-del-codelab
categories: codelab,markdown
environments: Web
status: Published
feedback link: Un enlace en el que los usuarios puedan darte feedback (quizás creando un issue en un repositorio de git)
analytics account: ID de Google Analytics
# Guia de bastionamiento para PC de alto rendimiento con placa base Aorus B550 Elite AX V2
---

## Materiales necesarios

- PC con placa base Aorus B550 Elite V2 AX
- Memoria USB formateada en FAT32
- Teclado USB (obviamente, entonces como entras a la BIOS...)
- Conexion a Internet para actualizar la BIOS

---

## Paso 1: Obtención y actualización de BIOS

1. Lo primero que vamos a hacer, es identificar que revisión tiene la placa base. Se puede buscar en la propia caja de la placa base o en la misma placa, en mi caso seria REV 1.5 (foto ejemplo de placa base con REV 1.4 marcado en la flecha)

   ![img1](img/img1.png)

2. Descargamos la ultima versión de la BIOS de nuestra placa de la pagina oficial de Gigabyte (es importante elegir la revisión de nuestra placa base para evitar errores en la instalacion):
   - https://www.gigabyte.com/es/Motherboard/B550-AORUS-ELITE-AX-V2-rev-15

   ![img2](img/img2.png)

3. Extraemos el archivo de la BIOS a nuestra memoria USB FAT32 vacía.

   ![img3](img/img3.png)

4. Reiniciamos el ordenador y entramos en BIOS machacando la tecla `Supr` tan pronto como reiniciemos.

5. Abrimos la utilidad **Q-Flash** pulsando `F8`. o haciendo clic en el menú de la BIOS,"Q-Flash". 

   ![img4](img/img4.png)

En este modelo de placa base también podemos actualizar directamente la placa base sin necesidad de CPU con un botón llamado "Q-Flash Plus"

   ![img5](img/img5.png)

6. Elegimos el archivo de la BIOS actualizada desde la USB y esperamos a que se actualice.

---

## Paso 2: Configuración de Secure Boot

1. Entramos nuevamente a la BIOS (machacando `Supr` al iniciar el ordenador).

2. Vamos a la pestaña **Boot**, antes activando el modo avanzado.

![img6](img/img6.png)


3. Desactivamos  `Soporte CSM` (establece en `Deshabilitado`). 
Consiste en una función de la placa donde podemos emular la BIOS antigua para poder ejecutar software más antiguo o Windows de 32 bits. Al desactivarlo, hace que no podamos ejecutar software antiguo o sistemas operativos viejos (Win7 o Win8) con vulnerabilidades conocidas, reduciendo así, la posibilidad de ataque. 

![img8](img/img8.png)

4. En **Boot > Secure Boot**:
   - Cambiamos el estado de `Secure Boot` a `Activado`. El Secure Boot es una función que evita que se pueda ejecutar software sin firma digital o malicioso, si lo tenemos desactivado, el atacante podrá ejecutar cualquier software malicioso en nuestra máquina, al no comprobar la firma digital.

![img9](img/img9.png)

   - Normalmente suele tardar un poco en activarse, en el caso de que no se pueda, le daríamos clic a "Restore Factory Keys" y debería activarse sin problema.

![img15](img/img15.png)

---

## Paso 3: Contraseñas de BIOS y arranque

En la pestaña **System**:
   - Estableceremos una contraseña segura en la `Contraseña de administrador` (tiene que ser mínimo de 12 carácteres, tanto con mayúsculas, minúsculas, números o símbolos especiales). Esto hace que al querer hacer cualquier acción (como cambiar la orden de arranque a un USB) requiera una contraseña para poder realizarse.

![img10](img/img10.png)

   - También configuraremos la `Contraseña de usuario` para restringir aún mas el acceso a la BIOS y evitar arranques desde USBs no autorizados o también desde la tarjeta de red, o una unidad óptica. Esto hace para que si quiera acceder a la BIOS debamos introducir su contraseña, por lo que aumenta la seguridad. Hay que recordar que ambas contraseñas deben ser diferentes para evitar riesgos de seguridad por reutilización de contraseñas.
  
  - En el arranque, la primera opción siempre será la de "Windows Boot Manager", para evitar que el ordenador arranque automáticamente al conectar un USB malicioso (para ello, siempre lo pondremos en la última opción, para reducir posibilidades de ataque)
![img11](img/img11.png)

- 
---

## Paso 4: Activación de TPM (fTPM)

1. Vamos a la pestaña a **Varios**, en la sección **Settings**.

![img12](img/img12.png)

2. Buscamos `AMD CPU fTPM` y lo ajustamos en `Activado`. Lo que hace el TPM, es que genera y almacena claves de firmado, verifica la integridad del SO durante el arranque y protege contra accesos no autorizados. Al no tenerlo, nuestro ordenador es más vulnerable a ataques que alteran el proceso de arranque y no se podría cifrar el disco con BitLocker.

![img13](img/img13.png)

3. Guardamos los cambios presionando F10.

---

## Paso 5: Desactivación de hardware no utilizado

En **Settings**:
   - Desactivamos `HD Audio Controller` en caso de usar un DAC USB externo. 

   ![img14](img/img14.png)

   - Desactivamos `Onboard LAN` si solo queremos usar WiFi.

   ![img19](img/img19.png)

   Estas acciones adicionales se realizan para reducir aún mas la superficie de ataque, ya que nos protegemos de escuchas no autorizadas en el caso del HD Audio Controller o en el caso del LAN Controller, evitar que puedan encender remotamente el ordenador y/o instalar un SO infectado.


---

## Paso 6: Verificación Final en Windows

1. Ejecutamos `msinfo32` en el buscador:

![img16](img/img16.png)

2. Tenemos que comprobar que la siguiente pestaña esté en "Activado" Si lo está, significa que hemos activado correctamente el arranque seguro.
   - `Estado de arranque seguro`: Activado.

![img17](img/img17.png)


2. En el Administrador de dispositivos, confirma que el dispositivo `Módulo de plataforma segura 2.0 (TPM)` esté presente.

![img18](img/img18.png)
---

# ¡Listo! Ya tendríamos nuestro ordenador más resistente ante ataques físicos.

---

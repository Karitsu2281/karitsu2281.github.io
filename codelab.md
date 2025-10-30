# CodeLab: Bastionamiento Completo de BIOS para Aorus B550 Elite V2 AX

Este CodeLab te guiará paso a paso para realizar el bastionamiento (hardening) de la BIOS de tu placa base **Aorus B550 Elite V2 AX**. El objetivo es asegurar tu PC de alto rendimiento desde el nivel más bajo, mejorando la seguridad, estabilidad y protección ante ataques de bajo nivel.

---

## Prerrequisitos

- PC con placa base Aorus B550 Elite V2 AX
- Memoria USB formateada en FAT32
- Acceso a la configuración de BIOS (tecla `Supr` o `Del` durante el arranque)
- Conexión a Internet para descargar actualizaciones

---

## Paso 1: Actualización de BIOS

1. Identifica la revisión de tu placa base impresa en la placa (ejemplo: rev. 1.1, 1.2, etc.)
2. Descarga la última versión de BIOS para tu revisión en la web oficial de Gigabyte:
   - https://www.gigabyte.com/es/Motherboard/B550-AORUS-ELITE-AX-V2-rev-11/support
3. Extrae el archivo BIOS a tu memoria USB FAT32 vacía.
4. Reinicia y entra en BIOS presionando `Supr` durante el inicio.
5. Abre la utilidad **Q-Flash** pulsando `F8`.
6. Selecciona "Update BIOS" y elige el archivo desde la USB.
7. Espera a que finalice el proceso sin apagar el equipo.

---

## Paso 2: Configuración de Secure Boot

1. Entra nuevamente a la BIOS (`Supr` al iniciar).
2. Ve a la pestaña **Boot**.
3. Desactiva `CSM Support` (establece en `Disabled`).
4. Guarda y reinicia (`F10`), vuelve a entrar a BIOS.
5. En **Boot > Secure Boot**:
   - Activa `Secure Boot` en `Enabled`.
   - Si no se activa, cambia a `Custom` y selecciona `Restore Factory Keys`.
6. Guarda y sal.

---

## Paso 3: Contraseñas de BIOS

1. En la pestaña **System**:
   - Establece una contraseña segura en `Administrator Password`.
   - Opcional: configura `User Password` para acceso restringido.
2. Guarda y sal.

---

## Paso 4: Activación de TPM (fTPM)

1. Ve a la pestaña **Peripherals** o **Settings**.
2. Busca `AMD CPU fTPM` y ponla en `Enabled`.
3. Guarda cambios.

---

## Paso 5: Desactivación de hardware no utilizado

1. En **Peripherals** o **Settings > IO Ports**:
   - Desactiva `Serial Port` y `Parallel Port` si no los usas.
   - Desactiva `HD Audio Controller` si tienes tarjeta de sonido externa.
   - Desactiva `Onboard WIFI` o `Onboard LAN` si no los usas.
   - Desactiva puertos SATA no usados.
2. Guarda y sal.

---

## Paso 6: Ajustes de estabilidad y virtualización

1. Ve a la pestaña **Tweaker** o **Settings**.
2. Activa `SVM Mode` (Virtualización) en `Enabled`.
3. Activa `Extreme Memory Profile (X.M.P.)` seleccionando `Profile 1`.
4. Deja los voltajes de CPU en `Auto` para estabilidad.
5. Opcional: Activa `Precision Boost Overdrive` en `Auto` o `Enabled`.
6. Guarda y sal.

---

## Paso 7: Verificación Final en SO Windows

1. Ejecuta `msinfo32` y verifica:
   - `Estado de arranque seguro`: Activado.
2. En el Administrador de dispositivos, confirma que el dispositivo `Módulo de plataforma segura 2.0 (TPM)` esté presente.

---

# ¡Listo! Tu BIOS está ahora bastionada para seguridad y rendimiento máximos.

---

**Nota:** Mantén siempre actualizada la BIOS y revisa periódicamente la configuración para nuevas opciones de seguridad. No modifiques opciones avanzadas sin conocer sus efectos para evitar inestabilidad.

---

## Créditos y Fuentes

- Página oficial Gigabyte B550 AORUS ELITE AX V2
- Guías sobre Secure Boot y TPM para placas Gigabyte
- Mejoras recomendadas en foros tecnológicos y videos tutoriales

---

Fin del CodeLab.

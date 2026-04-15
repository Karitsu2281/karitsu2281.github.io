# Parte 3 — Análisis de Certificados SSL

## Herramienta utilizada

[SSL Labs — Qualys SSL Test](https://www.ssllabs.com/ssltest/)

---

## 1. Análisis del certificado propio (tu-dominio.com)

### Captura del resultado en SSL Labs

<!-- Inserta aquí captura del informe SSL Labs de tu dominio -->
![SSL Labs - propio](./img/ssllabs_propio.png)

### Nota obtenida: X

### Motivos que lo validan como certificado correcto

- **Emisor reconocido**: El certificado está firmado por Let's Encrypt, una CA incluida en los trust stores de todos los navegadores principales.
- **Cadena de confianza completa**: SSL Labs verifica que la cadena de certificados (leaf → intermedio → root) está correctamente configurada.
- **Dominio validado**: El CN y el SAN del certificado coinciden con el dominio solicitado.
- **Protocolo seguro**: Se usa TLS 1.2 / TLS 1.3, sin SSLv3 ni TLS 1.0/1.1.
- **Sin vulnerabilidades conocidas**: No presenta POODLE, BEAST, Heartbleed, etc.
- **Vigente**: La fecha de expiración no ha sido alcanzada.

---

## 2. Certificados erróneos localizados

---

### Certificado 1 — Certificado caducado

**Sitio**: <!-- URL del sitio -->

**Tipo de error**: Certificado expirado (`NET::ERR_CERT_DATE_INVALID`)

**Captura del análisis**:

<!-- Inserta aquí captura del error o del análisis en el servicio utilizado -->
![Certificado caducado](./img/cert_error_caducado.png)

**Explicación**:

Los certificados tienen una fecha de expiración para limitar el tiempo durante el cual una clave comprometida podría ser explotada. Cuando un certificado supera esa fecha, el navegador no puede garantizar que siga siendo válido ni que la clave privada no haya sido comprometida, por lo que bloquea la conexión.

---

### Certificado 2 — Certificado autofirmado / CA no reconocida

**Sitio**: <!-- URL del sitio o entorno de laboratorio -->

**Tipo de error**: CA no reconocida (`NET::ERR_CERT_AUTHORITY_INVALID`)

**Captura del análisis**:

<!-- Inserta aquí captura -->
![CA no reconocida](./img/cert_error_ca_invalida.png)

**Explicación**:

El certificado no ha sido firmado por ninguna CA incluida en el trust store del sistema operativo o el navegador. Sin ese aval de tercero de confianza, el navegador no puede verificar la identidad del servidor y considera la conexión potencialmente peligrosa.

---

### Certificado 3 — Nombre del dominio no coincide

**Sitio**: <!-- URL del sitio -->

**Tipo de error**: Nombre incorrecto (`NET::ERR_CERT_COMMON_NAME_INVALID`)

**Captura del análisis**:

<!-- Inserta aquí captura -->
![Nombre no coincide](./img/cert_error_nombre.png)

**Explicación**:

El campo CN (Common Name) o los SAN (Subject Alternative Names) del certificado no coinciden con el dominio al que se está accediendo. Esto puede indicar un certificado mal configurado, un certificado reutilizado de otro dominio, o en el peor caso un ataque de tipo man-in-the-middle donde un atacante presenta un certificado ajeno.

---

## 3. Tabla resumen de errores

| # | Tipo de error | Causa principal | Riesgo |
|---|---|---|---|
| 1 | Caducado | Fecha de expiración superada | Clave posiblemente comprometida |
| 2 | CA no reconocida | Autofirmado o CA privada | No se puede verificar identidad |
| 3 | Nombre no coincide | CN/SAN distintos al dominio | Posible MITM o mala config |
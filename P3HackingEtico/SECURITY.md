# Aviso de seguridad — `Web_Talent-ScoutTech.rar`

> ⚠️ **PoC histórico — NO DESPLEGAR EN PRODUCCIÓN**

El archivo [`Web_Talent-ScoutTech.rar`](./Web_Talent-ScoutTech.rar) de este directorio contiene
el **código fuente original de la aplicación TalentScout** que fue auditada como
parte de la práctica de hacking ético del Proyecto 3.

## Por qué está aquí

Se incluye como **prueba de concepto (PoC)** adjunta al informe de pentest
([`pentest_report.md`](./pentest_report.md)) y al codelab
([`codelab.md`](./codelab.md)). Su propósito es **didáctico**: mostrar al
lector el código vulnerable que se auditó y cómo se remediaron los hallazgos
(SQL Injection, XSS almacenado, Broken Access Control, CSRF).

## ⚠️ Riesgos si se despliega tal cual

El código PHP contenido en el `.rar` **es vulnerable de forma intencionada** y
presenta, entre otros, los siguientes fallos documentados en el informe:

- **SQL Injection (Crítica)** en `auth.php` y `insert_player.php`.
- **XSS Almacenado (Alta)** en el sistema de comentarios.
- **Broken Access Control (Crítica)** por cookie `userId` no firmada.
- **CSRF (Media)** en integraciones con terceros.

Si alguien lo monta en un servidor accesible desde Internet, ese servidor
queda **expuesto a compromiso inmediato**.

## Qué hacer si quieres probarlo

Úsalo **solo en un entorno aislado** (máquina virtual sin red o segmento de
laboratorio), y aplica las remediaciones descritas en
[`pentest_report.md` §4](./pentest_report.md) antes de cualquier prueba. No
exponer a Internet ni a una red de producción.

## Contacto

Para reportar un problema de seguridad en este repositorio, abre un issue en
<https://github.com/karitsu2281/karitsu2281.github.io/issues>.

— Karitsu2281

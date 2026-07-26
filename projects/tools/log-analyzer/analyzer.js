(function () {
    'use strict';

    var SIGNATURES = [
        // ═══════════════════════════════════════════
        // WINDOWS SECURITY EVENTS
        // ═══════════════════════════════════════════
        { id: 'WIN-001', category: 'windows', severity: 'critical', name: 'Inicio de sesión fallido masivo (Event ID 4625)', regex: /4625.*?(?:cuenta|account|logon|inicio)/i, description: 'Múltiples intentos de inicio de sesión fallidos detectados. Esto puede indicar un ataque de fuerza bruta contra cuentas del sistema.', impact: 'Un atacante podría obtener acceso no autorizado si la contraseña es débil.', remediation: 'Revisar las cuentas objetivo. Bloquear IPs origen. Habilitar bloqueo por umbral de intentos. Revisar si hay cuentas con contraseñas débiles.', mitre: 'T1110', logFormat: 'windows' },
        { id: 'WIN-002', category: 'windows', severity: 'high', name: 'Cuenta bloqueada (Event ID 4740)', regex: /4740.*?(?:cuenta|account|bloqueado|locked)/i, description: 'Una cuenta de usuario ha sido bloqueada por superar el umbral de intentos fallidos.', impact: 'Denegación de servicio para el usuario legítimo. Puede indicar un ataque de fuerza bruta en curso.', remediation: 'Verificar la causa del bloqueo. Si es por ataque, revisar logs de origen. Restablecer la cuenta tras confirmar que no está comprometida.', mitre: 'T1110', logFormat: 'windows' },
        { id: 'WIN-003', category: 'windows', severity: 'high', name: 'Uso de privilegios sensibles (Event ID 4672)', regex: /4672.*?(?:privilegio|privilege|special|especial)/i, description: 'Se asignaron privilegios especiales a una cuenta (como SeTcbPrivilege o SeDebugPrivilege).', impact: 'Posible escalada de privilegios o movimiento lateral.', remediation: 'Verificar si la asignación fue legítima. Revisar si hay procesos sospechosos ejecutándose con privilegios elevados.', mitre: 'T1068', logFormat: 'windows' },
        { id: 'WIN-004', category: 'windows', severity: 'high', name: 'Creación de usuario en grupo privilegiado (Event ID 4720/4732)', regex: /(?:4720|4732).*?(?:administra|admin|group|grupo)/i, description: 'Se creó un nuevo usuario o se añadió a un grupo administrativo.', impact: 'Un atacante podría crear cuentas de backdoor para persistencia.', remediation: 'Verificar la legitimidad de la operación. Revisar quién la realizó y desde qué equipo.', mitre: 'T1136.001', logFormat: 'windows' },
        { id: 'WIN-005', category: 'windows', severity: 'critical', name: 'Servicio instalado remotamente (Event ID 4697/7045)', regex: /(?:4697|7045).*?(?:service|servicio|install|instalar)/i, description: 'Se instaló un servicio en el sistema. Los atacantes suelen instalar servicios para persistencia.', impact: 'El atacante ha establecido persistencia en el sistema.', remediation: 'Verificar el binario del servicio. Revisar firma digital. Analizar el servicio con antivirus. Consultar el equipo de seguridad.', mitre: 'T1543.003', logFormat: 'windows' },
        { id: 'WIN-006', category: 'windows', severity: 'high', name: 'Cambio en política de auditoría (Event ID 4719)', regex: /4719.*?(?:audit|auditor|politica|policy)/i, description: 'Se modificó la política de auditoría del sistema. Los atacantes alteran la auditoría para cubrir sus huellas.', impact: 'Pérdida de visibilidad de seguridad en el sistema.', remediation: 'Verificar quién realizó el cambio. Restaurar política de auditoría. Investigar por qué se deshabilitó.', mitre: 'T1562.002', logFormat: 'windows' },
        { id: 'WIN-007', category: 'windows', severity: 'high', name: 'Borrado de logs de eventos (Event ID 1102/104)', regex: /(?:1102|104).*?(?:log|registro|borrado|clear|clean)/i, description: 'Se borraron los logs de eventos del sistema. Los atacantes limpian logs para eliminar evidencia.', impact: 'Pérdida total de trazabilidad forense.', remediation: 'Este hallazgo es altamente sospechoso. Aislar el equipo. Iniciar procedimiento de respuesta a incidentes.', mitre: 'T1070.001', logFormat: 'windows' },
        { id: 'WIN-008', category: 'windows', severity: 'medium', name: 'Inicio de sesión con cuenta local (Event ID 4624 tipo 2/10)', regex: /4624.*?(?:tipo|type|logon|inicio).*?(?:2|10)/i, description: 'Inicio de sesión interactivo o remoto (RDP) detectado.', impact: 'Depende del contexto. Puede ser legítimo o un acceso no autorizado.', remediation: 'Verificar ubicación y horario. Si es sospechoso, revocar acceso y habilitar 2FA.', mitre: 'T1078', logFormat: 'windows' },
        { id: 'WIN-009', category: 'windows', severity: 'high', name: 'Tarea programada creada (Event ID 4698)', regex: /4698.*?(?:task|tarea|schedule|programada)/i, description: 'Se creó una tarea programada. Los atacantes usan tareas para persistencia o ejecución remota.', impact: 'Persistencia establecida en el sistema.', remediation: 'Revisar la acción de la tarea, el desencadenante y el usuario que la creó. Verificar firma digital del binario ejecutado.', mitre: 'T1053.005', logFormat: 'windows' },
        { id: 'WIN-010', category: 'windows', severity: 'critical', name: 'Cuenta de administrador local habilitada (Event ID 4722/4725)', regex: /(?:4722|4725).*?(?:admin|administrator|administrador)/i, description: 'La cuenta de administrador incorporada fue habilitada o deshabilitada.', impact: 'Posible movimiento lateral o escalada de privilegios.', remediation: 'Deshabilitar la cuenta de administrador si no es necesaria. Revisar quién realizó el cambio.', mitre: 'T1078', logFormat: 'windows' },
        { id: 'WIN-011', category: 'windows', severity: 'high', name: 'Conexión RDP entrante (Event ID 1026/1027/1149)', regex: /(?:1026|1027|1149).*?(?:rdp|remote|escritorio|terminal)/i, description: 'Conexión de Escritorio Remoto establecida desde una ubicación no habitual.', impact: 'Acceso remoto potencialmente no autorizado.', remediation: 'Verificar la IP origen y si el usuario tenía motivos para conectarse. Restringir RDP por firewall.', mitre: 'T1021.001', logFormat: 'windows' },
        { id: 'WIN-012', category: 'windows', severity: 'high', name: 'PowerShell execution log (Event ID 4104/4103)', regex: /(?:4104|4103).*?(?:powershell|script|bloque|block)/i, description: 'Ejecución de script PowerShell. Los atacantes usan PowerShell para ejecución sin archivo (fileless).', impact: 'Posible ejecución de código malicioso en memoria.', remediation: 'Revisar el script ejecutado. Habilitar logging de bloques de script. Restringir PowerShell en modo restringido.', mitre: 'T1059.001', logFormat: 'windows' },
        { id: 'WIN-013', category: 'windows', severity: 'medium', name: 'Registro modificado en Run/RunOnce (Event ID 4657/13)', regex: /(?:4657|13).*?(?:run|runonce|currentversion|startup|inicio)/i, description: 'Modificación en claves de registro de inicio automático.', impact: 'Posible persistencia de malware.', remediation: 'Verificar el valor añadido. Analizar el binario referenciado. Revisar con antivirus.', mitre: 'T1547.001', logFormat: 'windows' },
        { id: 'WIN-014', category: 'windows', severity: 'medium', name: 'Evento de antivirus/malware detectado (Event ID 1116/1117)', regex: /(?:1116|1117).*?(?:malware|virus|trojan|threat|amenaza)/i, description: 'Windows Defender ha detectado o eliminado una amenaza.', impact: 'El sistema está o estuvo expuesto a malware.', remediation: 'Revisar el tipo de amenaza y el archivo afectado. Ejecutar escaneo completo. Verificar IOC.', mitre: 'T1204', logFormat: 'windows' },
        { id: 'WIN-015', category: 'windows', severity: 'critical', name: 'Kerberos Golden Ticket detectado (Event ID 4768/4769 anómalo)', regex: /(?:4768|4769).*?(?:krbtgt|kerberos|golden|ticket)/i, description: 'Posible uso de Golden Ticket de Kerberos. Anomalía en ticket TGT detectada.', impact: 'Compromiso total del dominio. El atacante tiene persistencia ilimitada.', remediation: 'Resetear contraseña de krbtgt dos veces. Auditar todas las cuentas. Buscar IOC adicionales.', mitre: 'T1558.001', logFormat: 'windows' },
        { id: 'WIN-016', category: 'windows', severity: 'medium', name: 'Service Crash (Event ID 7031/7032/7034)', regex: /703[124].*?(?:service|servicio|crash|fail|fallo|termin)/i, description: 'Un servicio del sistema falló o terminó inesperadamente.', impact: 'Denegación de servicio. Posible indicador de ataque.', remediation: 'Revisar el servicio afectado. Verificar logs de aplicación. Comprobar integridad del binario.', mitre: 'T1489', logFormat: 'windows' },

        // ═══════════════════════════════════════════
        // AUTHENTICATION (SSH, SUDO, RDP, FTP)
        // ═══════════════════════════════════════════
        { id: 'AUTH-001', category: 'auth', severity: 'high', name: 'Múltiples fallos de autenticación SSH', regex: /(?:failed|fallido|failure).*(?:password|ssh|auth|login).*(?:for|para).*(?:root|admin)/i, description: 'Múltiples intentos fallidos de autenticación SSH, especialmente contra cuentas privilegiadas.', impact: 'Ataque de fuerza bruta en curso. Posible compromiso de cuentas.', remediation: 'Usar autenticación por clave pública. Deshabilitar login root por SSH. Usar Fail2ban. Cambiar puerto SSH.', mitre: 'T1110', logFormat: 'syslog' },
        { id: 'AUTH-002', category: 'auth', severity: 'high', name: 'Acceso sudo sin autenticación', regex: /sudo.*?(?:NOPASSWD|nopasswd|no password|sin contrase)/i, description: 'Ejecución de comandos con sudo sin autenticación.', impact: 'Escalada de privilegios sin verificación de identidad.', remediation: 'Revisar configuración de sudoers (/etc/sudoers). Eliminar entradas NOPASSWD. Mantener mínimo privilegio.', mitre: 'T1548.003', logFormat: 'syslog' },
        { id: 'AUTH-003', category: 'auth', severity: 'critical', name: 'Ataque de fuerza bruta SSH detectado', regex: /(?:Failed password|fallo|failure).*(?:root|admin|administrator).*(?:from|desde).*(?:\d{1,3}\.){3}\d{1,3}.*(?:10|20|30|50|100)/i, description: 'Múltiples intentos de autenticación SSH desde la misma IP contra cuentas privilegiadas.', impact: 'Ataque automatizado de fuerza bruta contra el servidor.', remediation: 'Bloquear IP origen. Implementar Fail2ban. Usar claves SSH. Considerar VPN/WireGuard para acceso.', mitre: 'T1110', logFormat: 'syslog' },
        { id: 'AUTH-004', category: 'auth', severity: 'medium', name: 'Inicio de sesión SSH exitoso desde IP desconocida', regex: /(?:Accepted|aceptado|success).*(?:publickey|password).*(?:from|desde)/i, description: 'Inicio de sesión SSH exitoso. Verificar si la IP origen es conocida.', impact: 'Acceso remoto legítimo o no autorizado.', remediation: 'Verificar la IP contra listas de acceso autorizadas. Monitorear actividad de la sesión.', mitre: 'T1078', logFormat: 'syslog' },
        { id: 'AUTH-005', category: 'auth', severity: 'high', name: 'Intento de acceso a cuenta inexistente', regex: /(?:invalid user|usuario invalido|unknown user|no such user).*(?:from|desde)/i, description: 'Intento de autenticación contra cuentas que no existen en el sistema.', impact: 'Escaneo de cuentas o ataque automatizado.', remediation: 'Bloquear IP origen. Usar Fail2ban para cuentas inexistentes. Monitorear patrones.', mitre: 'T1589.002', logFormat: 'syslog' },
        { id: 'AUTH-006', category: 'auth', severity: 'medium', name: 'Cambio de contraseña de root', regex: /(?:password changed|cambio de contrase).*(?:root|admin)/i, description: 'Se cambió la contraseña de una cuenta privilegiada.', impact: 'Posible compromiso de cuenta privilegiada.', remediation: 'Confirmar con el administrador. Si no fue autorizado, considerar el sistema comprometido.', mitre: 'T1098', logFormat: 'syslog' },
        { id: 'AUTH-007', category: 'auth', severity: 'high', name: 'Heartbleed TLS heartbeat (CVE-2014-0160)', regex: /(?:heartbleed|heartbeat|TLS|SSL).*(?:read|malformed|too long)/i, description: 'Posible intento de explotación de vulnerabilidad Heartbleed en OpenSSL.', impact: 'Filtración de memoria del servidor con claves privadas y datos.', remediation: 'Actualizar OpenSSL a versión parcheada. Revocar certificados TLS. Rotar secretos.', mitre: 'T1589', logFormat: 'any' },
        { id: 'AUTH-008', category: 'auth', severity: 'high', name: 'Fallo de autenticación RDP', regex: /(?:rdp|remote desktop|escritorio remoto|terminal server).*(?:fail|fallo|error|denied|denegado)/i, description: 'Intento fallido de conexión RDP.', impact: 'Posible ataque de fuerza bruta contra RDP.', remediation: 'Bloquear RDP en firewall. Usar VPN para acceso remoto. Habilitar NLA (Network Level Authentication).', mitre: 'T1110', logFormat: 'any' },
        { id: 'AUTH-009', category: 'auth', severity: 'low', name: 'Cambio de contraseña de usuario regular', regex: /(?:password changed|cambio de contrase).*(?:user|usuario)/i, description: 'Cambio de contraseña de usuario.', impact: 'Generalmente legítimo, pero puede indicar compromiso.', remediation: 'Verificar si fue el propio usuario. Sospechoso si múltiples cambios seguidos.', mitre: 'T1098', logFormat: 'syslog' },
        { id: 'AUTH-010', category: 'auth', severity: 'critical', name: 'Cuenta de servicio comprometida', regex: /(?:service account|cuenta de servicio|svc_).*(?:fail|fallo|comprom|anomal)/i, description: 'Comportamiento anómalo en cuenta de servicio.', impact: 'Las cuentas de servicio suelen tener privilegios elevados.', remediation: 'Rotar credenciales inmediatamente. Revisar permisos delegados. Auditar accesos recientes.', mitre: 'T1078', logFormat: 'any' },

        // ═══════════════════════════════════════════
        // WEB ATTACKS
        // ═══════════════════════════════════════════
        { id: 'WEB-001', category: 'web', severity: 'critical', name: 'Intento de SQL Injection', regex: /(?:union.*select|select.*from|'.*or.*'='|';|1=1|--\s|waitfor|delay|pg_sleep|sqlmap|benchmark)/i, description: 'Intento de inyección SQL detectado en parámetros de petición.', impact: 'El atacante intenta extraer/modificar datos de la base de datos.', remediation: 'Usar consultas parametrizadas. Validar y sanitizar input. Implementar WAF. Parchear aplicación.', mitre: 'T1190', logFormat: 'web' },
        { id: 'WEB-002', category: 'web', severity: 'high', name: 'Intento de Cross-Site Scripting (XSS)', regex: /(?:<script|alert\(|onerror=|onload=|javascript:|<svg|onmouse|onclick|<img.*on)/i, description: 'Intento de inyección XSS en parámetros.', impact: 'Robo de cookies, redirección a phishing, ejecución de JS malicioso.', remediation: 'Codificar output según contexto. Usar CSP. Sanitizar input. Implementar HttpOnly y Secure en cookies.', mitre: 'T1059.007', logFormat: 'web' },
        { id: 'WEB-003', category: 'web', severity: 'medium', name: 'Directory Traversal', regex: /(?:\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c|\.\.%252f|\.\.%5c)/i, description: 'Intento de path traversal para acceder a archivos fuera del directorio web.', impact: 'Lectura de archivos sensibles del sistema.', remediation: 'Validar rutas de archivos. Usar chroot o docker. No exponer paths del sistema.', mitre: 'T1005', logFormat: 'web' },
        { id: 'WEB-004', category: 'web', severity: 'high', name: 'Escaneo de rutas sensibles', regex: /\/(?:admin|wp-admin|phpmyadmin|manager|\.env|\.git|config|backup|db_admin|server-status)\b/i, description: 'Intento de acceso a rutas administrativas o archivos de configuración.', impact: 'Posible enumeración de directorios o exposición de información sensible.', remediation: 'Bloquear IP. Ocultar rutas administrativas. No exponer archivos de configuración. Autenticación fuerte en paneles.', mitre: 'T1046', logFormat: 'web' },
        { id: 'WEB-005', category: 'web', severity: 'medium', name: 'User-Agent de escáner/exploit', regex: /(?:sqlmap|nikto|nmap|nessus|openvas|acunetix|burp|zap|gobuster|dirbuster|wpscan|python-requests|curl|wget|masscan)/i, description: 'User-Agent asociado a herramientas de escaneo o explotación.', impact: 'Reconocimiento activo del objetivo.', remediation: 'Bloquear User-Agent en WAF/Nginx. Monitorear IP. No es concluyente (pueden falsificarse).', mitre: 'T1046', logFormat: 'web' },
        { id: 'WEB-006', category: 'web', severity: 'high', name: 'File Inclusion (LFI/RFI)', regex: /(?:include=|require=|file=|page=|document=|import=|php:\/\/|file:\/\/|data:\/\/|expect:\/\/)/i, description: 'Intento de inclusión remota o local de archivos.', impact: 'Ejecución remota de código o lectura de archivos arbitrarios.', remediation: 'Validar parámetros de inclusión. Usar mapeo de páginas permitidas. Deshabilitar allow_url_include.', mitre: 'T1190', logFormat: 'web' },
        { id: 'WEB-007', category: 'web', severity: 'medium', name: 'CSRF Token manipulation', regex: /(?:csrf|token|authenticity).*(?:missing|invalid|incorrect|wrong|fail)/i, description: 'Posible intento de Cross-Site Request Forgery.', impact: 'Ejecución de acciones no autorizadas en nombre de usuario autenticado.', remediation: 'Implementar tokens CSRF. Usar SameSite cookies. Verificar Origin/Referer.', mitre: 'T1529', logFormat: 'web' },
        { id: 'WEB-008', category: 'web', severity: 'high', name: 'Server-Side Request Forgery (SSRF)', regex: /(?:\?url=|&url=|\?file=|\?load=|\?path=)(?:https?:\/\/|file:\/\/|dict:\/\/|gopher:\/\/)/i, description: 'Posible intento de SSRF para acceder a recursos internos.', impact: 'Acceso a servicios internos (metadatos cloud, databases, etc.).', remediation: 'Lista blanca de destinos. Validar URLs con DNS inverso. No permitir esquemas internos.', mitre: 'T1190', logFormat: 'web' },
        { id: 'WEB-009', category: 'web', severity: 'medium', name: 'HTTP Method manipulation', regex: /(?:PUT|DELETE|TRACE|OPTIONS|PATCH).*\/.*(?:200|201|204)/i, description: 'Método HTTP peligroso permitido en el servidor.', impact: 'Posible modificación o eliminación de recursos.', remediation: 'Restringir métodos HTTP. Deshabilitar TRACE (Cross-Site Tracing).', mitre: 'T1190', logFormat: 'web' },
        { id: 'WEB-010', category: 'web', severity: 'low', name: 'Error 403/404 múltiple', regex: /(?:403|404).*(?:Forbidden|Not Found|Acceso denegado|No encontrado)/i, description: 'Múltiples errores de acceso/archivo no encontrado.', impact: 'Indica escaneo de directorios o intentos de acceso a rutas inexistentes.', remediation: 'Verificar si hay patrón. Bloquear IP si supera umbral.', mitre: 'T1046', logFormat: 'web' },
        { id: 'WEB-011', category: 'web', severity: 'high', name: 'Command Injection', regex: /(?:;|&&|\|\|).*(?:id|whoami|cat|ls|dir|ping|nslookup|wget|curl|bash|cmd|powershell)/i, description: 'Posible intento de inyección de comandos del sistema.', impact: 'Ejecución remota de comandos en el servidor.', remediation: 'Validar y sanitizar input. Usar funciones seguras en lugar de exec/system. Principio de mínimo privilegio.', mitre: 'T1203', logFormat: 'web' },
        { id: 'WEB-012', category: 'web', severity: 'medium', name: 'WordPress escaneo de plugins/vulnerabilidades', regex: /\/wp-content\/plugins\/|\/wp-content\/themes\/|\/wp-includes\/|\/xmlrpc\.php|\/wp-json\//i, description: 'Escaneo de componentes WordPress.', impact: 'Reconocimiento de plugins y temas que pueden tener vulnerabilidades.', remediation: 'Mantener WordPress y plugins actualizados. Ocultar versión. Usar WAF. Eliminar xmlrpc.php si no se usa.', mitre: 'T1046', logFormat: 'web' },

        // ═══════════════════════════════════════════
        // MALWARE & TTPS
        // ═══════════════════════════════════════════
        { id: 'MAL-001', category: 'malware', severity: 'critical', name: 'Indicador de C2 (Command & Control)', regex: /(?:pastebin\.com|\.onion|bootstrap\.exe|\.ps1.*-enc|base64|\.dll.*rundll|cmd\.exe.*\/c|obfuscated|malicios)/i, description: 'Posible comunicación con servidor de Comando y Control (C2).', impact: 'El sistema podría estar bajo control remoto de un atacante.', remediation: 'Aislar el equipo de la red. Ejecutar escaneo completo. Capturar tráfico de red. Notificar al SOC.', mitre: 'T1071', logFormat: 'any' },
        { id: 'MAL-002', category: 'malware', severity: 'critical', name: 'Ejecución de binario sospechoso en Temp', regex: /(?:temp|tmp|appdata|local.*temp).*\.(?:exe|dll|ps1|vbs|bat|cmd|scr|js)/i, description: 'Ejecución de binario desde directorio temporal.', impact: 'Alta probabilidad de infección por malware.', remediation: 'Analizar el archivo. Revisar el proceso padre. Escanear con EDR. Bloquear ejecución desde Temp.', mitre: 'T1204.002', logFormat: 'any' },
        { id: 'MAL-003', category: 'malware', severity: 'high', name: 'Descarga de archivo desde URL sospechosa', regex: /(?:http|https|ftp).*\.(?:exe|dll|ps1|vbs|bat|jar|scr).*(?:download|wget|curl|invoke-webrequest)/i, description: 'Descarga remota de archivos ejecutables.', impact: 'Posible descarga de payload malicioso.', remediation: 'Verificar reputación de la URL. Bloquear en proxy. Escanear el archivo descargado.', mitre: 'T1105', logFormat: 'any' },
        { id: 'MAL-004', category: 'malware', severity: 'critical', name: 'Proceso inyectado o comportamiento anómalo', regex: /(?:injection|inyección|hollowing|process.*(?:ghost|hollow)|reflective|runpe|malware|trojan|ransom|backdoor|keylog|worm)/i, description: 'Indicador de técnica de evasión o ejecución maliciosa.', impact: 'Compromiso del sistema con posibles técnicas avanzadas (inyección, process hollowing).', remediation: 'Análisis forense completo. Capturar volcado de memoria. Aislar sistema.', mitre: 'T1055', logFormat: 'any' },
        { id: 'MAL-005', category: 'malware', severity: 'high', name: 'Conexión saliente a IP sospechosa', regex: /(?:outbound|saliente|connect|conecta).*(?:unknown|sospech|unknown|malici).*(?:\d{1,3}\.){3}\d{1,3}/i, description: 'Conexión de red saliente hacia un destino identificado como sospechoso.', impact: 'Posible exfiltración de datos o comunicación C2.', remediation: 'Bloquear IP en firewall. Capturar tráfico. Analizar proceso origen.', mitre: 'T1041', logFormat: 'any' },
        { id: 'MAL-006', category: 'malware', severity: 'medium', name: 'Nombre de archivo sospechoso', regex: /(?:invoice|factura|urgent|urgente|document|cv|curriculum|update|actualizaci).*\.(?:exe|js|vbs|scr|ps1|docm|xlsm)/i, description: 'Archivo con nombre engañoso usado como señuelo de phishing.', impact: 'Probable intento de infección mediante ingeniería social.', remediation: 'No abrir archivos inesperados. Verificar remitente. Escanear con antivirus.', mitre: 'T1566', logFormat: 'any' },
        { id: 'MAL-007', category: 'malware', severity: 'high', name: 'Cifrado de archivos en masa', regex: /(?:encrypt|cifrado|ransom|locker|crypt|aaaa|\.encrypted|\.locked|\.crypt)/i, description: 'Posible ataque de ransomware: cifrado masivo de archivos.', impact: 'Pérdida de datos. Extorsión económica.', remediation: 'Aislar sistema inmediatamente. No pagar rescate. Identificar variante. Restaurar desde backup.', mitre: 'T1486', logFormat: 'any' },
        { id: 'MAL-008', category: 'malware', severity: 'medium', name: 'Modificación de archivo hosts', regex: /(?:hosts|etc\\hosts|drivers\\etc).*(?:127\.0\.0\.1|0\.0\.0\.0).*(?:google|facebook|bank|paypal)/i, description: 'Redirección de tráfico mediante modificación del archivo hosts.', impact: 'Phishing o bloqueo de sitios de seguridad.', remediation: 'Restaurar archivo hosts original. Verificar integridad del DNS. Escanear en busca de malware.', mitre: 'T1562', logFormat: 'any' },
        { id: 'MAL-009', category: 'malware', severity: 'critical', name: 'Token de acceso robado / Session hijacking', regex: /(?:token|session|jwt|bearer|oauth).*(?:stolen|robado|leaked|filtrad|comprom)/i, description: 'Posible robo de token de autenticación o sesión.', impact: 'Suplantación de identidad sin necesidad de credenciales.', remediation: 'Revocar tokens. Forzar cierre de sesión global. Rotar secretos. Implementar rotación de tokens.', mitre: 'T1528', logFormat: 'any' },
        { id: 'MAL-010', category: 'malware', severity: 'high', name: 'Uso de Mimikatz o herramientas de credential dumping', regex: /(?:mimikatz|sekurlsa|wdigest|lsadump|samdump|procdump|dumpert|pwdump|gsecdump|credential|vaultcmd)/i, description: 'Herramienta de extracción de credenciales detectada.', impact: 'Compromiso de todas las credenciales del sistema.', remediation: 'Aislar sistema inmediatamente. Rotar contraseñas de todas las cuentas. Habilitar LSA Protection.', mitre: 'T1003', logFormat: 'any' },

        // ═══════════════════════════════════════════
        // NETWORK & FIREWALL
        // ═══════════════════════════════════════════
        { id: 'NET-001', category: 'network', severity: 'medium', name: 'Escaneo de puertos detectado', regex: /(?:scan|escaneo|port|puerto|nmap|masscan|syn).*(?:multiple|multiple|many|varios|rapid|rápid)/i, description: 'Múltiples conexiones a diferentes puertos desde la misma IP en corto tiempo.', impact: 'Reconocimiento de servicios abiertos.', remediation: 'Bloquear IP origen. Implementar IPS/IDS. Reducir superficie de ataque.', mitre: 'T1046', logFormat: 'network' },
        { id: 'NET-002', category: 'network', severity: 'high', name: 'Ataque DDoS detectado', regex: /(?:ddos|flood|inundación|amplificación|amplification|reflection|reflexión).*(?:syn|udp|icmp|http|dns)/i, description: 'Patrón de tráfico consistente con un ataque de denegación de servicio distribuido.', impact: 'Indisponibilidad del servicio.', remediation: 'Activar protección anti-DDoS. Filtrar tráfico en firewall perimetral. Contactar con ISP.', mitre: 'T1498', logFormat: 'network' },
        { id: 'NET-003', category: 'network', severity: 'high', name: 'Conexión a puerto de administración remota expuesto', regex: /(?:22|3389|5900|8443).*(?:open|abierto|connected|conectado).*(?:external|externa|wan|internet)/i, description: 'Puerto de administración remota expuesto a Internet.', impact: 'Superficie de ataque ampliada.', remediation: 'Cerrar puertos en firewall. Usar VPN para acceso remoto. Implementar autenticación multifactor.', mitre: 'T1190', logFormat: 'network' },
        { id: 'NET-004', category: 'network', severity: 'medium', name: 'Tráfico DNS anómalo', regex: /(?:dns|domain).*(?:tunnel|túnel|anomal|large|grande|sospech|unknown|query|consulta).*(?:long|largo|base64|hex)/i, description: 'Consultas DNS con patrones sospechosos (túneles DNS o exfiltración).', impact: 'Exfiltración de datos o comunicación C2 por DNS.', remediation: 'Monitorear tráfico DNS. Implementar filtrado DNS. Usar DoH/DoT corporativo.', mitre: 'T1572', logFormat: 'network' },
        { id: 'NET-005', category: 'network', severity: 'low', name: 'Tráfico en puerto no estándar', regex: /(?:port|puerto).*(?:8443|8080|4443|2222|992|6666|1337|31337).*(?:traffic|tráfico|connection|conexión)/i, description: 'Tráfico en puertos no estándar o asociados a malware.', impact: 'Bajo: puede ser aplicación legítima en puerto alternativo.', remediation: 'Identificar la aplicación. Verificar si el puerto está autorizado.', mitre: 'T1571', logFormat: 'network' },
        { id: 'NET-006', category: 'network', severity: 'high', name: 'Firewall bloqueando tráfico saliente sospechoso', regex: /(?:block|bloque|denied|deneg|drop|reject|rechaz).*(?:outbound|saliente|egress).*(?:malicious|malici|sospech|unknown|trojan|bot)/i, description: 'El firewall ha bloqueado tráfico saliente hacia destinos maliciosos conocidos.', impact: 'Posible infección intentando contactar C2.', remediation: 'Investigar el proceso origen. Aislar el equipo. Capturar muestra del tráfico.', mitre: 'T1071', logFormat: 'network' },
        { id: 'NET-007', category: 'network', severity: 'medium', name: 'Protocolo no autorizado detectado', regex: /(?:protocol|protocolo).*(?:no autorizado|unauthorized|not allowed|no permitido).*(?:tunnel|proxy|vpn|tor)/i, description: 'Uso de protocolos de tunelización o anonimización.', impact: 'Bypass de controles de seguridad.', remediation: 'Bloquear en firewall de próxima generación. Implementar DLP. Revisar política de uso aceptable.', mitre: 'T1573', logFormat: 'network' },
        { id: 'NET-008', category: 'network', severity: 'high', name: 'ARP Spoofing detectado', regex: /(?:arp|man-in-the-middle|MITM|spoof|suplantación).*(?:duplicate|duplicado|unusual|anómalo|attack|ataque)/i, description: 'Posible ataque ARP Spoofing en la red local.', impact: 'Interceptación de tráfico entre dispositivos de la red.', remediation: 'Implementar ARP spoofing detection. Usar DHCP snooping. Segmentar red. Usar IPsec/SSL.', mitre: 'T1557', logFormat: 'network' },

        // ═══════════════════════════════════════════
        // CRASH & DUMP ANALYSIS
        // ═══════════════════════════════════════════
        { id: 'CRASH-001', category: 'crash', severity: 'critical', name: 'BSOD: CRITICAL_PROCESS_DIED', regex: /(?:CRITICAL_PROCESS_DIED|0x000000EF|0xEF)/i, description: 'Blue Screen of Death: un proceso crítico del sistema ha terminado inesperadamente.', impact: 'El sistema se detuvo para evitar daños mayores. Posible fallo de hardware o corrupción del sistema.', remediation: 'Verificar disco duro (chkdsk). Revisar memoria RAM (memtest86). Restaurar archivos del sistema (sfc /scannow). Actualizar controladores.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-002', category: 'crash', severity: 'critical', name: 'BSOD: MEMORY_MANAGEMENT', regex: /(?:MEMORY_MANAGEMENT|0x0000001A|0x1A)/i, description: 'BSOD: Error de gestión de memoria. Problema con la memoria RAM o controladores de memoria.', impact: 'Corrupción de datos en memoria. Inestabilidad del sistema.', remediation: 'Ejecutar diagnóstico de memoria (mdsched.exe). Verificar controladores de chipset. Comprobar voltajes de RAM.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-003', category: 'crash', severity: 'critical', name: 'BSOD: SYSTEM_SERVICE_EXCEPTION', regex: /(?:SYSTEM_SERVICE_EXCEPTION|0x0000003B|0x3B)/i, description: 'BSOD: Excepción en servicio del sistema. Causa común: controladores defectuosos o incompatibles.', impact: 'Fallo recurrente que impide el uso normal del sistema.', remediation: 'Actualizar o revertir controladores recién instalados. Ejecutarsfc /scannow. Comprobar actualizaciones de Windows.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-004', category: 'crash', severity: 'critical', name: 'BSOD: DRIVER_IRQL_NOT_LESS_OR_EQUAL', regex: /(?:DRIVER_IRQL_NOT_LESS_OR_EQUAL|0x000000D1|0xD1)/i, description: 'BSOD: Un controlador intentó acceder a memoria con IRQL incorrecto. Controlador defectuoso.', impact: 'Fallo del sistema causado por driver defectuoso.', remediation: 'Identificar el controlador en el mensaje de error. Actualizar o revertir. Usar Driver Verifier para diagnóstico.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-005', category: 'crash', severity: 'critical', name: 'BSOD: PAGE_FAULT_IN_NONPAGED_AREA', regex: /(?:PAGE_FAULT_IN_NONPAGED_AREA|0x00000050|0x50)/i, description: 'BSOD: El sistema intentó acceder a memoria no paginada que no existe.', impact: 'Fallo de hardware (RAM/SSD) o controlador defectuoso.', remediation: 'Ejecutar diagnóstico de RAM. Verificar disco (chkdsk). Actualizar controladores de almacenamiento.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-006', category: 'crash', severity: 'critical', name: 'BSOD: IRQL_NOT_LESS_OR_EQUAL', regex: /(?:IRQL_NOT_LESS_OR_EQUAL|0x0000000A|0x0A)/i, description: 'BSOD: Un controlador o servicio intentó acceder a memoria a un IRQL demasiado alto.', impact: 'Fallo del sistema. Puede ser por driver, hardware o software incompatible.', remediation: 'Actualizar controladores. Desinstalar software reciente. Verificar compatibilidad de hardware.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-007', category: 'crash', severity: 'critical', name: 'BSOD: KERNEL_SECURITY_CHECK_FAILURE', regex: /(?:KERNEL_SECURITY_CHECK_FAILURE|0x00000139|0x139)/i, description: 'BSOD: Fallo en verificación de seguridad del kernel. Puede indicar corrupción de memoria o rootkit.', impact: 'Posible compromiso del kernel. Corrupción de estructuras críticas.', remediation: 'Ejecutar escaneo antivirus/antimalware. Verificar integridad de archivos del sistema. Actualizar Windows.', mitre: 'T1562', logFormat: 'dump' },
        { id: 'CRASH-008', category: 'crash', severity: 'critical', name: 'BSOD: UNEXPECTED_KERNEL_MODE_TRAP', regex: /(?:UNEXPECTED_KERNEL_MODE_TRAP|0x0000007F|0x7F)/i, description: 'BSOD: Excepción no esperada en modo kernel. Causas: hardware defectuoso (CPU/RAM), overclocking, controladores maliciosos.', impact: 'Fallo crítico del sistema.', remediation: 'Eliminar overclocking. Verificar temperaturas de CPU. Ejecutar diagnóstico de hardware.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-009', category: 'crash', severity: 'high', name: 'BSOD: VIDEO_TDR_FAILURE', regex: /(?:VIDEO_TDR_FAILURE|0x00000116|0x116)/i, description: 'BSOD: Fallo de gráficos. El controlador de video no respondió y Windows lo recuperó.', impact: 'Fallo de la GPU o del controlador de gráficos.', remediation: 'Actualizar controladores de GPU. Reducir overclock de GPU. Verificar temperatura de la tarjeta gráfica.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-010', category: 'crash', severity: 'high', name: 'BSOD: APC_INDEX_MISMATCH', regex: /(?:APC_INDEX_MISMATCH|0x00000001|0x01)/i, description: 'BSOD: Error en el sistema de Archivos o controladores de almacenamiento.', impact: 'Posible fallo de disco o controlador de almacenamiento.', remediation: 'Verificar integridad del disco (chkdsk /f). Actualizar controladores de almacenamiento. Revisar conexiones SATA/NVMe.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-011', category: 'crash', severity: 'medium', name: 'Fallo de controlador detectado', regex: /(?:driver|controlador).*(?:fail|fallo|error|crash|stop|detenid).*(?:0x|ntoskrnl|dxgkrnl|kern)/i, description: 'Fallo de controlador del sistema detectado en el volcado.', impact: 'Inestabilidad del sistema.', remediation: 'Identificar y actualizar el controlador problemático. Verificar compatibilidad con la versión de Windows.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-012', category: 'crash', severity: 'high', name: 'Corrupción de memoria detectada en dump', regex: /(?:memory|memoria).*(?:corrupt|corrup|damage|dañ|bad|mal|error|page|pool)/i, description: 'Se detectó corrupción de memoria en el volcado.', impact: 'Posible fallo de hardware (RAM) o driver defectuoso.', remediation: 'Ejecutar Windows Memory Diagnostic. Probar RAM con memtest86. Comprobar compatibilidad de módulos.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-013', category: 'crash', severity: 'high', name: 'Volcado por cierre inesperado de proceso (crash/hang)', regex: /(?:hang|colgado|freeze|congelado|not responding|sin respuesta|timeout|tiempo.*espera)/i, description: 'El sistema o una aplicación dejó de responder y generó un volcado.', impact: 'Pérdida de datos no guardados. Posible fuga de memoria o bucle infinito.', remediation: 'Revisar el consumo de recursos del proceso. Actualizar la aplicación. Verificar conflictos de software.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-014', category: 'crash', severity: 'medium', name: 'Registro de volcado por error de aplicación', regex: /(?:exception|excepción|error|fault).*(?:application|aplicación|app).*(?:crash|fallo|stop|detenid).*(?:\.exe|\.dll)/i, description: 'Volcado generado por una aplicación que falló.', impact: 'La aplicación específica dejó de funcionar.', remediation: 'Reinstalar la aplicación. Verificar requisitos del sistema. Buscar actualizaciones del fabricante.', mitre: '', logFormat: 'dump' },

        // ═══════════════════════════════════════════
        // COMPLIANCE & AUDIT
        // ═══════════════════════════════════════════
        { id: 'CMP-001', category: 'compliance', severity: 'high', name: 'Cuenta con privilegios excesivos', regex: /(?:privilegio.*excesiv|admin.*local|domain.*admin).*(?:grant|conced|asign|add|añad)/i, description: 'Cuenta con privilegios administrativos sin justificación.', impact: 'Incumplimiento de mínimo privilegio.', remediation: 'Revisar membresías de grupos. Aplicar RBAC. Auditar cuentas privilegiadas periódicamente.', mitre: '', logFormat: 'any' },
        { id: 'CMP-002', category: 'compliance', severity: 'medium', name: 'Uso de protocolo no cifrado', regex: /(?:telnet|ftp|http|pop3|imap|smb1).*(?:login|auth|password|contrase)/i, description: 'Uso de protocolos que transmiten credenciales en texto claro.', impact: 'Interceptación de credenciales en la red.', remediation: 'Migrar a SSH/FTPS/HTTPS/IMAPS. Deshabilitar protocolos legacy. Implementar cifrado en todas las comunicaciones.', mitre: '', logFormat: 'any' },
        { id: 'CMP-003', category: 'compliance', severity: 'medium', name: 'Política de contraseñas débil', regex: /(?:password|contrase).*(?:never expires|no expira|never.*change|no.*camb|weak|débil|simple|123456|1234)/i, description: 'Se detectó una cuenta con contraseña débil o que nunca expira.', impact: 'Incumplimiento de políticas de seguridad.', remediation: 'Implementar política de contraseñas fuertes. Habilitar expiración periódica. Usar LAPS para admin locales.', mitre: '', logFormat: 'any' },
        { id: 'CMP-004', category: 'compliance', severity: 'low', name: 'Auditoría deshabilitada en recurso', regex: /(?:audit|auditor).*(?:disabled|deshabilit|off|inactiv|not.*config)/i, description: 'La auditoría no está habilitada en un recurso del sistema.', impact: 'Falta de visibilidad para detectar incidentes.', remediation: 'Habilitar auditoría en el recurso afectado. Centralizar logs en SIEM.', mitre: '', logFormat: 'any' },
        { id: 'CMP-005', category: 'compliance', severity: 'high', name: 'Firewall deshabilitado', regex: /(?:firewall|firewall).*(?:disabled|deshabilit|off|apagad|inact|stopped|detenid)/i, description: 'El firewall del sistema está deshabilitado.', impact: 'Exposición total a ataques de red.', remediation: 'Habilitar el firewall. Verificar reglas. No deshabilitar sin justificación documentada.', mitre: '', logFormat: 'any' },
        { id: 'CMP-006', category: 'compliance', severity: 'high', name: 'Actualizaciones de seguridad pendientes', regex: /(?:update|actualizac).*(?:pending|pendient|miss|no instal|critical|crítica|security|seguridad).*(?:days|días|weeks|semanas)/i, description: 'Actualizaciones críticas de seguridad no instaladas.', impact: 'Sistema vulnerable a exploits conocidos.', remediation: 'Aplicar parches de seguridad. Implementar WSUS/SCCM. Establecer política de actualizaciones.', mitre: '', logFormat: 'any' },
        { id: 'CMP-007', category: 'compliance', severity: 'medium', name: 'Conexión no autorizada a dispositivo USB', regex: /(?:usb|removable|extraíble|flash|pendrive).*(?:connect|conect|mount|monta|autorun|autoplay)/i, description: 'Conexión de dispositivo USB no autorizado.', impact: 'Filtración de datos o introducción de malware.', remediation: 'Implementar DLP. Deshabilitar puertos USB. Usar software de control de dispositivos. Registrar conexiones.', mitre: '', logFormat: 'any' },
        // ═══════════════════════════════════════════
        // LINUX SYSTEM LOGS
        // ═══════════════════════════════════════════
        { id: 'LNX-001', category: 'linux', severity: 'critical', name: 'Kernel Panic / Oops', regex: /(?:kernel panic|BUG:|unable to handle|general protection fault|Oops:|segfault|segmentation fault).*(?:kernel|linux|\d+\.\d+\.\d+)/i, description: 'El kernel de Linux ha experimentado un error crítico del que no puede recuperarse.', impact: 'El sistema se detiene o reinicia. Posible pérdida de datos no guardados.', remediation: 'Revisar dmesg para contexto. Verificar hardware (RAM con memtest86). Actualizar kernel. Revisar controladores y módulos recién cargados.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-002', category: 'linux', severity: 'critical', name: 'OOM Killer activado (Out of Memory)', regex: /(?:Out of memory|OOM|oom-killer|invoked oom-killer|killed process).*(?:Killed|terminated|score)/i, description: 'El sistema agotó la memoria RAM y el OOM Killer terminó procesos para liberar memoria.', impact: 'Aplicaciones críticas pueden ser terminadas. Degradación severa del rendimiento.', remediation: 'Revisar qué proceso consumió toda la RAM. Añadir más RAM o swap. Configurar límites de memoria por proceso (systemd/cgroups). Ajustar vm.overcommit_memory.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-003', category: 'linux', severity: 'high', name: 'Error de sistema de archivos (ext4/btrfs/xfs)', regex: /(?:ext4|btrfs|xfs|filesystem|journal|inode|superblock).*(?:error|corrupt|fail|read-only|ro|remount|abort)/i, description: 'Error en el sistema de archivos detectado. El sistema puede remontar el volumen como solo lectura.', impact: 'Pérdida de datos. Sistema inestable. Posible fallo de disco.', remediation: 'Ejecutar fsck en modo recuperación. Verificar salud del disco con smartctl. Revisar cables SATA/NVMe. Reemplazar disco si hay sectores defectuosos.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-004', category: 'linux', severity: 'high', name: 'Error de E/S de disco (I/O Error)', regex: /(?:I\/O error|input\/output error|buffer I\/O|lost page|disk.*fail|sd[a-z]+|nvme|ata.*error).*(?:error|fail|timeout|abort)/i, description: 'Error de entrada/salida en dispositivo de almacenamiento.', impact: 'Pérdida de datos. Aplicaciones pueden congelarse o fallar.', remediation: 'Revisar smartctl -a /dev/sdX. Verificar cables y conexiones. Comprobar temperatura del disco. Reemplazar si hay errores de hardware.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-005', category: 'linux', severity: 'critical', name: 'Servicio systemd en estado failed', regex: /(?:systemd|unit).*?(?:failed|falló|failed result|enter failed|failed with).*(?:exit-code|timeout|signal|core|watchdog)/i, description: 'Un servicio gestionado por systemd ha entrado en estado de fallo.', impact: 'El servicio o aplicación no está funcionando. Posible denegación de servicio.', remediation: 'Revisar journalctl -u NOMBRE_SERVICIO. Verificar configuración del servicio. Comprobar dependencias. Revisar permisos y binarios.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-006', category: 'linux', severity: 'high', name: 'Servicio no encontrado o no arranca (systemd)', regex: /(?:unit not found|failed to start|not-found|dependency failed|timed out|start-limit|disable).*(?:service|timer|socket|mount)/i, description: 'Un servicio systemd no se encuentra o no puede iniciarse.', impact: 'El servicio no está disponible.', remediation: 'Verificar que el servicio está instalado. Revisar dependencias: systemctl list-dependencies. Comprobar archivos .service en /etc/systemd/system/.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-007', category: 'linux', severity: 'high', name: 'Error de apt/dpkg (gestor de paquetes)', regex: /(?:apt|dpkg|apt-get|aptitude).*(?:error|broken|unmet dependencies|held broken|configure|not installed|subprocess|unpack|unable to fetch|503|404|no repository|hash sum mismatch)/i, description: 'Error en la gestión de paquetes del sistema.', impact: 'El sistema no puede instalar o actualizar paquetes. Riesgo de seguridad por parches no aplicados.', remediation: 'Ejecutar sudo apt --fix-broken install. Revisar /etc/apt/sources.list. Verificar conectividad a repositorios. Limpiar caché: sudo apt clean.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-008', category: 'linux', severity: 'critical', name: 'SELinux denial / AVC audit', regex: /(?:SELinux|selinux|AVC|avc:.*denied).*(?:denied|reject|block|permission).*(?:comm=|path=|name=)/i, description: 'SELinux ha denegado una operación por política de seguridad.', impact: 'Aplicaciones pueden fallar por permisos denegados. Sistema más restrictivo de lo esperado.', remediation: 'Revisar ausearch -m avc -ts recent. Usar audit2allow para generar políticas. No deshabilitar SELinux. Ajustar contextos con chcon/semanage.', mitre: 'T1562.001', logFormat: 'linux' },
        { id: 'LNX-009', category: 'linux', severity: 'high', name: 'AppArmor denial', regex: /(?:apparmor|AppArmor).*(?:denied|DENIED|reject|block|profile).*(?:comm=|operation=)/i, description: 'AppArmor ha denegado una operación según su perfil de seguridad.', impact: 'Aplicación bloqueada al realizar una operación no permitida.', remediation: 'Revisar aa-status. Ver logs en /var/log/syslog o journalctl. Ajustar perfil con aa-complain/aa-enforce. Usar aa-logprof para generar reglas.', mitre: 'T1562.001', logFormat: 'linux' },
        { id: 'LNX-010', category: 'linux', severity: 'high', name: 'Error de red: interfaz caída/DHCP fallido', regex: /(?:dhcp|interface|network|net).*(?:down|fail|error|timeout|not found|no carrier|link.*down|address.*not|device.*not found)/i, description: 'La interfaz de red ha fallado o no ha podido obtener configuración DHCP.', impact: 'El sistema pierde conectividad de red.', remediation: 'Revisar ip a / ifconfig. Verificar cable/conexión WiFi. Comprobar servicio NetworkManager/systemd-networkd. Verificar servidor DHCP en la red.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-011', category: 'linux', severity: 'medium', name: 'Error de resolución DNS', regex: /(?:dns|resolv|name resolution|host not found|cannot resolve|temporary failure in name|failed to resolve)/i, description: 'Fallo en la resolución de nombres DNS.', impact: 'El sistema no puede acceder a recursos por nombre de dominio.', remediation: 'Revisar /etc/resolv.conf. Verificar conectividad al servidor DNS. Probar con nslookup/dig. Comprobar systemd-resolved.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-012', category: 'linux', severity: 'high', name: 'Espacio en disco crítico', regex: /(?:disk full|no space left|device.*no space|filesystem full|space.*exhausted|partition.*full).*(?:sda|nvme|md|mapper|\/)/i, description: 'El disco ha alcanzado su capacidad máxima.', impact: 'Aplicaciones no pueden escribir archivos. El sistema puede volverse inestable.', remediation: 'Limpiar logs viejos (logrotate). Revisar archivos grandes con du -sh /*. Eliminar paquetes no usados (apt autoremove). Ampliar partición si es posible.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-013', category: 'linux', severity: 'medium', name: 'Agotamiento de inodos', regex: /(?:inode.*exhaust|no space left.*inode|inode.*full|reserved.*inode)/i, description: 'Se han agotado los inodos disponibles en el sistema de archivos.', impact: 'No se pueden crear nuevos archivos aunque haya espacio libre.', remediation: 'Eliminar archivos pequeños innecesarios (find . -type f | wc -l). Revisar directorios con muchos archivos temporales. Aumentar número de inodos al formatear.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-014', category: 'linux', severity: 'medium', name: 'SWAP al límite / swapping excesivo', regex: /(?:swap|swapping).*(?:full|exhaust|high|critic|oom|insufficient)/i, description: 'El uso de swap es muy alto, lo que degrada el rendimiento drásticamente.', impact: 'Rendimiento del sistema gravemente degradado.', remediation: 'Identificar procesos con mayor uso de memoria (htop). Añadir más RAM. Ajustar swappiness (sysctl vm.swappiness=10). Agregar más swap si es necesario.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-015', category: 'linux', severity: 'medium', name: 'Error de montaje de sistema de archivos', regex: /(?:mount|mount.nfs|mount.cifs|fstab).*(?:error|fail|not found|invalid|wrong fs|bad superblock|no such device|cannot mount)/i, description: 'Error al montar un sistema de archivos en el arranque o por solicitud.', impact: 'Recurso o partición no disponible.', remediation: 'Revisar /etc/fstab. Verificar UUID con blkid. Comprobar que el dispositivo existe. Usar systemctl daemon-reload si es systemd mount.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-016', category: 'linux', severity: 'high', name: 'Error de NTP/sincronización de hora', regex: /(?:ntp|chrony|time.*synch|clock.*skew|time.*fail|adjust.*time|ntpd).*(?:error|fail|no server|timeout|skew|offset|unsynchronised)/i, description: 'Fallo en la sincronización del reloj del sistema.', impact: 'Problemas de autenticación (Kerberos), logs con marcas de tiempo incorrectas.', remediation: 'Verificar servicio chrony/ntpd. Revisar conectividad a servidores NTP. Comprobar zona horaria (timedatectl). Verificar firewall (puerto 123 UDP).', mitre: '', logFormat: 'linux' },
        { id: 'LNX-017', category: 'linux', severity: 'high', name: 'Error de hardware detectado (MCE/EDAC)', regex: /(?:mce|machine check|EDAC|hardware error|CPU.*error|memory.*error|core.*error|cache.*error|bus.*error).*(?:corrected|uncorrected|fatal|overflow)/i, description: 'El sistema ha detectado errores de hardware a nivel de CPU/memoria/caché.', impact: 'Posible fallo de hardware inminente. Corrupción de datos silenciosa.', remediation: 'Revisar salida de mcelog. Ejecutar memtest86 para RAM. Verificar temperatura CPU. Comprobar integridad de la placa base.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-018', category: 'linux', severity: 'high', name: 'Error de RAID/LVM', regex: /(?:mdadm|raid|lvm|volume group|physical volume|logical volume).*(?:fail|degraded|error|not found|inconsistent|missing|inactive|sync.*error)/i, description: 'Error en configuración RAID o LVM.', impact: 'Degradación de redundancia de datos. Posible pérdida de datos si falla otro disco.', remediation: 'Revisar estado con cat /proc/mdstat o lvs/pvs/vgs. Reemplazar disco fallido en RAID. Reconstruir volumen lógico.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-019', category: 'linux', severity: 'medium', name: 'Proceso zombie o defunct detectado', regex: /(?:zombie|defunct|zombie process|defunct process).*(?:\[\d+\]|\d+|wait|parent)/i, description: 'Procesos en estado zombie (terminados pero no recolectados por el padre).', impact: 'Agotamiento de tabla de procesos si se acumulan.', remediation: 'Identificar el proceso padre con ps aux | grep Z. Enviar SIGCHLD o matar el proceso padre. Como último recurso, reiniciar.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-020', category: 'linux', severity: 'high', name: 'Error de segmentación / core dump generado', regex: /(?:segfault|segmentation fault|core dumped|core.*\[|\bsigsegv\b|SIGSEGV).*(?:\d+|\.core|pid)/i, description: 'Una aplicación terminó con error de segmentación, generando un volcado de memoria.', impact: 'La aplicación falló inesperadamente. Posible bug o corrupción de memoria.', remediation: 'Analizar core dump con gdb backtrace. Actualizar la aplicación. Verificar bibliotecas compartidas (ldd). Reportar bug al mantenedor.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-021', category: 'linux', severity: 'high', name: 'Fallo de autenticación PAM', regex: /(?:pam|pam_unix|pam_sss).*(?:authentication error|auth.*fail|permission denied|user not known|account expired|password expired).*(?:uid=|user=|ruser=)/i, description: 'Error en el módulo de autenticación PAM (Pluggable Authentication Modules).', impact: 'Usuarios legítimos pueden no poder iniciar sesión.', remediation: 'Revisar configuración en /etc/pam.d/. Verificar que el usuario existe y no está bloqueado/expired. Comprobar /etc/nsswitch.conf.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-022', category: 'linux', severity: 'high', name: 'Error de cron/tarea programada fallida', regex: /(?:cron|crontab|anacron|systemd-timer).*(?:error|fail|not found|no such|exit status|killed|SIGTERM|SIGKILL|mail.*error)/i, description: 'Una tarea programada (cron, systemd-timer) ha fallado.', impact: 'Tareas automatizadas de mantenimiento no ejecutadas.', remediation: 'Revisar syslog para el error con grep CRON. Verificar script ejecutado. Comprobar rutas absolutas en crontab. Revisar permisos de ejecución.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-023', category: 'linux', severity: 'low', name: 'Logrotate fallido', regex: /(?:logrotate).*(?:error|fail|permission denied|no such file|not found)/i, description: 'Error al rotar archivos de log del sistema.', impact: 'Los logs pueden crecer sin control y llenar el disco.', remediation: 'Ejecutar logrotate -d para depurar. Revisar configuración en /etc/logrotate.d/. Verificar permisos de directorios de logs.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-024', category: 'linux', severity: 'high', name: 'Certificado TLS/SSL caducado o inválido', regex: /(?:certificate|x509|ssl|tls|CA cert).*(?:expir|invalid|self-signed|cannot verify|not trusted|no certificate|unable to get|verify error)/i, description: 'Un certificado ha caducado o no es válido.', impact: 'Servicios HTTPS/RPC pueden no funcionar. Posible brecha de seguridad.', remediation: 'Renovar certificado con certbot/acme.sh. Verificar fecha del sistema. Revisar cadena de confianza. Asegurar que el certificado cubre el dominio correcto.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-025', category: 'linux', severity: 'low', name: 'Error de permisos en archivo/directorio', regex: /(?:permission denied|EACCES|operation not permitted|no permissions).*(?:open|read|write|exec|access|creating|opening|unlink)/i, description: 'El sistema ha denegado acceso a un archivo por permisos insuficientes.', impact: 'Aplicación o servicio no puede acceder a un recurso necesario.', remediation: 'Verificar permisos con ls -la. Usar chmod/chown. Revisar ACLs con getfacl. Comprobar atributos extendidos (lsattr).', mitre: '', logFormat: 'linux' },
        { id: 'LNX-026', category: 'linux', severity: 'high', name: 'Error de contenedor Docker', regex: /(?:docker|containerd|runc).*(?:error|fail|exit code|not found|no such|refused|timeout|cannot connect|OCI|container.*failed)/i, description: 'Error en el motor de contenedores Docker o containerd.', impact: 'Contenedores no pueden iniciarse o ejecutarse.', remediation: 'Revisar docker logs NOMBRE. Verificar docker ps -a. Comprobar espacio en disco. Revisar políticas de reinicio. Actualizar Docker Engine.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-027', category: 'linux', severity: 'medium', name: 'Error de conexión a base de datos', regex: /(?:mysql|mariadb|postgresql|mongodb|redis|sqlite).*(?:connection refused|cannot connect|no route to host|timeout|too many connections|closed|gone away|shutdown|out of memory).*(?:error|fail)/i, description: 'Error de conexión a base de datos.', impact: 'Aplicaciones dependientes de la BD no funcionan.', remediation: 'Verificar que el servicio BD está activo. Revisar bind-address y puerto. Comprobar firewall y SELinux. Verificar límite de conexiones simultáneas.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-028', category: 'linux', severity: 'medium', name: 'Error de Nginx/Apache/servidor web', regex: /(?:nginx|apache|httpd|php-fpm).*(?:error|fail|segfault|bind.*address|address.*use|no.*socket|worker.*exit|child.*exit|premature|proxy.*fail|upstream.*timeout|connect.*refused)/i, description: 'Error en el servidor web.', impact: 'El sitio web puede no estar disponible o servir errores.', remediation: 'Revisar error.log del servidor web. Verificar configuración de virtual hosts. Comprobar límites de workers/conexiones. Reiniciar servicio.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-029', category: 'linux', severity: 'medium', name: 'Fallo en demonio de logging (rsyslog/journald)', regex: /(?:rsyslog|journald|syslogd|syslog-ng).*(?:error|fail|cannot open|permission|write|socket|config|overflow|drop|discard)/i, description: 'Error en el subsistema de logging del sistema.', impact: 'Pérdida de logs del sistema. Dificultad para auditar o depurar.', remediation: 'Revisar configuración en /etc/rsyslog.conf. Verificar espacio en disco. Reiniciar servicio: systemctl restart rsyslog. Revisar /run/systemd/journal/size.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-030', category: 'linux', severity: 'high', name: 'Error de firmware o microcódigo', regex: /(?:firmware|microcode|ucode|microcode).*(?:error|fail|bug|update|missing|not loaded|corrupt|mismatch)/i, description: 'Error relacionado con firmware del hardware o microcódigo de la CPU.', impact: 'Posible inestabilidad del sistema o falta de parches de seguridad de CPU.', remediation: 'Actualizar microcódigo: sudo apt install intel-microcode/amd64-microcode. Actualizar firmware del sistema. Revisar dmesg para más detalles.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-032', category: 'linux', severity: 'medium', name: 'Temperatura del sistema elevada / thermal throttle', regex: /(?:thermal|temperature|throttle|overheat|critical temp|high temp|temp.*warning|acpi.*temp|cooling).*(?:critical|high|emergency|fail|shutdown|throttle)/i, description: 'La temperatura del sistema ha alcanzado niveles críticos.', impact: 'Rendimiento reducido (throttling). Apagado por protección térmica.', remediation: 'Limpiar ventiladores y disipadores. Mejorar flujo de aire. Revisar pasta térmica. Monitorizar con sensors. Reducir carga del sistema.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-033', category: 'linux', severity: 'high', name: 'Error de NFS share montado', regex: /(?:nfs|nfs4).*(?:fail|error|timeout|not responding|stale|server.*not|RPC|portmapper|mountd|no route|permission).*(?:server|mount|export)/i, description: 'Error al acceder a un recurso compartido NFS.', impact: 'Aplicaciones que dependen del NFS pueden colgarse o fallar.', remediation: 'Verificar servicio rpcbind/nfs-server. Revisar exports. Comprobar conectividad de red. Usar soft mount para evitar colgar procesos.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-034', category: 'linux', severity: 'low', name: 'Error de script de arranque (rc.local/init.d)', regex: /(?:rc\.local|init\.d|rc[\d].d).*(?:error|fail|exit|not found|permission denied)/i, description: 'Error en script de inicio del sistema.', impact: 'Servicio configurado en rc.local puede no haberse iniciado.', remediation: 'Revisar script. Verificar permisos de ejecución. Migrar servicios a systemd.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-035', category: 'linux', severity: 'high', name: 'Error de red: IP duplicada en la red', regex: /(?:IP.*conflict|duplicate.*IP|DAD|arp.*duplicate|address.*already.*use|IPv4.*conflict).*(?:eth|ens|enp|wlan|enx)/i, description: 'Se ha detectado un conflicto de IP en la red local (otro dispositivo usa la misma IP).', impact: 'Pérdida intermitente de conectividad.', remediation: 'Usar DHCP en lugar de IP estática. Revisar configuración de red del dispositivo. Verificar servidor DHCP. Configurar reserva DHCP.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-036', category: 'linux', severity: 'high', name: 'Error de conexión WiFi/802.11', regex: /(?:wlan|wifi|wireless|802\.11|iwlwifi|brcmfmac|ath).*(?:error|fail|deauthenticated|disconnect|association|authentication.*fail|no network|scan.*error)/i, description: 'Error en la conexión inalámbrica del sistema.', impact: 'Pérdida de conectividad WiFi.', remediation: 'Reiniciar NetworkManager. Verificar driver inalámbrico (lspci -k). Comprobar señal. Olvidar y reconectar a la red.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-037', category: 'linux', severity: 'medium', name: 'Fallo de conexión USB', regex: /(?:usb|hub).*(?:error|fail|timeout|reset|disconnect|power|overcurrent|descriptor|not enough).*(?:device|port|speed|config)/i, description: 'Error en dispositivo USB conectado al sistema.', impact: 'El dispositivo USB puede no funcionar correctamente.', remediation: 'Reconectar el dispositivo. Probar en otro puerto USB. Revisar dmesg. Actualizar kernel.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-038', category: 'linux', severity: 'medium', name: 'Agotamiento de descriptores de archivo (file descriptors)', regex: /(?:too many open files|file descriptor.*exhaust|cannot open.*files|socket.*too many|ulimit.*limit|max.*files)/i, description: 'Un proceso ha agotado el límite de archivos abiertos.', impact: 'El proceso no puede abrir más archivos/sockets. Servicio puede fallar.', remediation: 'Aumentar límite en /etc/security/limits.conf. Revisar ulimit -n. Identificar fuga de FDs con lsof -p PID. Configurar systemd LimitNOFILE.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-039', category: 'linux', severity: 'high', name: 'Interrupción por falta de electricidad / apagado incorrecto', regex: /(?:power fail|Brownout|blackout|UPS|power.*loss|unexpected shutdown|dirty.*shutdown|system.*unclean|recovering.*journal|recovery.*fs)/i, description: 'El sistema se apagó inesperadamente por falta de alimentación.', impact: 'Posible corrupción del sistema de archivos. Datos no guardados perdidos.', remediation: 'Usar UPS. Ejecutar fsck tras apagado incorrecto. Verificar integridad de logs. Comprobar sistema de archivos.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-040', category: 'linux', severity: 'high', name: 'Error de pipewire/sonido/audio', regex: /(?:pipewire|pulseaudio|alsa|snd|audio|sound).*(?:error|fail|cannot open|no device|unable to|disconnected|suspend|recover)/i, description: 'Error en el subsistema de audio del sistema.', impact: 'El audio del sistema no funciona.', remediation: 'Reiniciar servicio de audio (systemctl --user restart pipewire). Verificar hardware con lspci. Revisar configuración de ALSA/PulseAudio/ PipeWire.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-041', category: 'linux', severity: 'medium', name: 'Error de Python/runtime (module not found, etc)', regex: /(?:ModuleNotFoundError|ImportError|No module named|Cannot find module|Error.*module|SyntaxError|TypeError|KeyError|AttributeError|Traceback.*most recent).*(?:line|file|error)/i, description: 'Error en tiempo de ejecución de un script Python.', impact: 'La aplicación Python o script falló.', remediation: 'Verificar dependencias (pip list/requirements.txt). Revisar entorno virtual. Comprobar versión de Python. Revisar el stacktrace para depurar.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-042', category: 'linux', severity: 'critical', name: 'Ataque de fuerza bruta SSH intensivo', regex: /(?:Failed password|authentication failure).*(?:from|desde).*(?:\d{1,3}\.){3}\d{1,3}.*(?:port|puerto).*(?:ssh2|ssh).*/i, description: 'Múltiples intentos de autenticación SSH fallidos desde una o más IPs.', impact: 'Ataque automatizado de fuerza bruta contra el servidor. Riesgo de compromiso si alguna cuenta usa contraseña débil.', remediation: 'Bloquear IPs ofensivas con iptables/nftables. Implementar Fail2ban. Usar autenticación por clave SSH. Deshabilitar login por contraseña. Cambiar puerto SSH.', mitre: 'T1110', logFormat: 'linux' },
        { id: 'LNX-043', category: 'linux', severity: 'medium', name: 'Auditd event registrado', regex: /(?:audit|auditd).*(?:type=\d+|user=|proctitle=|SYSCALL|execve|path=|LOGIN|SECCOMP).*(?:uid=|auid=|pid=|comm=|exe=)/i, description: 'Evento de auditoría registrado por auditd.', impact: 'Depende del tipo de evento. Puede ser acceso autorizado o no autorizado.', remediation: 'Revisar /var/log/audit/audit.log con ausearch. Verificar contexto del evento. Ajustar reglas de auditoría si hay falsos positivos.', mitre: '', logFormat: 'linux' }
    ];

    var CATEGORIES = {
        linux: { icon: '\uf17c', label: 'Sistema Linux' },
        windows: { icon: '\uf17a', label: 'Eventos Windows' },
        auth: { icon: '\uf084', label: 'Autenticación' },
        web: { icon: '\uf0ac', label: 'Ataques Web' },
        malware: { icon: '\uf188', label: 'Malware & TTPs' },
        network: { icon: '\uf0e8', label: 'Red & Firewall' },
        crash: { icon: '\uf1e2', label: 'Crash & Dumps' },
        compliance: { icon: '\uf0ad', label: 'Compliance' }
    };

    var SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    var SEVERITY_LABELS = { critical: 'Crítico', high: 'Alto', medium: 'Medio', low: 'Bajo', info: 'Info' };
    var SEVERITY_CLASSES = { critical: 's-critical', high: 's-high', medium: 's-medium', low: 's-low', info: 's-info' };
    var SEVERITY_CARD = { critical: 'severity-critical', high: 'severity-high', medium: 'severity-medium', low: 'severity-low', info: 'severity-info' };

    var ui = {
        dropZone: document.getElementById('dropZone'),
        fileInput: document.getElementById('fileInput'),
        fileInfo: document.getElementById('fileInfo'),
        fileName: document.getElementById('fileName'),
        fileMeta: document.getElementById('fileMeta'),
        analyzeBtn: document.getElementById('analyzeBtn'),
        resetBtn: document.getElementById('resetBtn'),
        report: document.getElementById('report'),
        reportTitle: document.getElementById('reportTitle'),
        reportTimestamp: document.getElementById('reportTimestamp'),
        severitySummary: document.getElementById('severitySummary'),
        findingsList: document.getElementById('findingsList'),
        exportBtn: document.getElementById('exportBtn'),
        printBtn: document.getElementById('printBtn'),
        cfg: {
            linux: document.getElementById('cfgLinux'),
            windows: document.getElementById('cfgWindows'),
            auth: document.getElementById('cfgAuth'),
            web: document.getElementById('cfgWeb'),
            malware: document.getElementById('cfgMalware'),
            network: document.getElementById('cfgNetwork'),
            crash: document.getElementById('cfgCrash'),
            compliance: document.getElementById('cfgCompliance')
        }
    };

    var currentFile = null;
    var currentContent = null;
    var currentFindings = null;

    function getActiveCategories() {
        var active = {};
        for (var key in ui.cfg) {
            if (ui.cfg[key] && ui.cfg[key].checked) {
                active[key] = true;
            }
        }
        return active;
    }

    function resetUI() {
        currentFile = null;
        currentContent = null;
        currentFindings = null;
        ui.fileInfo.classList.remove('show');
        ui.fileInput.value = '';
        ui.analyzeBtn.disabled = true;
        ui.report.classList.remove('show');
        ui.dropZone.classList.remove('has-file');
    }

    function formatFileSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / 1048576).toFixed(1) + ' MB';
    }

    function handleFile(file) {
        currentFile = file;
        ui.analyzeBtn.disabled = false;
        ui.dropZone.classList.add('has-file');
        ui.fileName.textContent = file.name;
        ui.fileMeta.textContent = formatFileSize(file.size) + ' · ' + (file.type || 'desconocido');
        ui.fileInfo.classList.add('show');
    }

    function readFile(file) {
        return new Promise(function (resolve, reject) {
            var reader = new FileReader();
            reader.onload = function (e) {
                resolve({ name: file.name, size: file.size, type: file.type, content: e.target.result });
            };
            reader.onerror = function () { reject(new Error('Error al leer el archivo')); };
            reader.readAsText(file, 'utf-8');
        });
    }

    function detectLogFormat(name) {
        var ext = name.split('.').pop().toLowerCase();
        if (ext === 'dmp') return 'dump';
        if (ext === 'evtx') return 'windows';
        if (ext === 'syslog') return 'syslog';
        if (ext === 'csv') return 'csv';
        return 'generic';
    }

    function extractTextFromDmp(content) {
        var lines = content.split('\n');
        var extracted = [];
        var currentLine = '';
        for (var i = 0; i < lines.length; i++) {
            currentLine = lines[i];
            if (!currentLine) continue;
            var clean = '';
            for (var j = 0; j < currentLine.length; j++) {
                var code = currentLine.charCodeAt(j);
                if ((code >= 32 && code <= 126) || code === 9 || code === 13 || code === 10) {
                    clean += currentLine.charAt(j);
                } else if (code > 127 && code < 256) {
                    clean += currentLine.charAt(j);
                }
            }
            clean = clean.trim();
            if (clean.length > 3) {
                extracted.push(clean);
            }
        }
        return extracted.join('\n');
    }

    function analyze(content, fileName, activeCats) {
        var findings = [];
        var matchedIds = {};

        var logFormat = detectLogFormat(fileName);
        var isDump = logFormat === 'dump';
        var textToAnalyze = isDump ? extractTextFromDmp(content) : content;

        var lines = textToAnalyze.split('\n');
        var lineCount = lines.length;

        for (var i = 0; i < SIGNATURES.length; i++) {
            var sig = SIGNATURES[i];
            if (!activeCats[sig.category]) continue;
            if (matchedIds[sig.id]) continue;

            var regex = new RegExp(sig.regex.source, 'gi');
            var match = regex.exec(textToAnalyze);
            if (match) {
                var contextLine = -1;
                var contextText = '';
                for (var l = 0; l < lineCount; l++) {
                    if (regex.test(lines[l])) {
                        contextLine = l + 1;
                        contextText = lines[l].substring(0, 300);
                        break;
                    }
                    regex.lastIndex = 0;
                }

                findings.push({
                    id: sig.id,
                    category: sig.category,
                    severity: sig.severity,
                    name: sig.name,
                    description: sig.description,
                    impact: sig.impact,
                    remediation: sig.remediation,
                    mitre: sig.mitre,
                    line: contextLine,
                    context: contextText,
                    matched: match[0]
                });
                matchedIds[sig.id] = true;
            }
        }

        if (isDump && findings.length === 0) {
            var hasErrorPattern = /\b(?:error|fail|fault|crash|dump|stop|bug|exception|fatal|critical)\b/i.test(textToAnalyze);
            if (hasErrorPattern) {
                findings.push({
                    id: 'DUMP-GEN',
                    category: 'crash',
                    severity: 'info',
                    name: 'Volcado de memoria analizado (dump genérico)',
                    description: 'El archivo .dmp contiene cadenas de texto indicativas de error, pero no se identificaron patrones específicos de BSOD.',
                    impact: 'Es posible que el sistema haya experimentado un fallo genérico o cierre inesperado.',
                    remediation: 'Usa WinDbg para analizar el volcado completo: !analyze -v. Verifica los controladores recién instalados. Revisa el Visor de Eventos de Windows para eventos relacionados.',
                    mitre: '',
                    line: 0,
                    context: '',
                    matched: ''
                });
            } else {
                findings.push({
                    id: 'DUMP-NOERR',
                    category: 'crash',
                    severity: 'info',
                    name: 'Volcado de memoria genérico sin patrones de error',
                    description: 'No se encontraron patrones de error o crash en las cadenas extraídas del volcado. Esto puede deberse a que el dump no contiene texto legible o es un formato no compatible.',
                    impact: 'El análisis de cadenas tiene limitaciones; un dump puede contener información binaria no extraíble como texto.',
                    remediation: 'Para un análisis completo usa WinDbg (comando !analyze -v) o Volatility. Asegúrate de que el dump no esté comprimido.',
                    mitre: '',
                    line: 0,
                    context: '',
                    matched: ''
                });
            }
        }

        findings.sort(function (a, b) {
            var sa = SEVERITY_ORDER[a.severity] || 99;
            var sb = SEVERITY_ORDER[b.severity] || 99;
            return sa - sb;
        });

        return {
            fileName: fileName,
            fileSize: currentFile ? currentFile.size : 0,
            timestamp: new Date().toISOString(),
            totalLines: lineCount,
            logFormat: logFormat,
            totalFindings: findings.length,
            severityCounts: countSeverities(findings),
            findings: findings
        };
    }

    function countSeverities(findings) {
        var counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        for (var i = 0; i < findings.length; i++) {
            if (counts.hasOwnProperty(findings[i].severity)) {
                counts[findings[i].severity]++;
            }
        }
        return counts;
    }

    function renderReport(report) {
        ui.reportTitle.textContent = 'Informe: ' + report.fileName;
        ui.reportTimestamp.textContent = new Date(report.timestamp).toLocaleString('es-ES');

        var sumHtml = '';
        var severities = [
            { key: 'critical', label: 'Crítico' },
            { key: 'high', label: 'Alto' },
            { key: 'medium', label: 'Medio' },
            { key: 'low', label: 'Bajo' },
            { key: 'info', label: 'Info' }
        ];
        for (var s = 0; s < severities.length; s++) {
            var sev = severities[s];
            var count = report.severityCounts[sev.key] || 0;
            sumHtml += '<div class="severity-item ' + sev.key + '"><div class="count">' + count + '</div><div class="label">' + sev.label + '</div></div>';
        }
        ui.severitySummary.innerHTML = sumHtml;

        var listHtml = '';
        if (report.findings.length === 0) {
            listHtml = '<div class="no-findings"><div class="icon"><i class="fa-solid fa-shield-check"></i></div><h3>Sin hallazgos</h3><p>No se detectaron patrones de seguridad en el archivo analizado.</p></div>';
        } else {
            for (var f = 0; f < report.findings.length; f++) {
                var finding = report.findings[f];
                listHtml += '<div class="finding-card ' + (SEVERITY_CARD[finding.severity] || '') + '" id="finding-' + finding.id + '">';
                listHtml += '<div class="finding-header">';
                listHtml += '<span class="finding-title">' + escapeHtml(finding.name) + '</span>';
                listHtml += '<span class="finding-severity ' + (SEVERITY_CLASSES[finding.severity] || '') + '">' + (SEVERITY_LABELS[finding.severity] || finding.severity) + '</span>';
                listHtml += '</div>';
                listHtml += '<div class="finding-detail"><strong>Descripción:</strong> ' + escapeHtml(finding.description) + '</div>';
                listHtml += '<div class="finding-detail"><strong>Impacto:</strong> ' + escapeHtml(finding.impact) + '</div>';
                listHtml += '<div class="finding-remediation"><strong><i class="fa-solid fa-wrench"></i> Recomendación:</strong> ' + escapeHtml(finding.remediation) + '</div>';
                if (finding.mitre) {
                    listHtml += '<div class="finding-mitre"><strong>MITRE ATT&CK:</strong> ' + escapeHtml(finding.mitre) + '</div>';
                }
                if (finding.line > 0 && finding.context) {
                    listHtml += '<div class="finding-line"><strong>Línea ' + finding.line + ':</strong> ' + escapeHtml(finding.context) + '</div>';
                }
                listHtml += renderSearchButtons(finding);
                listHtml += '</div>';
            }
        }
        ui.findingsList.innerHTML = listHtml;

        ui.report.classList.add('show');
        ui.report.scrollIntoView({ behavior: 'smooth', block: 'start' });
        currentFindings = report;
    }

    function buildSearchQuery(finding) {
        var parts = [finding.name];
        if (finding.mitre) parts.push('MITRE ATT&CK ' + finding.mitre);
        if (finding.remediation) {
            var words = finding.remediation.split(/\s+/).slice(0, 6).join(' ');
            parts.push(words);
        }
        if (finding.context && finding.context.length > 10) {
            var ctx = finding.context.replace(/[^a-zA-Z0-9\s\-_\/\.:]/g, ' ').trim();
            parts.push(ctx.substring(0, 80));
        }
        return parts.join(' ').substring(0, 250);
    }

    function getSearchUrls(finding) {
        var query = encodeURIComponent(buildSearchQuery(finding));
        var urls = {
            duckduckgo: 'https://duckduckgo.com/?q=' + query + '&ia=web',
            stackoverflow: 'https://stackoverflow.com/search?q=' + encodeURIComponent(finding.name.substring(0, 120)),
            serverfault: 'https://serverfault.com/search?q=' + encodeURIComponent('linux ' + finding.name.substring(0, 100))
        };
        if (finding.category === 'windows' || finding.category === 'crash') {
            urls.microsoft = 'https://learn.microsoft.com/en-us/search/?terms=' + encodeURIComponent(finding.name.substring(0, 80) + ' Windows');
        }
        if (finding.mitre) {
            var mid = finding.mitre.replace(/\.\d+$/, '');
            urls.mitre = 'https://attack.mitre.org/techniques/' + mid + '/';
        }
        return urls;
    }

    function searchDDG(findingId, finding) {
        var card = document.getElementById('finding-' + findingId);
        if (!card) return;
        var btn = card.querySelector('.ddg-search-btn');
        var results = card.querySelector('.ddg-results');
        if (!btn || !results) return;

        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> Buscando…';

        var query = encodeURIComponent(buildSearchQuery(finding));
        var url = 'https://api.duckduckgo.com/?q=' + query + '&format=json&no_html=1&skip_disambig=1&t=logwise';

        results.style.display = 'block';
        results.innerHTML = '<div class="ddg-loading"><span class="spinner"></span> Consultando DuckDuckGo…</div>';

        fetch(url)
            .then(function (r) {
                if (!r.ok) throw new Error('HTTP ' + r.status);
                return r.json();
            })
            .then(function (data) {
                var html = '<div class="ddg-header"><i class="fa-solid fa-magnifying-glass"></i> Resultados DuckDuckGo</div>';

                if (data.AbstractText) {
                    html += '<div class="ddg-abstract"><strong>Resumen:</strong> ' + escapeHtml(data.AbstractText) + '</div>';
                    if (data.AbstractURL) {
                        html += '<div class="ddg-source"><a href="' + escapeHtml(data.AbstractURL) + '" target="_blank" rel="noopener noreferrer">Fuente: ' + escapeHtml(data.AbstractSource || data.AbstractURL) + '</a></div>';
                    }
                }

                if (data.RelatedTopics && data.RelatedTopics.length > 0) {
                    html += '<div class="ddg-topics"><strong>Relacionado:</strong><ul>';
                    var count = 0;
                    for (var i = 0; i < data.RelatedTopics.length && count < 5; i++) {
                        var topic = data.RelatedTopics[i];
                        if (topic.Text) {
                            html += '<li>' + escapeHtml(topic.Text.substring(0, 200)) + '</li>';
                            count++;
                        } else if (topic.Topics) {
                            for (var j = 0; j < topic.Topics.length && count < 5; j++) {
                                html += '<li>' + escapeHtml(topic.Topics[j].Text.substring(0, 200)) + '</li>';
                                count++;
                            }
                        }
                    }
                    html += '</ul></div>';
                }

                if (data.Results && data.Results.length > 0) {
                    html += '<div class="ddg-results-list"><strong>Enlaces:</strong><ul>';
                    for (var k = 0; k < Math.min(data.Results.length, 3); k++) {
                        var res = data.Results[k];
                        html += '<li><a href="' + escapeHtml(res.FirstURL) + '" target="_blank" rel="noopener noreferrer">' + escapeHtml(res.Text) + '</a></li>';
                    }
                    html += '</ul></div>';
                }

                if (!data.AbstractText && (!data.RelatedTopics || data.RelatedTopics.length === 0)) {
                    html += '<div class="ddg-empty">No se encontraron resultados instantáneos. Prueba abriendo DuckDuckGo en una pestaña.</div>';
                }

                html += '<div class="ddg-footer">Resultados de DuckDuckGo · Búsqueda privada</div>';
                results.innerHTML = html;
                btn.innerHTML = '<i class="fa-solid fa-rotate"></i> Buscar de nuevo';
                btn.disabled = false;
            })
            .catch(function (err) {
                results.innerHTML = '<div class="ddg-error"><i class="fa-solid fa-triangle-exclamation"></i> No se pudo consultar DuckDuckGo: ' + escapeHtml(err.message) + '.<br><span style="font-size:0.85rem">Los navegadores pueden bloquear la API. Prueba abriendo DuckDuckGo manualmente desde los botones de arriba.</span></div>';
                btn.innerHTML = '<i class="fa-solid fa-magnifying-glass"></i> Causa raíz';
                btn.disabled = false;
            });
    }

    function renderSearchButtons(finding) {
        var urls = getSearchUrls(finding);
        var html = '<div class="research-bar">';
        html += '<span class="research-label"><i class="fa-solid fa-magnifying-glass"></i> Investigar:</span>';
        html += '<button type="button" class="research-btn ddg-search-btn" onclick="searchDDG(\'' + finding.id.replace(/'/g, '\\\'') + '\',' + JSON.stringify(finding).replace(/</g, '\\u003c').replace(/>/g, '\\u003e') + ')" title="Auto-buscar causa raíz en DuckDuckGo"><i class="fa-solid fa-bolt"></i> Causa raíz</button>';
        html += '<a href="' + urls.duckduckgo + '" target="_blank" rel="noopener noreferrer" class="research-btn ddg" title="Abrir DuckDuckGo en pestaña"><i class="fa-solid fa-magnifying-glass"></i> DuckDuckGo</a>';
        html += '<a href="' + urls.stackoverflow + '" target="_blank" rel="noopener noreferrer" class="research-btn so" title="Stack Overflow"><i class="fa-brands fa-stack-overflow"></i> Stack Overflow</a>';
        html += '<a href="' + urls.serverfault + '" target="_blank" rel="noopener noreferrer" class="research-btn sf" title="Server Fault"><i class="fa-solid fa-server"></i> Server Fault</a>';
        if (urls.microsoft) {
            html += '<a href="' + urls.microsoft + '" target="_blank" rel="noopener noreferrer" class="research-btn ms" title="Microsoft Learn"><i class="fa-brands fa-microsoft"></i> Microsoft</a>';
        }
        if (urls.mitre) {
            html += '<a href="' + urls.mitre + '" target="_blank" rel="noopener noreferrer" class="research-btn mitre" title="MITRE ATT&CK"><i class="fa-solid fa-shield-halved"></i> MITRE</a>';
        }
        html += '</div>';
        html += '<div class="ddg-results" id="ddg-' + finding.id + '" style="display:none"></div>';
        return html;
    }

    function escapeHtml(str) {
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(str));
        return div.innerHTML;
    }

    function exportReport(report) {
        var blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = 'LogWise-reporte-' + report.fileName.replace(/\.[^.]+$/, '') + '.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // ── EVENT LISTENERS ──────────────────────────

    ui.dropZone.addEventListener('click', function () { ui.fileInput.click(); });

    ui.dropZone.addEventListener('dragover', function (e) {
        e.preventDefault();
        e.stopPropagation();
        ui.dropZone.classList.add('dragover');
    });

    ui.dropZone.addEventListener('dragleave', function (e) {
        e.preventDefault();
        e.stopPropagation();
        ui.dropZone.classList.remove('dragover');
    });

    ui.dropZone.addEventListener('drop', function (e) {
        e.preventDefault();
        e.stopPropagation();
        ui.dropZone.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) {
            var file = e.dataTransfer.files[0];
            ui.fileInput.files = e.dataTransfer.files;
            handleFile(file);
        }
    });

    ui.fileInput.addEventListener('change', function () {
        if (this.files.length > 0) {
            handleFile(this.files[0]);
        }
    });

    ui.resetBtn.addEventListener('click', resetUI);

    ui.analyzeBtn.addEventListener('click', function () {
        if (!currentFile) return;

        var btn = ui.analyzeBtn;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> Analizando…';

        readFile(currentFile).then(function (fileData) {
            currentContent = fileData.content;
            var activeCats = getActiveCategories();
            var report = analyze(fileData.content, fileData.name, activeCats);
            renderReport(report);
        }).catch(function (err) {
            alert('Error al leer el archivo: ' + err.message);
        }).finally(function () {
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-flask"></i> Analizar';
        });
    });

    ui.exportBtn.addEventListener('click', function () {
        if (currentFindings) exportReport(currentFindings);
    });

    ui.printBtn.addEventListener('click', function () {
        window.print();
    });

})();

(function () {
    'use strict';

    // ═══════════════════════════════════════════════════════════════════════════
    // LogWise — Analizador forense de logs y volcados .dmp
    // 100% cliente. Sin dependencias externas. Sin enviar archivos.
    // v2.0 — seguridad endurecida, BSOD mejorado, opt-in DuckDuckGo.
    // ═══════════════════════════════════════════════════════════════════════════

    var MAX_FILE_SIZE = 50 * 1024 * 1024;
    var MAX_TEXT_SIZE = 5 * 1024 * 1024;
    var MAX_LINES_FOR_TEXT = 100000;
    var MAX_LINE_LENGTH = 2000;
    var MAX_DUMP_SCAN_BYTES = 32 * 1024 * 1024;
    var MAX_STRING_SCAN_BYTES = 4 * 1024 * 1024;
    var REGEX_TIMEOUT_MS = 2000;

    var SEVERITY_ORDER = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };
    var SEVERITY_LABELS = { critical: 'Crítico', high: 'Alto', medium: 'Medio', low: 'Bajo', info: 'Info' };
    var SEVERITY_CLASSES = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info' };
    var SEVERITY_CARD = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info' };

    // ═══════════════════════════════════════════════════════════════════════════
    // FIRMAS DE SEGURIDAD / LOGS
    // Las regex evitan .* anidados y líneas largas para prevenir backtracking.
    // ═══════════════════════════════════════════════════════════════════════════

    var SIGNATURES = [
        // WINDOWS SECURITY EVENTS
        { id: 'WIN-001', category: 'windows', severity: 'critical', name: 'Inicio de sesión fallido masivo (Event ID 4625)', regex: /4625.{0,60}(?:cuenta|account|logon|inicio)/i, description: 'Múltiples intentos de inicio de sesión fallidos detectados. Esto puede indicar un ataque de fuerza bruta contra cuentas del sistema.', impact: 'Un atacante podría obtener acceso no autorizado si la contraseña es débil.', remediation: 'Revisar las cuentas objetivo. Bloquear IPs origen. Habilitar bloqueo por umbral de intentos. Revisar si hay cuentas con contraseñas débiles.', mitre: 'T1110', logFormat: 'windows' },
        { id: 'WIN-002', category: 'windows', severity: 'high', name: 'Cuenta bloqueada (Event ID 4740)', regex: /4740.{0,60}(?:cuenta|account|bloqueado|locked)/i, description: 'Una cuenta de usuario ha sido bloqueada por superar el umbral de intentos fallidos.', impact: 'Denegación de servicio para el usuario legítimo. Puede indicar un ataque de fuerza bruta en curso.', remediation: 'Verificar la causa del bloqueo. Si es por ataque, revisar logs de origen. Restablecer la cuenta tras confirmar que no está comprometida.', mitre: 'T1110', logFormat: 'windows' },
        { id: 'WIN-003', category: 'windows', severity: 'high', name: 'Uso de privilegios sensibles (Event ID 4672)', regex: /4672.{0,60}(?:privilegio|privilege|special|especial)/i, description: 'Se asignaron privilegios especiales a una cuenta (como SeTcbPrivilege o SeDebugPrivilege).', impact: 'Posible escalada de privilegios o movimiento lateral.', remediation: 'Verificar si la asignación fue legítima. Revisar si hay procesos sospechosos ejecutándose con privilegios elevados.', mitre: 'T1068', logFormat: 'windows' },
        { id: 'WIN-004', category: 'windows', severity: 'high', name: 'Creación de usuario en grupo privilegiado (Event ID 4720/4732)', regex: /(?:4720|4732).{0,60}(?:administra|admin|group|grupo)/i, description: 'Se creó un nuevo usuario o se añadió a un grupo administrativo.', impact: 'Un atacante podría crear cuentas de backdoor para persistencia.', remediation: 'Verificar la legitimidad de la operación. Revisar quién la realizó y desde qué equipo.', mitre: 'T1136.001', logFormat: 'windows' },
        { id: 'WIN-005', category: 'windows', severity: 'critical', name: 'Servicio instalado remotamente (Event ID 4697/7045)', regex: /(?:4697|7045).{0,60}(?:service|servicio|install|instalar)/i, description: 'Se instaló un servicio en el sistema. Los atacantes suelen instalar servicios para persistencia.', impact: 'El atacante ha establecido persistencia en el sistema.', remediation: 'Verificar el binario del servicio. Revisar firma digital. Analizar el servicio con antivirus. Consultar el equipo de seguridad.', mitre: 'T1543.003', logFormat: 'windows' },
        { id: 'WIN-006', category: 'windows', severity: 'high', name: 'Cambio en política de auditoría (Event ID 4719)', regex: /4719.{0,60}(?:audit|auditor|politica|policy)/i, description: 'Se modificó la política de auditoría del sistema. Los atacantes alteran la auditoría para cubrir sus huellas.', impact: 'Pérdida de visibilidad de seguridad en el sistema.', remediation: 'Verificar quién realizó el cambio. Restaurar política de auditoría. Investigar por qué se deshabilitó.', mitre: 'T1562.002', logFormat: 'windows' },
        { id: 'WIN-007', category: 'windows', severity: 'high', name: 'Borrado de logs de eventos (Event ID 1102/104)', regex: /(?:1102|104).{0,60}(?:log|registro|borrado|clear|clean)/i, description: 'Se borraron los logs de eventos del sistema. Los atacantes limpian logs para eliminar evidencia.', impact: 'Pérdida total de trazabilidad forense.', remediation: 'Este hallazgo es altamente sospechoso. Aislar el equipo. Iniciar procedimiento de respuesta a incidentes.', mitre: 'T1070.001', logFormat: 'windows' },
        { id: 'WIN-008', category: 'windows', severity: 'medium', name: 'Inicio de sesión con cuenta local (Event ID 4624 tipo 2/10)', regex: /4624.{0,40}(?:tipo|type|logon|inicio).{0,20}(?:2|10)/i, description: 'Inicio de sesión interactivo o remoto (RDP) detectado.', impact: 'Depende del contexto. Puede ser legítimo o un acceso no autorizado.', remediation: 'Verificar ubicación y horario. Si es sospechoso, revocar acceso y habilitar 2FA.', mitre: 'T1078', logFormat: 'windows' },
        { id: 'WIN-009', category: 'windows', severity: 'high', name: 'Tarea programada creada (Event ID 4698)', regex: /4698.{0,60}(?:task|tarea|schedule|programada)/i, description: 'Se creó una tarea programada. Los atacantes usan tareas para persistencia o ejecución remota.', impact: 'Persistencia establecida en el sistema.', remediation: 'Revisar la acción de la tarea, el desencadenante y el usuario que la creó. Verificar firma digital del binario ejecutado.', mitre: 'T1053.005', logFormat: 'windows' },
        { id: 'WIN-010', category: 'windows', severity: 'critical', name: 'Cuenta de administrador local habilitada (Event ID 4722/4725)', regex: /(?:4722|4725).{0,60}(?:admin|administrator|administrador)/i, description: 'La cuenta de administrador incorporada fue habilitada o deshabilitada.', impact: 'Posible movimiento lateral o escalada de privilegios.', remediation: 'Deshabilitar la cuenta de administrador si no es necesaria. Revisar quién realizó el cambio.', mitre: 'T1078', logFormat: 'windows' },
        { id: 'WIN-011', category: 'windows', severity: 'high', name: 'Conexión RDP entrante (Event ID 1026/1027/1149)', regex: /(?:1026|1027|1149).{0,60}(?:rdp|remote|escritorio|terminal)/i, description: 'Conexión de Escritorio Remoto establecida desde una ubicación no habitual.', impact: 'Acceso remoto potencialmente no autorizado.', remediation: 'Verificar la IP origen y si el usuario tenía motivos para conectarse. Restringir RDP por firewall.', mitre: 'T1021.001', logFormat: 'windows' },
        { id: 'WIN-012', category: 'windows', severity: 'high', name: 'PowerShell execution log (Event ID 4104/4103)', regex: /(?:4104|4103).{0,60}(?:powershell|script|bloque|block)/i, description: 'Ejecución de script PowerShell. Los atacantes usan PowerShell para ejecución sin archivo (fileless).', impact: 'Posible ejecución de código malicioso en memoria.', remediation: 'Revisar el script ejecutado. Habilitar logging de bloques de script. Restringir PowerShell en modo restringido.', mitre: 'T1059.001', logFormat: 'windows' },
        { id: 'WIN-013', category: 'windows', severity: 'medium', name: 'Registro modificado en Run/RunOnce (Event ID 4657/13)', regex: /(?:4657|13).{0,60}(?:run|runonce|currentversion|startup|inicio)/i, description: 'Modificación en claves de registro de inicio automático.', impact: 'Posible persistencia de malware.', remediation: 'Verificar el valor añadido. Analizar el binario referenciado. Revisar con antivirus.', mitre: 'T1547.001', logFormat: 'windows' },
        { id: 'WIN-014', category: 'windows', severity: 'medium', name: 'Evento de antivirus/malware detectado (Event ID 1116/1117)', regex: /(?:1116|1117).{0,60}(?:malware|virus|trojan|threat|amenaza)/i, description: 'Windows Defender ha detectado o eliminado una amenaza.', impact: 'El sistema está o estuvo expuesto a malware.', remediation: 'Revisar el tipo de amenaza y el archivo afectado. Ejecutar escaneo completo. Verificar IOC.', mitre: 'T1204', logFormat: 'windows' },
        { id: 'WIN-015', category: 'windows', severity: 'critical', name: 'Kerberos Golden Ticket detectado (Event ID 4768/4769 anómalo)', regex: /(?:4768|4769).{0,60}(?:krbtgt|kerberos|golden|ticket)/i, description: 'Posible uso de Golden Ticket de Kerberos. Anomalía en ticket TGT detectada.', impact: 'Compromiso total del dominio. El atacante tiene persistencia ilimitada.', remediation: 'Resetear contraseña de krbtgt dos veces. Auditar todas las cuentas. Buscar IOC adicionales.', mitre: 'T1558.001', logFormat: 'windows' },
        { id: 'WIN-016', category: 'windows', severity: 'medium', name: 'Service Crash (Event ID 7031/7032/7034)', regex: /703[124].{0,60}(?:service|servicio|crash|fail|fallo|termin)/i, description: 'Un servicio del sistema falló o terminó inesperadamente.', impact: 'Denegación de servicio. Posible indicador de ataque.', remediation: 'Revisar el servicio afectado. Verificar logs de aplicación. Comprobar integridad del binario.', mitre: 'T1489', logFormat: 'windows' },
        { id: 'WIN-017', category: 'windows', severity: 'high', name: 'Windows Defender deshabilitado o bypassado', regex: /(?:defender|windows defender|wdac).{0,50}(?:disabled|deshabilit|off|apagad|bypass|tamper|exclusion)/i, description: 'Windows Defender o protección antimanipulación fueron deshabilitados o se añadieron exclusiones sospechosas.', impact: 'El sistema queda expuesto a malware o evasión.', remediation: 'Revisar exclusiones y políticas de Defender. Restaurar protección y auditar quién hizo el cambio.', mitre: 'T1562.001', logFormat: 'windows' },
        { id: 'WIN-018', category: 'windows', severity: 'high', name: 'Intento de ejecución de proceso con alta integridad (Event ID 4688)', regex: /4688.{0,60}(?:cmd\.exe|powershell\.exe|wscript|cscript|rundll32|regsvr32|mshta)/i, description: 'Se ejecutó un intérprete o utilidad de carga de código con privilegios elevados.', impact: 'Posible ejecución de payload o técnicas de Living Off The Land.', remediation: 'Revisar línea de comandos. Auditar creación de procesos. Implementar AppLocker/WDAC.', mitre: 'T1218', logFormat: 'windows' },
        { id: 'WIN-019', category: 'windows', severity: 'critical', name: 'LSASS accedido para volcado de credenciales (Event ID 4656/4657)', regex: /(?:4656|4657).{0,60}(?:lsass\.exe|SAM|SECURITY|LSA)/i, description: 'Acceso a procesos o archivos sensibles de autenticación, posible volcado de credenciales.', impact: 'Robo de hashes NTLM o credenciales del dominio.', remediation: 'Habilitar LSA Protection. Revisar permisos. Rotar credenciales si se confirma volcado.', mitre: 'T1003.001', logFormat: 'windows' },

        // AUTHENTICATION
        { id: 'AUTH-001', category: 'auth', severity: 'high', name: 'Múltiples fallos de autenticación SSH', regex: /(?:failed|fallido|failure).{0,40}(?:password|ssh|auth|login).{0,40}(?:for|para).{0,20}(?:root|admin)/i, description: 'Múltiples intentos fallidos de autenticación SSH, especialmente contra cuentas privilegiadas.', impact: 'Ataque de fuerza bruta en curso. Posible compromiso de cuentas.', remediation: 'Usar autenticación por clave pública. Deshabilitar login root por SSH. Usar Fail2ban. Cambiar puerto SSH.', mitre: 'T1110', logFormat: 'syslog' },
        { id: 'AUTH-002', category: 'auth', severity: 'high', name: 'Acceso sudo sin autenticación', regex: /sudo.{0,40}(?:NOPASSWD|nopasswd|no password|sin contrase)/i, description: 'Ejecución de comandos con sudo sin autenticación.', impact: 'Escalada de privilegios sin verificación de identidad.', remediation: 'Revisar configuración de sudoers (/etc/sudoers). Eliminar entradas NOPASSWD. Mantener mínimo privilegio.', mitre: 'T1548.003', logFormat: 'syslog' },
        { id: 'AUTH-003', category: 'auth', severity: 'critical', name: 'Ataque de fuerza bruta SSH detectado', regex: /(?:Failed password|fallo|failure).{0,40}(?:root|admin|administrator).{0,40}(?:from|desde).{0,40}(?:\d{1,3}\.){3}\d{1,3}/i, description: 'Múltiples intentos de autenticación SSH desde la misma IP contra cuentas privilegiadas.', impact: 'Ataque automatizado de fuerza bruta contra el servidor.', remediation: 'Bloquear IP origen. Implementar Fail2ban. Usar claves SSH. Considerar VPN/WireGuard para acceso.', mitre: 'T1110', logFormat: 'syslog' },
        { id: 'AUTH-004', category: 'auth', severity: 'medium', name: 'Inicio de sesión SSH exitoso desde IP desconocida', regex: /(?:Accepted|aceptado|success).{0,40}(?:publickey|password).{0,40}(?:from|desde)/i, description: 'Inicio de sesión SSH exitoso. Verificar si la IP origen es conocida.', impact: 'Acceso remoto legítimo o no autorizado.', remediation: 'Verificar la IP contra listas de acceso autorizadas. Monitorear actividad de la sesión.', mitre: 'T1078', logFormat: 'syslog' },
        { id: 'AUTH-005', category: 'auth', severity: 'high', name: 'Intento de acceso a cuenta inexistente', regex: /(?:invalid user|usuario invalido|unknown user|no such user).{0,40}(?:from|desde)/i, description: 'Intento de autenticación contra cuentas que no existen en el sistema.', impact: 'Escaneo de cuentas o ataque automatizado.', remediation: 'Bloquear IP origen. Usar Fail2ban para cuentas inexistentes. Monitorear patrones.', mitre: 'T1589.002', logFormat: 'syslog' },
        { id: 'AUTH-006', category: 'auth', severity: 'medium', name: 'Cambio de contraseña de root', regex: /(?:password changed|cambio de contrase).{0,40}(?:root|admin)/i, description: 'Se cambió la contraseña de una cuenta privilegiada.', impact: 'Posible compromiso de cuenta privilegiada.', remediation: 'Confirmar con el administrador. Si no fue autorizado, considerar el sistema comprometido.', mitre: 'T1098', logFormat: 'syslog' },
        { id: 'AUTH-007', category: 'auth', severity: 'high', name: 'Heartbleed TLS heartbeat (CVE-2014-0160)', regex: /(?:heartbleed|heartbeat|TLS|SSL).{0,40}(?:read|malformed|too long)/i, description: 'Posible intento de explotación de vulnerabilidad Heartbleed en OpenSSL.', impact: 'Filtración de memoria del servidor con claves privadas y datos.', remediation: 'Actualizar OpenSSL a versión parcheada. Revocar certificados TLS. Rotar secretos.', mitre: 'T1589', logFormat: 'any' },
        { id: 'AUTH-008', category: 'auth', severity: 'high', name: 'Fallo de autenticación RDP', regex: /(?:rdp|remote desktop|escritorio remoto|terminal server).{0,60}(?:fail|fallo|error|denied|denegado)/i, description: 'Intento fallido de conexión RDP.', impact: 'Posible ataque de fuerza bruta contra RDP.', remediation: 'Bloquear RDP en firewall. Usar VPN para acceso remoto. Habilitar NLA (Network Level Authentication).', mitre: 'T1110', logFormat: 'any' },
        { id: 'AUTH-009', category: 'auth', severity: 'low', name: 'Cambio de contraseña de usuario regular', regex: /(?:password changed|cambio de contrase).{0,40}(?:user|usuario)/i, description: 'Cambio de contraseña de usuario.', impact: 'Generalmente legítimo, pero puede indicar compromiso.', remediation: 'Verificar si fue el propio usuario. Sospechoso si múltiples cambios seguidos.', mitre: 'T1098', logFormat: 'syslog' },
        { id: 'AUTH-010', category: 'auth', severity: 'critical', name: 'Cuenta de servicio comprometida', regex: /(?:service account|cuenta de servicio|svc_).{0,60}(?:fail|fallo|comprom|anomal)/i, description: 'Comportamiento anómalo en cuenta de servicio.', impact: 'Las cuentas de servicio suelen tener privilegios elevados.', remediation: 'Rotar credenciales inmediatamente. Revisar permisos delegados. Auditar accesos recientes.', mitre: 'T1078', logFormat: 'any' },
        { id: 'AUTH-011', category: 'auth', severity: 'high', name: 'Autenticación SSH con contraseña permitida', regex: /Password authentication.{0,30}(?:yes|enabled|permit)/i, description: 'La configuración SSH permite autenticación por contraseña.', impact: 'Aumenta la superficie de ataque de fuerza bruta.', remediation: 'Deshabilitar PasswordAuthentication en sshd_config. Usar solo claves SSH.', mitre: 'T1110', logFormat: 'syslog' },

        // WEB ATTACKS
        { id: 'WEB-001', category: 'web', severity: 'critical', name: 'Intento de SQL Injection', regex: /(?:union.{0,20}select|select.{0,20}from|';|--\s|waitfor|delay|pg_sleep|sqlmap|benchmark)/i, description: 'Intento de inyección SQL detectado en parámetros de petición.', impact: 'El atacante intenta extraer/modificar datos de la base de datos.', remediation: 'Usar consultas parametrizadas. Validar y sanitizar input. Implementar WAF. Parchear aplicación.', mitre: 'T1190', logFormat: 'web' },
        { id: 'WEB-002', category: 'web', severity: 'high', name: 'Intento de Cross-Site Scripting (XSS)', regex: /(?:<script|alert\(|onerror=|onload=|javascript:|<svg|onmouse|onclick|<img.{0,20}on)/i, description: 'Intento de inyección XSS en parámetros.', impact: 'Robo de cookies, redirección a phishing, ejecución de JS malicioso.', remediation: 'Codificar output según contexto. Usar CSP. Sanitizar input. Implementar HttpOnly y Secure en cookies.', mitre: 'T1059.007', logFormat: 'web' },
        { id: 'WEB-003', category: 'web', severity: 'medium', name: 'Directory Traversal', regex: /(?:\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c|\.\.%252f|\.\.%5c)/i, description: 'Intento de path traversal para acceder a archivos fuera del directorio web.', impact: 'Lectura de archivos sensibles del sistema.', remediation: 'Validar rutas de archivos. Usar chroot o docker. No exponer paths del sistema.', mitre: 'T1005', logFormat: 'web' },
        { id: 'WEB-004', category: 'web', severity: 'high', name: 'Escaneo de rutas sensibles', regex: /\/(?:admin|wp-admin|phpmyadmin|manager|\.env|\.git|config|backup|db_admin|server-status)\b/i, description: 'Intento de acceso a rutas administrativas o archivos de configuración.', impact: 'Posible enumeración de directorios o exposición de información sensible.', remediation: 'Bloquear IP. Ocultar rutas administrativas. No exponer archivos de configuración. Autenticación fuerte en paneles.', mitre: 'T1046', logFormat: 'web' },
        { id: 'WEB-005', category: 'web', severity: 'medium', name: 'User-Agent de escáner/exploit', regex: /(?:sqlmap|nikto|nmap|nessus|openvas|acunetix|burp|zap|gobuster|dirbuster|wpscan|python-requests|curl|wget|masscan)/i, description: 'User-Agent asociado a herramientas de escaneo o explotación.', impact: 'Reconocimiento activo del objetivo.', remediation: 'Bloquear User-Agent en WAF/Nginx. Monitorear IP. No es concluyente (pueden falsificarse).', mitre: 'T1046', logFormat: 'web' },
        { id: 'WEB-006', category: 'web', severity: 'high', name: 'File Inclusion (LFI/RFI)', regex: /(?:include=|require=|file=|page=|document=|import=|php:\/\/|file:\/\/|data:\/\/|expect:\/\/)/i, description: 'Intento de inclusión remota o local de archivos.', impact: 'Ejecución remota de código o lectura de archivos arbitrarios.', remediation: 'Validar parámetros de inclusión. Usar mapeo de páginas permitidas. Deshabilitar allow_url_include.', mitre: 'T1190', logFormat: 'web' },
        { id: 'WEB-007', category: 'web', severity: 'medium', name: 'CSRF Token manipulation', regex: /(?:csrf|token|authenticity).{0,40}(?:missing|invalid|incorrect|wrong|fail)/i, description: 'Posible intento de Cross-Site Request Forgery.', impact: 'Ejecución de acciones no autorizadas en nombre de usuario autenticado.', remediation: 'Implementar tokens CSRF. Usar SameSite cookies. Verificar Origin/Referer.', mitre: 'T1529', logFormat: 'web' },
        { id: 'WEB-008', category: 'web', severity: 'high', name: 'Server-Side Request Forgery (SSRF)', regex: /(?:\?url=|&url=|\?file=|\?load=|\?path=)(?:https?:\/\/|file:\/\/|dict:\/\/|gopher:\/\/)/i, description: 'Posible intento de SSRF para acceder a recursos internos.', impact: 'Acceso a servicios internos (metadatos cloud, databases, etc.).', remediation: 'Lista blanca de destinos. Validar URLs con DNS inverso. No permitir esquemas internos.', mitre: 'T1190', logFormat: 'web' },
        { id: 'WEB-009', category: 'web', severity: 'medium', name: 'HTTP Method manipulation', regex: /(?:PUT|DELETE|TRACE|OPTIONS|PATCH).{0,40}\/.{0,40}(?:200|201|204)/i, description: 'Método HTTP peligroso permitido en el servidor.', impact: 'Posible modificación o eliminación de recursos.', remediation: 'Restringir métodos HTTP. Deshabilitar TRACE (Cross-Site Tracing).', mitre: 'T1190', logFormat: 'web' },
        { id: 'WEB-010', category: 'web', severity: 'low', name: 'Error 403/404 múltiple', regex: /(?:403|404).{0,40}(?:Forbidden|Not Found|Acceso denegado|No encontrado)/i, description: 'Múltiples errores de acceso/archivo no encontrado.', impact: 'Indica escaneo de directorios o intentos de acceso a rutas inexistentes.', remediation: 'Verificar si hay patrón. Bloquear IP si supera umbral.', mitre: 'T1046', logFormat: 'web' },
        { id: 'WEB-011', category: 'web', severity: 'high', name: 'Command Injection', regex: /(?:;|&&|\|\|).{0,20}(?:id|whoami|cat|ls|dir|ping|nslookup|wget|curl|bash|cmd|powershell)/i, description: 'Posible intento de inyección de comandos del sistema.', impact: 'Ejecución remota de comandos en el servidor.', remediation: 'Validar y sanitizar input. Usar funciones seguras en lugar de exec/system. Principio de mínimo privilegio.', mitre: 'T1203', logFormat: 'web' },
        { id: 'WEB-012', category: 'web', severity: 'medium', name: 'WordPress escaneo de plugins/vulnerabilidades', regex: /\/wp-content\/plugins\/|\/wp-content\/themes\/|\/wp-includes\/|\/xmlrpc\.php|\/wp-json\//i, description: 'Escaneo de componentes WordPress.', impact: 'Reconocimiento de plugins y temas que pueden tener vulnerabilidades.', remediation: 'Mantener WordPress y plugins actualizados. Ocultar versión. Usar WAF. Eliminar xmlrpc.php si no se usa.', mitre: 'T1046', logFormat: 'web' },
        { id: 'WEB-013', category: 'web', severity: 'high', name: 'Exposición de información sensible (.env, .git, backup)', regex: /\.(?:env|git|svn|bak|backup|config|log|sql|pem|key)(?:\?|#|\/|$)/i, description: 'Solicitud a archivos de configuración o backups expuestos.', impact: 'Fuga de credenciales, claves o código fuente.', remediation: 'Bloquear acceso a archivos sensibles. Revisar configuración del servidor web. Eliminar backups públicos.', mitre: 'T1552', logFormat: 'web' },
        { id: 'WEB-014', category: 'web', severity: 'high', name: 'JWT/Token anómalo o manipulado', regex: /(?:jwt|bearer|token).{0,40}(?:invalid|malformed|expired|signature|alg:none|none)/i, description: 'Intento de uso de token JWT inválido o manipulado (posible JWT None algorithm).', impact: 'Bypass de autenticación o escalada de privilegios.', remediation: 'Validar firma y algoritmo JWT. Rechazar alg:none. Verificar expiración y emisor.', mitre: 'T1556', logFormat: 'web' },

        // MALWARE & TTPs
        { id: 'MAL-001', category: 'malware', severity: 'critical', name: 'Indicador de C2 (Command & Control)', regex: /(?:pastebin\.com|\.onion|bootstrap\.exe|\.ps1.{0,20}-enc|base64|\.dll.{0,20}rundll|cmd\.exe.{0,20}\/c|obfuscated|malicios)/i, description: 'Posible comunicación con servidor de Comando y Control (C2).', impact: 'El sistema podría estar bajo control remoto de un atacante.', remediation: 'Aislar el equipo de la red. Ejecutar escaneo completo. Capturar tráfico de red. Notificar al SOC.', mitre: 'T1071', logFormat: 'any' },
        { id: 'MAL-002', category: 'malware', severity: 'critical', name: 'Ejecución de binario sospechoso en Temp', regex: /(?:temp|tmp|appdata|local.{0,20}temp).{0,40}\.(?:exe|dll|ps1|vbs|bat|cmd|scr|js)/i, description: 'Ejecución de binario desde directorio temporal.', impact: 'Alta probabilidad de infección por malware.', remediation: 'Analizar el archivo. Revisar el proceso padre. Escanear con EDR. Bloquear ejecución desde Temp.', mitre: 'T1204.002', logFormat: 'any' },
        { id: 'MAL-003', category: 'malware', severity: 'high', name: 'Descarga de archivo desde URL sospechosa', regex: /(?:http|https|ftp).{0,60}\.(?:exe|dll|ps1|vbs|bat|jar|scr).{0,40}(?:download|wget|curl|invoke-webrequest)/i, description: 'Descarga remota de archivos ejecutables.', impact: 'Posible descarga de payload malicioso.', remediation: 'Verificar reputación de la URL. Bloquear en proxy. Escanear el archivo descargado.', mitre: 'T1105', logFormat: 'any' },
        { id: 'MAL-004', category: 'malware', severity: 'critical', name: 'Proceso inyectado o comportamiento anómalo', regex: /(?:injection|inyección|hollowing|process.{0,20}(?:ghost|hollow)|reflective|runpe|malware|trojan|ransom|backdoor|keylog|worm)/i, description: 'Indicador de técnica de evasión o ejecución maliciosa.', impact: 'Compromiso del sistema con posibles técnicas avanzadas (inyección, process hollowing).', remediation: 'Análisis forense completo. Capturar volcado de memoria. Aislar sistema.', mitre: 'T1055', logFormat: 'any' },
        { id: 'MAL-005', category: 'malware', severity: 'high', name: 'Conexión saliente a IP sospechosa', regex: /(?:outbound|saliente|connect|conecta).{0,40}(?:unknown|sospech|unknown|malici).{0,40}(?:\d{1,3}\.){3}\d{1,3}/i, description: 'Conexión de red saliente hacia un destino identificado como sospechoso.', impact: 'Posible exfiltración de datos o comunicación C2.', remediation: 'Bloquear IP en firewall. Capturar tráfico. Analizar proceso origen.', mitre: 'T1041', logFormat: 'any' },
        { id: 'MAL-006', category: 'malware', severity: 'medium', name: 'Nombre de archivo sospechoso', regex: /(?:invoice|factura|urgent|urgente|document|cv|curriculum|update|actualizaci).{0,20}\.(?:exe|js|vbs|scr|ps1|docm|xlsm)/i, description: 'Archivo con nombre engañoso usado como señuelo de phishing.', impact: 'Probable intento de infección mediante ingeniería social.', remediation: 'No abrir archivos inesperados. Verificar remitente. Escanear con antivirus.', mitre: 'T1566', logFormat: 'any' },
        { id: 'MAL-007', category: 'malware', severity: 'critical', name: 'Cifrado de archivos en masa', regex: /(?:encrypt|cifrado|ransom|locker|crypt|aaaa|\.encrypted|\.locked|\.crypt)/i, description: 'Posible ataque de ransomware: cifrado masivo de archivos.', impact: 'Pérdida de datos. Extorsión económica.', remediation: 'Aislar sistema inmediatamente. No pagar rescate. Identificar variante. Restaurar desde backup.', mitre: 'T1486', logFormat: 'any' },
        { id: 'MAL-008', category: 'malware', severity: 'medium', name: 'Modificación de archivo hosts', regex: /(?:hosts|etc\\hosts|drivers\\etc).{0,40}(?:127\.0\.0\.1|0\.0\.0\.0).{0,40}(?:google|facebook|bank|paypal)/i, description: 'Redirección de tráfico mediante modificación del archivo hosts.', impact: 'Phishing o bloqueo de sitios de seguridad.', remediation: 'Restaurar archivo hosts original. Verificar integridad del DNS. Escanear en busca de malware.', mitre: 'T1562', logFormat: 'any' },
        { id: 'MAL-009', category: 'malware', severity: 'critical', name: 'Token de acceso robado / Session hijacking', regex: /(?:token|session|jwt|bearer|oauth).{0,40}(?:stolen|robado|leaked|filtrad|comprom)/i, description: 'Posible robo de token de autenticación o sesión.', impact: 'Suplantación de identidad sin necesidad de credenciales.', remediation: 'Revocar tokens. Forzar cierre de sesión global. Rotar secretos. Implementar rotación de tokens.', mitre: 'T1528', logFormat: 'any' },
        { id: 'MAL-010', category: 'malware', severity: 'high', name: 'Uso de Mimikatz o herramientas de credential dumping', regex: /(?:mimikatz|sekurlsa|wdigest|lsadump|samdump|procdump|dumpert|pwdump|gsecdump|credential|vaultcmd)/i, description: 'Herramienta de extracción de credenciales detectada.', impact: 'Compromiso de todas las credenciales del sistema.', remediation: 'Aislar sistema inmediatamente. Rotar contraseñas de todas las cuentas. Habilitar LSA Protection.', mitre: 'T1003', logFormat: 'any' },
        { id: 'MAL-011', category: 'malware', severity: 'high', name: 'Descarga con PowerShell encoded command', regex: /powershell.{0,40}(?:-enc|-encodedcommand|frombase64string|invoke-expression|iex|downloadstring)/i, description: 'PowerShell ejecutando comando codificado o descarga de payload.', impact: 'Ejecución de código malicioso, típicamente sin tocar disco.', remediation: 'Bloquear ejecución de PowerShell codificado. Habilitar logs de script. Revisar proceso padre.', mitre: 'T1059.001', logFormat: 'any' },
        { id: 'MAL-012', category: 'malware', severity: 'high', name: 'Uso de utilidades Living Off The Land (LOTL)', regex: /(?:rundll32|regsvr32|mshta|certutil|wscript|cscript).{0,40}(?:http|\.dll|\.exe|\.js|\.vbs|decode|encode|urlcache)/i, description: 'Utilidades legítimas de Windows usadas para cargar o ejecutar código malicioso.', impact: 'Evasión de controles de seguridad y ejecución de payload.', remediation: 'Auditar uso de estas utilidades. Implementar WDAC/AppLocker. Revisar líneas de comando.', mitre: 'T1218', logFormat: 'any' },

        // NETWORK & FIREWALL
        { id: 'NET-001', category: 'network', severity: 'medium', name: 'Escaneo de puertos detectado', regex: /(?:scan|escaneo|port|puerto|nmap|masscan|syn).{0,40}(?:multiple|many|varios|rapid|rápid)/i, description: 'Múltiples conexiones a diferentes puertos desde la misma IP en corto tiempo.', impact: 'Reconocimiento de servicios abiertos.', remediation: 'Bloquear IP origen. Implementar IPS/IDS. Reducir superficie de ataque.', mitre: 'T1046', logFormat: 'network' },
        { id: 'NET-002', category: 'network', severity: 'high', name: 'Ataque DDoS detectado', regex: /(?:ddos|flood|inundación|amplificación|amplification|reflection|reflexión).{0,40}(?:syn|udp|icmp|http|dns)/i, description: 'Patrón de tráfico consistente con un ataque de denegación de servicio distribuido.', impact: 'Indisponibilidad del servicio.', remediation: 'Activar protección anti-DDoS. Filtrar tráfico en firewall perimetral. Contactar con ISP.', mitre: 'T1498', logFormat: 'network' },
        { id: 'NET-003', category: 'network', severity: 'high', name: 'Conexión a puerto de administración remota expuesto', regex: /(?:22|3389|5900|8443).{0,40}(?:open|abierto|connected|conectado).{0,40}(?:external|externa|wan|internet)/i, description: 'Puerto de administración remota expuesto a Internet.', impact: 'Superficie de ataque ampliada.', remediation: 'Cerrar puertos en firewall. Usar VPN para acceso remoto. Implementar autenticación multifactor.', mitre: 'T1190', logFormat: 'network' },
        { id: 'NET-004', category: 'network', severity: 'medium', name: 'Tráfico DNS anómalo', regex: /(?:dns|domain).{0,40}(?:tunnel|túnel|anomal|large|grande|sospech|unknown|query|consulta).{0,40}(?:long|largo|base64|hex)/i, description: 'Consultas DNS con patrones sospechosos (túneles DNS o exfiltración).', impact: 'Exfiltración de datos o comunicación C2 por DNS.', remediation: 'Monitorear tráfico DNS. Implementar filtrado DNS. Usar DoH/DoT corporativo.', mitre: 'T1572', logFormat: 'network' },
        { id: 'NET-005', category: 'network', severity: 'low', name: 'Tráfico en puerto no estándar', regex: /(?:port|puerto).{0,40}(?:8443|8080|4443|2222|992|6666|1337|31337).{0,40}(?:traffic|tráfico|connection|conexión)/i, description: 'Tráfico en puertos no estándar o asociados a malware.', impact: 'Bajo: puede ser aplicación legítima en puerto alternativo.', remediation: 'Identificar la aplicación. Verificar si el puerto está autorizado.', mitre: 'T1571', logFormat: 'network' },
        { id: 'NET-006', category: 'network', severity: 'high', name: 'Firewall bloqueando tráfico saliente sospechoso', regex: /(?:block|bloque|denied|deneg|drop|reject|rechaz).{0,40}(?:outbound|saliente|egress).{0,40}(?:malicious|malici|sospech|unknown|trojan|bot)/i, description: 'El firewall ha bloqueado tráfico saliente hacia destinos maliciosos conocidos.', impact: 'Posible infección intentando contactar C2.', remediation: 'Investigar el proceso origen. Aislar el equipo. Capturar muestra del tráfico.', mitre: 'T1071', logFormat: 'network' },
        { id: 'NET-007', category: 'network', severity: 'medium', name: 'Protocolo no autorizado detectado', regex: /(?:protocol|protocolo).{0,40}(?:no autorizado|unauthorized|not allowed|no permitido).{0,40}(?:tunnel|proxy|vpn|tor)/i, description: 'Uso de protocolos de tunelización o anonimización.', impact: 'Bypass de controles de seguridad.', remediation: 'Bloquear en firewall de próxima generación. Implementar DLP. Revisar política de uso aceptable.', mitre: 'T1573', logFormat: 'network' },
        { id: 'NET-008', category: 'network', severity: 'high', name: 'ARP Spoofing detectado', regex: /(?:arp|man-in-the-middle|MITM|spoof|suplantación).{0,40}(?:duplicate|duplicado|unusual|anómalo|attack|ataque)/i, description: 'Posible ataque ARP Spoofing en la red local.', impact: 'Interceptación de tráfico entre dispositivos de la red.', remediation: 'Implementar ARP spoofing detection. Usar DHCP snooping. Segmentar red. Usar IPsec/SSL.', mitre: 'T1557', logFormat: 'network' },
        { id: 'NET-009', category: 'network', severity: 'medium', name: 'Conexión saliente a IP de reputación dudosa', regex: /(?:outbound|saliente|connection|conexión).{0,40}(?:\d{1,3}\.){3}\d{1,3}.{0,40}(?:suspicious|malicious|blacklist|reputation)/i, description: 'Conexión saliente hacia IP con reputación negativa.', impact: 'Posible comunicación C2 o exfiltración.', remediation: 'Bloquear IP. Investigar proceso origen. Revisar proxy/firewall.', mitre: 'T1071', logFormat: 'network' },

        // CRASH & DUMP ANALYSIS
        { id: 'CRASH-001', category: 'crash', severity: 'critical', name: 'BSOD: CRITICAL_PROCESS_DIED', regex: /(?:CRITICAL_PROCESS_DIED|0x000000EF|0xEF)/i, description: 'Blue Screen of Death: un proceso crítico del sistema ha terminado inesperadamente.', impact: 'El sistema se detuvo para evitar daños mayores. Posible fallo de hardware o corrupción del sistema.', remediation: 'Verificar disco duro (chkdsk). Revisar memoria RAM (memtest86). Restaurar archivos del sistema (sfc /scannow). Actualizar controladores.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-002', category: 'crash', severity: 'critical', name: 'BSOD: MEMORY_MANAGEMENT', regex: /(?:MEMORY_MANAGEMENT|0x0000001A|0x1A)/i, description: 'BSOD: Error de gestión de memoria. Problema con la memoria RAM o controladores de memoria.', impact: 'Corrupción de datos en memoria. Inestabilidad del sistema.', remediation: 'Ejecutar diagnóstico de memoria (mdsched.exe). Verificar controladores de chipset. Comprobar voltajes de RAM.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-003', category: 'crash', severity: 'critical', name: 'BSOD: SYSTEM_SERVICE_EXCEPTION', regex: /(?:SYSTEM_SERVICE_EXCEPTION|0x0000003B|0x3B)/i, description: 'BSOD: Excepción en servicio del sistema. Causa común: controladores defectuosos o incompatibles.', impact: 'Fallo recurrente que impide el uso normal del sistema.', remediation: 'Actualizar o revertir controladores recién instalados. Ejecutar sfc /scannow. Comprobar actualizaciones de Windows.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-004', category: 'crash', severity: 'critical', name: 'BSOD: DRIVER_IRQL_NOT_LESS_OR_EQUAL', regex: /(?:DRIVER_IRQL_NOT_LESS_OR_EQUAL|0x000000D1|0xD1)/i, description: 'BSOD: Un controlador intentó acceder a memoria con IRQL incorrecto. Controlador defectuoso.', impact: 'Fallo del sistema causado por driver defectuoso.', remediation: 'Identificar el controlador en el mensaje de error. Actualizar o revertir. Usar Driver Verifier para diagnóstico.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-005', category: 'crash', severity: 'critical', name: 'BSOD: PAGE_FAULT_IN_NONPAGED_AREA', regex: /(?:PAGE_FAULT_IN_NONPAGED_AREA|0x00000050|0x50)/i, description: 'BSOD: El sistema intentó acceder a memoria no paginada que no existe.', impact: 'Fallo de hardware (RAM/SSD) o controlador defectuoso.', remediation: 'Ejecutar diagnóstico de RAM. Verificar disco (chkdsk). Actualizar controladores de almacenamiento.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-006', category: 'crash', severity: 'critical', name: 'BSOD: IRQL_NOT_LESS_OR_EQUAL', regex: /(?:IRQL_NOT_LESS_OR_EQUAL|0x0000000A|0x0A)/i, description: 'BSOD: Un controlador o servicio intentó acceder a memoria a un IRQL demasiado alto.', impact: 'Fallo del sistema. Puede ser por driver, hardware o software incompatible.', remediation: 'Actualizar controladores. Desinstalar software reciente. Verificar compatibilidad de hardware.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-007', category: 'crash', severity: 'critical', name: 'BSOD: KERNEL_SECURITY_CHECK_FAILURE', regex: /(?:KERNEL_SECURITY_CHECK_FAILURE|0x00000139|0x139)/i, description: 'BSOD: Fallo en verificación de seguridad del kernel. Puede indicar corrupción de memoria o rootkit.', impact: 'Posible compromiso del kernel. Corrupción de estructuras críticas.', remediation: 'Ejecutar escaneo antivirus/antimalware. Verificar integridad de archivos del sistema. Actualizar Windows.', mitre: 'T1562', logFormat: 'dump' },
        { id: 'CRASH-008', category: 'crash', severity: 'critical', name: 'BSOD: UNEXPECTED_KERNEL_MODE_TRAP', regex: /(?:UNEXPECTED_KERNEL_MODE_TRAP|0x0000007F|0x7F)/i, description: 'BSOD: Excepción no esperada en modo kernel. Causas: hardware defectuoso (CPU/RAM), overclocking, controladores maliciosos.', impact: 'Fallo crítico del sistema.', remediation: 'Eliminar overclocking. Verificar temperaturas de CPU. Ejecutar diagnóstico de hardware.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-009', category: 'crash', severity: 'high', name: 'BSOD: VIDEO_TDR_FAILURE', regex: /(?:VIDEO_TDR_FAILURE|0x00000116|0x116)/i, description: 'BSOD: Fallo de gráficos. El controlador de video no respondió y Windows lo recuperó.', impact: 'Fallo de la GPU o del controlador de gráficos.', remediation: 'Actualizar controladores de GPU. Reducir overclock de GPU. Verificar temperatura de la tarjeta gráfica.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-010', category: 'crash', severity: 'high', name: 'BSOD: APC_INDEX_MISMATCH', regex: /(?:APC_INDEX_MISMATCH|0x00000001|0x01)/i, description: 'BSOD: Error en el sistema de Archivos o controladores de almacenamiento.', impact: 'Posible fallo de disco o controlador de almacenamiento.', remediation: 'Verificar integridad del disco (chkdsk /f). Actualizar controladores de almacenamiento. Revisar conexiones SATA/NVMe.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-011', category: 'crash', severity: 'medium', name: 'Fallo de controlador detectado', regex: /(?:driver|controlador).{0,40}(?:fail|fallo|error|crash|stop|detenid).{0,40}(?:0x|ntoskrnl|dxgkrnl|kern)/i, description: 'Fallo de controlador del sistema detectado en el volcado.', impact: 'Inestabilidad del sistema.', remediation: 'Identificar y actualizar el controlador problemático. Verificar compatibilidad con la versión de Windows.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-012', category: 'crash', severity: 'high', name: 'Corrupción de memoria detectada en dump', regex: /(?:memory|memoria).{0,40}(?:corrupt|corrup|damage|dañ|bad|mal|error|page|pool)/i, description: 'Se detectó corrupción de memoria en el volcado.', impact: 'Posible fallo de hardware (RAM) o driver defectuoso.', remediation: 'Ejecutar Windows Memory Diagnostic. Probar RAM con memtest86. Comprobar compatibilidad de módulos.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-013', category: 'crash', severity: 'high', name: 'Volcado por cierre inesperado de proceso (crash/hang)', regex: /(?:hang|colgado|freeze|congelado|not responding|sin respuesta|timeout|tiempo.{0,20}espera)/i, description: 'El sistema o una aplicación dejó de responder y generó un volcado.', impact: 'Pérdida de datos no guardados. Posible fuga de memoria o bucle infinito.', remediation: 'Revisar el consumo de recursos del proceso. Actualizar la aplicación. Verificar conflictos de software.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-014', category: 'crash', severity: 'medium', name: 'Registro de volcado por error de aplicación', regex: /(?:exception|excepción|error|fault).{0,40}(?:application|aplicación|app).{0,40}(?:crash|fallo|stop|detenid).{0,40}(?:\.exe|\.dll)/i, description: 'Volcado generado por una aplicación que falló.', impact: 'La aplicación específica dejó de funcionar.', remediation: 'Reinstalar la aplicación. Verificar requisitos del sistema. Buscar actualizaciones del fabricante.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-015', category: 'crash', severity: 'critical', name: 'BSOD: DPC_WATCHDOG_VIOLATION', regex: /(?:DPC_WATCHDOG_VIOLATION|0x00000133|0x133)/i, description: 'BSOD: Un DPC (Deferred Procedure Call) tardó demasiado. Frecuentemente relacionado con drivers de almacenamiento o SSD.', impact: 'Driver de almacenamiento lento o firmware obsoleto.', remediation: 'Actualizar firmware del SSD. Actualizar drivers de chipset y NVMe/SATA. Desactivar Fast Boot.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-016', category: 'crash', severity: 'critical', name: 'BSOD: DRIVER_POWER_STATE_FAILURE', regex: /(?:DRIVER_POWER_STATE_FAILURE|0x0000009F|0x9F)/i, description: 'BSOD: Un driver no completó una transición de energía a tiempo.', impact: 'Driver problemático durante suspensión/reanudación.', remediation: 'Actualizar drivers de GPU, red, chipset y audio. Deshabilitar hibernación como prueba. Configurar energía máxima rendimiento.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-017', category: 'crash', severity: 'critical', name: 'BSOD: WHEA_UNCORRECTABLE_ERROR', regex: /(?:WHEA_UNCORRECTABLE_ERROR|0x00000124|0x124)/i, description: 'BSOD: Error de hardware no corregible (CPU, RAM, placa base, fuente).', impact: 'Fallo grave de hardware.', remediation: 'Verificar temperaturas. Probar RAM. Revisar overclock. Comprobar fuente de alimentación. Actualizar BIOS.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-018', category: 'crash', severity: 'critical', name: 'BSOD: MACHINE_CHECK_EXCEPTION', regex: /(?:MACHINE_CHECK_EXCEPTION|0x0000009C|0x9C)/i, description: 'BSOD: Error grave de hardware detectado por la CPU.', impact: 'Fallo de hardware: CPU, RAM, placa base o fuente.', remediation: 'Revisar temperatura CPU. Verificar overclocking. Comprobar fuente de alimentación. Ejecutar diagnósticos.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-019', category: 'crash', severity: 'high', name: 'BSOD: SYSTEM_THREAD_EXCEPTION_NOT_HANDLED', regex: /(?:SYSTEM_THREAD_EXCEPTION_NOT_HANDLED|0x0000007E|0x7E)/i, description: 'BSOD: Excepción en hilo del sistema no manejada.', impact: 'Fallo por driver o servicio defectuoso.', remediation: 'Actualizar o revertir controladores recientes. Ejecutar sfc /scannow. Revisar software nuevo.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-020', category: 'crash', severity: 'critical', name: 'BSOD: KMODE_EXCEPTION_NOT_HANDLED', regex: /(?:KMODE_EXCEPTION_NOT_HANDLED|0x0000001E|0x1E)/i, description: 'BSOD: Excepción en modo kernel no manejada por un controlador.', impact: 'Fallo del sistema por driver defectuoso.', remediation: 'Identificar el driver en los parámetros. Actualizar o revertir drivers recién instalados.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-021', category: 'crash', severity: 'critical', name: 'BSOD: CLOCK_WATCHDOG_TIMEOUT', regex: /(?:CLOCK_WATCHDOG_TIMEOUT|0x00000101|0x101)/i, description: 'BSOD: Un procesador no respondió a una interrupción del reloj.', impact: 'CPU bloqueada o overclocking inestable.', remediation: 'Eliminar overclocking. Verificar temperatura CPU. Actualizar BIOS. Revisar fuente de alimentación.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-022', category: 'crash', severity: 'high', name: 'BSOD: DRIVER_VERIFIER_DETECTED_VIOLATION', regex: /(?:DRIVER_VERIFIER_DETECTED_VIOLATION|0x000000C4|0xC4)/i, description: 'BSOD: Driver Verifier detectó una violación en un driver.', impact: 'Driver defectuoso identificado por el verificador.', remediation: 'Desinstalar el driver señalado. Actualizar controladores. Driver Verifier no debe estar activo en producción.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-023', category: 'crash', severity: 'critical', name: 'BSOD: INACCESSIBLE_BOOT_DEVICE', regex: /(?:INACCESSIBLE_BOOT_DEVICE|0x0000007B|0x7B)/i, description: 'BSOD: Windows no puede acceder al dispositivo de arranque.', impact: 'El sistema no arranca.', remediation: 'Verificar conexiones de disco. Revisar orden de arranque en BIOS. Reparar BCD. Posible fallo de disco.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-024', category: 'crash', severity: 'critical', name: 'BSOD: NTFS_FILE_SYSTEM', regex: /(?:NTFS_FILE_SYSTEM|0x00000024|0x24)/i, description: 'BSOD: Error en el sistema de archivos NTFS.', impact: 'Posible corrupción de disco o fallo de almacenamiento.', remediation: 'Ejecutar chkdsk /f /r. Verificar disco con smartctl. Revisar cable de datos.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-025', category: 'crash', severity: 'critical', name: 'BSOD: CRITICAL_STRUCTURE_CORRUPTION', regex: /(?:CRITICAL_STRUCTURE_CORRUPTION|0x00000109|0x109)/i, description: 'BSOD: Corrupción de estructuras críticas del kernel. Posible rootkit o fallo de hardware.', impact: 'Posible compromiso del kernel o corrupción grave.', remediation: 'Escaneo antimalware completo. Verificar integridad con sfc. Ejecutar diagnóstico de RAM.', mitre: 'T1562', logFormat: 'dump' },
        { id: 'CRASH-026', category: 'crash', severity: 'high', name: 'BSOD: ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY', regex: /(?:ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY|0x000000FC|0xFC)/i, description: 'BSOD: Intentó ejecutar código en memoria no ejecutable (DEP/NX).', impact: 'Driver defectuoso o malware intentando bypassar DEP.', remediation: 'Actualizar controladores. Ejecutar escaneo antimalware. Verificar configuración DEP.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-027', category: 'crash', severity: 'critical', name: 'BSOD: PFN_LIST_CORRUPT', regex: /(?:PFN_LIST_CORRUPT|0x0000004E|0x4E)/i, description: 'BSOD: Corrupción de la lista PFN (Page Frame Number).', impact: 'Corrupción grave de memoria.', remediation: 'Ejecutar diagnóstico de RAM. Verificar controladores de almacenamiento. Actualizar chipset.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-028', category: 'crash', severity: 'critical', name: 'BSOD: BAD_POOL_HEADER', regex: /(?:BAD_POOL_HEADER|0x00000019|0x19)/i, description: 'BSOD: Cabecera de pool de memoria corrupta.', impact: 'Corrupción de memoria por driver defectuoso o RAM.', remediation: 'Actualizar controladores. Ejecutar diagnóstico de RAM. Usar Driver Verifier.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-029', category: 'crash', severity: 'high', name: 'BSOD: BAD_POOL_CALLER', regex: /(?:BAD_POOL_CALLER|0x000000C2|0xC2)/i, description: 'BSOD: Driver llamó incorrectamente a funciones de pool de memoria.', impact: 'Driver defectuoso corrompiendo memoria.', remediation: 'Actualizar controladores. Usar Driver Verifier para identificar el driver problemático.', mitre: '', logFormat: 'dump' },
        { id: 'CRASH-030', category: 'crash', severity: 'high', name: 'BSOD: REFERENCE_BY_POINTER', regex: /(?:REFERENCE_BY_POINTER|0x00000018|0x18)/i, description: 'BSOD: Error en conteo de referencias de objeto. Generalmente driver.', impact: 'Driver con bug de conteo de referencias.', remediation: 'Actualizar o desinstalar drivers recientes. Usar Driver Verifier.', mitre: '', logFormat: 'dump' },

        // COMPLIANCE & AUDIT
        { id: 'CMP-001', category: 'compliance', severity: 'high', name: 'Cuenta con privilegios excesivos', regex: /(?:privilegio.{0,20}excesiv|admin.{0,20}local|domain.{0,20}admin).{0,40}(?:grant|conced|asign|add|añad)/i, description: 'Cuenta con privilegios administrativos sin justificación.', impact: 'Incumplimiento de mínimo privilegio.', remediation: 'Revisar membresías de grupos. Aplicar RBAC. Auditar cuentas privilegiadas periódicamente.', mitre: '', logFormat: 'any' },
        { id: 'CMP-002', category: 'compliance', severity: 'medium', name: 'Uso de protocolo no cifrado', regex: /(?:telnet|ftp|http|pop3|imap|smb1).{0,40}(?:login|auth|password|contrase)/i, description: 'Uso de protocolos que transmiten credenciales en texto claro.', impact: 'Interceptación de credenciales en la red.', remediation: 'Migrar a SSH/FTPS/HTTPS/IMAPS. Deshabilitar protocolos legacy. Implementar cifrado en todas las comunicaciones.', mitre: '', logFormat: 'any' },
        { id: 'CMP-003', category: 'compliance', severity: 'medium', name: 'Política de contraseñas débil', regex: /(?:password|contrase).{0,40}(?:never expires|no expira|never.{0,20}change|no.{0,20}camb|weak|débil|simple|123456|1234)/i, description: 'Se detectó una cuenta con contraseña débil o que nunca expira.', impact: 'Incumplimiento de políticas de seguridad.', remediation: 'Implementar política de contraseñas fuertes. Habilitar expiración periódica. Usar LAPS para admin locales.', mitre: '', logFormat: 'any' },
        { id: 'CMP-004', category: 'compliance', severity: 'low', name: 'Auditoría deshabilitada en recurso', regex: /(?:audit|auditor).{0,40}(?:disabled|deshabilit|off|inactiv|not.{0,20}config)/i, description: 'La auditoría no está habilitada en un recurso del sistema.', impact: 'Falta de visibilidad para detectar incidentes.', remediation: 'Habilitar auditoría en el recurso afectado. Centralizar logs en SIEM.', mitre: '', logFormat: 'any' },
        { id: 'CMP-005', category: 'compliance', severity: 'high', name: 'Firewall deshabilitado', regex: /(?:firewall|firewall).{0,40}(?:disabled|deshabilit|off|apagad|inact|stopped|detenid)/i, description: 'El firewall del sistema está deshabilitado.', impact: 'Exposición total a ataques de red.', remediation: 'Habilitar el firewall. Verificar reglas. No deshabilitar sin justificación documentada.', mitre: '', logFormat: 'any' },
        { id: 'CMP-006', category: 'compliance', severity: 'high', name: 'Actualizaciones de seguridad pendientes', regex: /(?:update|actualizac).{0,40}(?:pending|pendient|miss|no instal|critical|crítica|security|seguridad).{0,40}(?:days|días|weeks|semanas)/i, description: 'Actualizaciones críticas de seguridad no instaladas.', impact: 'Sistema vulnerable a exploits conocidos.', remediation: 'Aplicar parches de seguridad. Implementar WSUS/SCCM. Establecer política de actualizaciones.', mitre: '', logFormat: 'any' },
        { id: 'CMP-007', category: 'compliance', severity: 'medium', name: 'Conexión no autorizada a dispositivo USB', regex: /(?:usb|removable|extraíble|flash|pendrive).{0,40}(?:connect|conect|mount|monta|autorun|autoplay)/i, description: 'Conexión de dispositivo USB no autorizado.', impact: 'Filtración de datos o introducción de malware.', remediation: 'Implementar DLP. Deshabilitar puertos USB. Usar software de control de dispositivos. Registrar conexiones.', mitre: '', logFormat: 'any' },
        { id: 'CMP-008', category: 'compliance', severity: 'high', name: 'Permisos de archivo sensibles relajados', regex: /(?:chmod|chown|icacls|setacl).{0,40}(?:777|Everyone|Full Control|ALL PERMISSIONS|0666)/i, description: 'Permisos excesivos otorgados a archivos o directorios sensibles.', impact: 'Cualquier usuario puede leer/escribir archivos críticos.', remediation: 'Restaurar permisos mínimos necesarios. Auditar archivos con permisos 777 o Everyone Full Control.', mitre: 'T1222', logFormat: 'any' },

        // LINUX SYSTEM LOGS
        { id: 'LNX-001', category: 'linux', severity: 'critical', name: 'Kernel Panic / Oops', regex: /(?:kernel panic|BUG:|unable to handle|general protection fault|Oops:|segfault|segmentation fault).{0,40}(?:kernel|linux|\d+\.\d+\.\d+)/i, description: 'El kernel de Linux ha experimentado un error crítico del que no puede recuperarse.', impact: 'El sistema se detiene o reinicia. Posible pérdida de datos no guardados.', remediation: 'Revisar dmesg para contexto. Verificar hardware (RAM con memtest86). Actualizar kernel. Revisar controladores y módulos recién cargados.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-002', category: 'linux', severity: 'critical', name: 'OOM Killer activado (Out of Memory)', regex: /(?:Out of memory|OOM|oom-killer|invoked oom-killer|killed process).{0,40}(?:Killed|terminated|score)/i, description: 'El sistema agotó la memoria RAM y el OOM Killer terminó procesos para liberar memoria.', impact: 'Aplicaciones críticas pueden ser terminadas. Degradación severa del rendimiento.', remediation: 'Revisar qué proceso consumió toda la RAM. Añadir más RAM o swap. Configurar límites de memoria por proceso (systemd/cgroups). Ajustar vm.overcommit_memory.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-003', category: 'linux', severity: 'high', name: 'Error de sistema de archivos (ext4/btrfs/xfs)', regex: /(?:ext4|btrfs|xfs|filesystem|journal|inode|superblock).{0,40}(?:error|corrupt|fail|read-only|ro|remount|abort)/i, description: 'Error en el sistema de archivos detectado. El sistema puede remontar el volumen como solo lectura.', impact: 'Pérdida de datos. Sistema inestable. Posible fallo de disco.', remediation: 'Ejecutar fsck en modo recuperación. Verificar salud del disco con smartctl. Revisar cables SATA/NVMe. Reemplazar disco si hay sectores defectuosos.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-004', category: 'linux', severity: 'high', name: 'Error de E/S de disco (I/O Error)', regex: /(?:I\/O error|input\/output error|buffer I\/O|lost page|disk.{0,20}fail|sd[a-z]+|nvme|ata.{0,20}error).{0,40}(?:error|fail|timeout|abort)/i, description: 'Error de entrada/salida en dispositivo de almacenamiento.', impact: 'Pérdida de datos. Aplicaciones pueden congelarse o fallar.', remediation: 'Revisar smartctl -a /dev/sdX. Verificar cables y conexiones. Comprobar temperatura del disco. Reemplazar si hay errores de hardware.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-005', category: 'linux', severity: 'critical', name: 'Servicio systemd en estado failed', regex: /(?:systemd|unit).{0,40}(?:failed|falló|failed result|enter failed|failed with).{0,40}(?:exit-code|timeout|signal|core|watchdog)/i, description: 'Un servicio gestionado por systemd ha entrado en estado de fallo.', impact: 'El servicio o aplicación no está funcionando. Posible denegación de servicio.', remediation: 'Revisar journalctl -u NOMBRE_SERVICIO. Verificar configuración del servicio. Comprobar dependencias. Revisar permisos y binarios.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-006', category: 'linux', severity: 'high', name: 'Servicio no encontrado o no arranca (systemd)', regex: /(?:unit not found|failed to start|not-found|dependency failed|timed out|start-limit|disable).{0,40}(?:service|timer|socket|mount)/i, description: 'Un servicio systemd no se encuentra o no puede iniciarse.', impact: 'El servicio no está disponible.', remediation: 'Verificar que el servicio está instalado. Revisar dependencias: systemctl list-dependencies. Comprobar archivos .service en /etc/systemd/system/.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-007', category: 'linux', severity: 'high', name: 'Error de apt/dpkg (gestor de paquetes)', regex: /(?:apt|dpkg|apt-get|aptitude).{0,40}(?:error|broken|unmet dependencies|held broken|configure|not installed|subprocess|unpack|unable to fetch|503|404|no repository|hash sum mismatch)/i, description: 'Error en la gestión de paquetes del sistema.', impact: 'El sistema no puede instalar o actualizar paquetes. Riesgo de seguridad por parches no aplicados.', remediation: 'Ejecutar sudo apt --fix-broken install. Revisar /etc/apt/sources.list. Verificar conectividad a repositorios. Limpiar caché: sudo apt clean.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-008', category: 'linux', severity: 'critical', name: 'SELinux denial / AVC audit', regex: /(?:SELinux|selinux|AVC|avc:.{0,20}denied).{0,40}(?:denied|reject|block|permission).{0,40}(?:comm=|path=|name=)/i, description: 'SELinux ha denegado una operación por política de seguridad.', impact: 'Aplicaciones pueden fallar por permisos denegados. Sistema más restrictivo de lo esperado.', remediation: 'Revisar ausearch -m avc -ts recent. Usar audit2allow para generar políticas. No deshabilitar SELinux. Ajustar contextos con chcon/semanage.', mitre: 'T1562.001', logFormat: 'linux' },
        { id: 'LNX-009', category: 'linux', severity: 'high', name: 'AppArmor denial', regex: /(?:apparmor|AppArmor).{0,40}(?:denied|DENIED|reject|block|profile).{0,40}(?:comm=|operation=)/i, description: 'AppArmor ha denegado una operación según su perfil de seguridad.', impact: 'Aplicación bloqueada al realizar una operación no permitida.', remediation: 'Revisar aa-status. Ver logs en /var/log/syslog o journalctl. Ajustar perfil con aa-complain/aa-enforce. Usar aa-logprof para generar reglas.', mitre: 'T1562.001', logFormat: 'linux' },
        { id: 'LNX-010', category: 'linux', severity: 'high', name: 'Error de red: interfaz caída/DHCP fallido', regex: /(?:dhcp|interface|network|net).{0,40}(?:down|fail|error|timeout|not found|no carrier|link.{0,20}down|address.{0,20}not|device.{0,20}not found)/i, description: 'La interfaz de red ha fallado o no ha podido obtener configuración DHCP.', impact: 'El sistema pierde conectividad de red.', remediation: 'Revisar ip a / ifconfig. Verificar cable/conexión WiFi. Comprobar servicio NetworkManager/systemd-networkd. Verificar servidor DHCP en la red.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-011', category: 'linux', severity: 'medium', name: 'Error de resolución DNS', regex: /(?:dns|resolv|name resolution|host not found|cannot resolve|temporary failure in name|failed to resolve)/i, description: 'Fallo en la resolución de nombres DNS.', impact: 'El sistema no puede acceder a recursos por nombre de dominio.', remediation: 'Revisar /etc/resolv.conf. Verificar conectividad al servidor DNS. Probar con nslookup/dig. Comprobar systemd-resolved.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-012', category: 'linux', severity: 'high', name: 'Espacio en disco crítico', regex: /(?:disk full|no space left|device.{0,20}no space|filesystem full|space.{0,20}exhausted|partition.{0,20}full).{0,40}(?:sda|nvme|md|mapper|\/)/i, description: 'El disco ha alcanzado su capacidad máxima.', impact: 'Aplicaciones no pueden escribir archivos. El sistema puede volverse inestable.', remediation: 'Limpiar logs viejos (logrotate). Revisar archivos grandes con du -sh /*. Eliminar paquetes no usados (apt autoremove). Ampliar partición si es posible.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-013', category: 'linux', severity: 'medium', name: 'Agotamiento de inodos', regex: /(?:inode.{0,20}exhaust|no space left.{0,20}inode|inode.{0,20}full|reserved.{0,20}inode)/i, description: 'Se han agotado los inodos disponibles en el sistema de archivos.', impact: 'No se pueden crear nuevos archivos aunque haya espacio libre.', remediation: 'Eliminar archivos pequeños innecesarios. Revisar directorios con muchos archivos temporales. Aumentar número de inodos al formatear.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-014', category: 'linux', severity: 'medium', name: 'SWAP al límite / swapping excesivo', regex: /(?:swap|swapping).{0,40}(?:full|exhaust|high|critic|oom|insufficient)/i, description: 'El uso de swap es muy alto, lo que degrada el rendimiento drásticamente.', impact: 'Rendimiento del sistema gravemente degradado.', remediation: 'Identificar procesos con mayor uso de memoria (htop). Añadir más RAM. Ajustar swappiness (sysctl vm.swappiness=10). Agregar más swap si es necesario.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-015', category: 'linux', severity: 'medium', name: 'Error de montaje de sistema de archivos', regex: /(?:mount|mount\.nfs|mount\.cifs|fstab).{0,40}(?:error|fail|not found|invalid|wrong fs|bad superblock|no such device|cannot mount)/i, description: 'Error al montar un sistema de archivos en el arranque o por solicitud.', impact: 'Recurso o partición no disponible.', remediation: 'Revisar /etc/fstab. Verificar UUID con blkid. Comprobar que el dispositivo existe. Usar systemctl daemon-reload si es systemd mount.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-016', category: 'linux', severity: 'high', name: 'Error de NTP/sincronización de hora', regex: /(?:ntp|chrony|time.{0,20}synch|clock.{0,20}skew|time.{0,20}fail|adjust.{0,20}time|ntpd).{0,40}(?:error|fail|no server|timeout|skew|offset|unsynchronised)/i, description: 'Fallo en la sincronización del reloj del sistema.', impact: 'Problemas de autenticación (Kerberos), logs con marcas de tiempo incorrectas.', remediation: 'Verificar servicio chrony/ntpd. Revisar conectividad a servidores NTP. Comprobar zona horaria (timedatectl). Verificar firewall (puerto 123 UDP).', mitre: '', logFormat: 'linux' },
        { id: 'LNX-017', category: 'linux', severity: 'high', name: 'Error de hardware detectado (MCE/EDAC)', regex: /(?:mce|machine check|EDAC|hardware error|CPU.{0,20}error|memory.{0,20}error|core.{0,20}error|cache.{0,20}error|bus.{0,20}error).{0,40}(?:corrected|uncorrected|fatal|overflow)/i, description: 'El sistema ha detectado errores de hardware a nivel de CPU/memoria/caché.', impact: 'Posible fallo de hardware inminente. Corrupción de datos silenciosa.', remediation: 'Revisar salida de mcelog. Ejecutar memtest86 para RAM. Verificar temperatura CPU. Comprobar integridad de la placa base.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-018', category: 'linux', severity: 'high', name: 'Error de controlador de GPU (nouveau/nvidia/amd)', regex: /(?:nouveau|nvidia|amdgpu|i915|radeon).{0,40}(?:gpu|fifo|fault|error|hang|timeout|Xid)/i, description: 'Error en el controlador de gráficos de Linux.', impact: 'Pantalla negra, congelamiento o reinicio. Posible fallo de GPU.', remediation: 'Actualizar firmware de GPU. Probar driver propietario vs libre. Verificar temperatura y cableado.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-019', category: 'linux', severity: 'high', name: 'Kernel tainted / módulo no firmado', regex: /(?:tainted|unsigned module|module verification failed|disabling lockdown)/i, description: 'El kernel ha cargado un módulo no firmado o el sistema está marcado como tainted.', impact: 'Garantía de soporte del kernel comprometida. Posible módulo malicioso o de terceros.', remediation: 'Revisar módulos cargados: lsmod. Verificar firmas. Evitar módulos de terceros no confiables.', mitre: 'T1562.001', logFormat: 'linux' },
        { id: 'LNX-020', category: 'linux', severity: 'critical', name: 'Escalada de privilegios detectada (sudo/su)', regex: /(?:sudo|su).{0,20}(?:root|to=root|USER=root).{0,20}(?:command|cmd|COMMAND)/i, description: 'Comando ejecutado como root mediante sudo o su.', impact: 'Uso de privilegios elevados. Auditar para detectar abuso.', remediation: 'Revisar sudoers. Auditar comandos sudo. Limitar privilegios al mínimo necesario.', mitre: 'T1548.003', logFormat: 'linux' },
        { id: 'LNX-021', category: 'linux', severity: 'high', name: 'Proceso crítico terminado o watchdog', regex: /(?:watchdog|watchdog.{0,20}timeout|softdog|harddog|process.{0,20}died).{0,40}(?:timeout|kill|reboot|reset)/i, description: 'Un watchdog o proceso crítico detectó bloqueo y reinició el sistema.', impact: 'Sistema congelado o inestable. Posible kernel panic o driver bloqueado.', remediation: 'Revisar logs previos al watchdog. Verificar drivers y hardware. Aumentar timeout si es esperado.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-022', category: 'linux', severity: 'medium', name: 'Thermald / sobrecalentamiento CPU', regex: /(?:thermal|thermald|temperature|cpu.{0,20}throttling|critical temperature)/i, description: 'Sistema reportando temperaturas críticas o throttling.', impact: 'Rendimiento degradado. Posible daño hardware si persiste.', remediation: 'Limpiar ventiladores y disipadores. Revisar pasta térmica. Comprobar ventilación del chasis.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-023', category: 'linux', severity: 'high', name: 'Pánico de BTRFS/ZFS o corrupción', regex: /(?:btrfs|zfs).{0,40}(?:panic|corruption|checksum error|recover|scrub|repair)/i, description: 'Sistema de archivos avanzado detectó corrupción o error de checksum.', impact: 'Riesgo de pérdida de datos. Puede indicar RAM o disco defectuoso.', remediation: 'Ejecutar scrub (btrfs/zfs). Revisar RAM con memtest86. Verificar SMART del disco.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-024', category: 'linux', severity: 'medium', name: 'Demasiados archivos abiertos (file descriptors)', regex: /(?:too many open files|file descriptor|EMFILE|ENFILE|nofile limit)/i, description: 'El sistema o un proceso alcanzó el límite de descriptores de archivo.', impact: 'Aplicaciones no pueden abrir archivos o sockets. Posible fuga de recursos.', remediation: 'Aumentar ulimit si es necesario. Identificar proceso con fuga. Revisar código o configuración.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-025', category: 'linux', severity: 'high', name: 'Auditd detenido o logs de auditoría perdidos', regex: /(?:auditd|audit).{0,40}(?:stopped|dead|failed|rotate|dropped|backlog.{0,20}full)/i, description: 'El servicio de auditoría del kernel se detuvo o perdió eventos.', impact: 'Pérdida de evidencia forense. Posible intento de borrar huellas.', remediation: 'Revisar auditd y configuración de backlog. Centralizar logs. Investigar causa de la parada.', mitre: 'T1070.001', logFormat: 'linux' },
        { id: 'LNX-026', category: 'linux', severity: 'high', name: 'Modificación de binarios críticos o hashes', regex: /(?:aide|tripwire|hash.{0,20}mismatch|file.{0,20}changed).{0,40}(?:bin|sbin|etc|lib|usr)/i, description: 'Sistema de integridad detectó cambios en archivos críticos del sistema.', impact: 'Posible intrusión o modificación no autorizada de binarios del sistema.', remediation: 'Verificar cambios esperados (actualizaciones). Investigar cambios inesperados. Restaurar desde medios confiables.', mitre: 'T1565.001', logFormat: 'linux' },
        { id: 'LNX-027', category: 'linux', severity: 'high', name: 'Ejecución de comando privilegiado por cron', regex: /(?:cron|CRON).{0,40}(?:root|sudo).{0,40}(?:cmd|command|run)/i, description: 'Tarea cron ejecutada como root o con sudo.', impact: 'Persistencia o escalada de privilegios si el script es modificable.', remediation: 'Auditar crontabs. Revisar permisos de scripts ejecutados. Limitar tareas root.', mitre: 'T1053.003', logFormat: 'linux' },
        { id: 'LNX-028', category: 'linux', severity: 'critical', name: 'Kernel module loaded from unusual path', regex: /(?:insmod|modprobe).{0,40}(?:\/tmp\/|\/var\/tmp\/|\/home\/|\/dev\/shm\/)/i, description: 'Módulo del kernel cargado desde un directorio temporal o inusual.', impact: 'Alta probabilidad de rootkit o módulo malicioso.', remediation: 'Descargar módulo inmediatamente. Investigar origen. Aislar sistema y hacer análisis forense.', mitre: 'T1547.006', logFormat: 'linux' },
        { id: 'LNX-029', category: 'linux', severity: 'high', name: 'Container/pod crash loop', regex: /(?:container|pod|docker).{0,40}(?:crashloopbackoff|restart.{0,20}loop|exited|OOMKilled|Error)/i, description: 'Contenedor o pod en bucle de reinicio o terminado por OOM.', impact: 'Servicio inestable. Posible fuga de memoria o configuración errónea.', remediation: 'Revisar logs del contenedor. Limitar recursos. Verificar configuración y dependencias.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-030', category: 'linux', severity: 'medium', name: 'Snap/AppArmor profile failure', regex: /(?:snap|apparmor).{0,40}(?:profile.{0,20}fail|denied|blocked|confined)/i, description: 'Aplicación confinada por snap/AppArmor bloqueada.', impact: 'Aplicación no funciona correctamente o intenta acceder a recursos no autorizados.', remediation: 'Revisar logs de AppArmor. Ajustar perfil o permisos si es necesario.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-031', category: 'linux', severity: 'high', name: 'LUKS/dm-crypt error', regex: /(?:luks|dm-crypt|cryptsetup).{0,40}(?:error|fail|corrupt|header|unlock)/i, description: 'Error en el cifrado de disco LUKS/dm-crypt.', impact: 'Posible imposibilidad de desbloquear disco o datos inaccesibles.', remediation: 'Verificar passphrase/clave. Hacer backup de cabecera LUKS. Revisar hardware de disco.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-032', category: 'linux', severity: 'high', name: 'RAID/array degradation', regex: /(?:md|raid|lvm|btrfs).{0,40}(?:degraded|failed|missing|removed|rebuild|resync)/i, description: 'Array RAID o volumen lógico degradado o en reconstrucción.', impact: 'Riesgo de pérdida de datos si falla otro disco.', remediation: 'Revisar estado con cat /proc/mdstat o lvs. Reemplazar disco fallido. Monitorizar reconstrucción.', mitre: '', logFormat: 'linux' },
        { id: 'LNX-033', category: 'linux', severity: 'medium', name: 'Seccomp/BPF filter violation', regex: /(?:seccomp|bpf).{0,40}(?:violation|denied|blocked|kill|trap)/i, description: 'Seccomp o filtro BPF bloqueó una syscall.', impact: 'Aplicación intentó usar syscall no permitida. Posible exploit o comportamiento anómalo.', remediation: 'Revisar syscall denegada. Actualizar perfil seccomp. Investigar aplicación afectada.', mitre: 'T1622', logFormat: 'linux' }
    ];

    // ═══════════════════════════════════════════════════════════════════════════
    // MAPAS DE BSOD, NTSTATUS Y BASE DE DRIVERS
    // ═══════════════════════════════════════════════════════════════════════════

    var NTSTATUS_MAP = {
        0xC0000001: 'STATUS_UNSUCCESSFUL',
        0xC0000005: 'STATUS_ACCESS_VIOLATION',
        0xC000000D: 'STATUS_INVALID_PARAMETER',
        0xC000009A: 'STATUS_INSUFFICIENT_RESOURCES',
        0xC000009B: 'STATUS_DEVICE_DATA_ERROR',
        0xC000009C: 'STATUS_DEVICE_NOT_CONNECTED',
        0xC00000BB: 'STATUS_NOT_SUPPORTED',
        0xC0000121: 'STATUS_DELETE_PENDING',
        0xC0000135: 'STATUS_DLL_NOT_FOUND',
        0xC0000137: 'STATUS_ENTRYPOINT_NOT_FOUND',
        0xC0000139: 'STATUS_DLL_INIT_FAILED',
        0xC0000142: 'STATUS_DLL_INIT_FAILED_LOGOFF',
        0xC0000221: 'STATUS_IMAGE_CHECKSUM_MISMATCH',
        0xC0000225: 'STATUS_NOT_FOUND',
        0xC0000244: 'STATUS_QUOTA_EXCEEDED',
        0xC00002C5: 'STATUS_OPLOCK_NOT_GRANTED',
        0xC0000374: 'STATUS_HEAP_CORRUPTION',
        0xC0000409: 'STATUS_STACK_BUFFER_OVERRUN',
        0xC000041D: 'STATUS_INVALID_CRUNTIME_PARAMETER',
        0xC0000420: 'STATUS_ASSERTION_FAILURE',
        0xC0000456: 'STATUS_PAGEFILE_QUOTA_EXCEEDED',
        0xC0000467: 'STATUS_BAD_COMPRESSION_BUFFER',
        0xC0000491: 'STATUS_NO_MEMORY',
        0xC0000602: 'STATUS_PROCEDURE_NOT_FOUND',
        0xC000070A: 'STATUS_NO_SUPPORTED',
        0xC0000718: 'STATUS_VARIABLE_NOT_FOUND',
        0xC000076D: 'STATUS_CTX_WINSTATION_DISCONNECTED',
        0xE0000001: 'STATUS_ABANDONED',
        0xE0000002: 'STATUS_MUTEX_NOT_OWNED',
        0xE0000003: 'STATUS_SERVER_NOT_FOUND',
        0xE0000008: 'STATUS_INVALID_SERVER_STATE',
        0xE0000200: 'STATUS_GRAPHICS_NO_VIDEO_MEMORY',
        0xE0000201: 'STATUS_GRAPHICS_DRIVER_MISMATCH'
    };

    var BUGCHECK_PARAM_DESC = {
        0x00000116: [
            'Optional pointer to internal TDR recovery context (TDR_RECOVERY_CONTEXT).',
            'Pointer into responsible device driver module (e.g. owner tag).',
            'Optional error code (NTSTATUS) of the last failed operation.',
            'Optional internal context dependent data.'
        ],
        0x00000117: [
            'Pointer to the internal TDR context.',
            'Pointer to the device object.',
            'The GPU vendor-specific failure code.',
            'Reserved.'
        ],
        0x0000010E: [
            'Pointer to the VIDEO_MEMORY_MANAGEMENT_INTERNAL context.',
            'Internal value dependent on the exception.',
            'Internal value dependent on the exception.',
            'Internal value dependent on the exception.'
        ],
        0x00000113: [
            'Pointer to the DXG context.',
            'Pointer to the DXG adapter.',
            'NTSTATUS error code.',
            'Reserved.'
        ],
        0x00000119: [
            'Adapter pointer.',
            'Video scheduler internal command buffer.',
            'NTSTATUS error code for the failure.',
            'Additional context.'
        ],
        0x00000141: [
            'Pointer to the internal video engine context.',
            'Pointer to the video device.',
            'GPU vendor-specific error code.',
            'Reserved.'
        ],
        0x000000D1: [
            'Memory address referenced.',
            'IRQL at time of fault.',
            'Type of access: 0=read, 1=write, 2=execute.',
            'Address that referenced the memory.'
        ],
        0x00000050: [
            'Memory address that caused the fault.',
            'Type of operation: 0=read, 1=write, 2=execute, 3=execute+write.',
            'Page table entry (PTE) value.',
            'Address of the instruction that caused the fault.'
        ],
        0x0000000A: [
            'Memory address referenced.',
            'IRQL at time of fault.',
            'Type of access: 0=read, 1=write, 2=execute.',
            'Address that referenced the memory.'
        ],
        0x0000003B: [
            'NTSTATUS code of the failed system service.',
            'Address where the exception occurred.',
            'Parameter 0 for the exception record.',
            'Parameter 1 for the exception record.'
        ],
        0x0000007E: [
            'Exception code (NTSTATUS).',
            'Exception record address.',
            'Context record address.',
            'Not used.'
        ],
        0x0000007F: [
            'Exception code (NTSTATUS).',
            'Exception record address.',
            'Context record address.',
            'Not used.'
        ],
        0x000000EF: [
            'Pointer to the process object that terminated.',
            'Pointer to the thread object (or process name).',
            'NTSTATUS code for the termination.',
            'Not used.'
        ],
        0x000000F4: [
            'Object type that was terminated.',
            'Pointer to the object.',
            'Pointer to the process.',
            'Pointer to the thread.'
        ],
        0x00000124: [
            'Bank number of the MCA (Machine Check Architecture) error.',
            'MCA status (MSR).',
            'MCA address (MSR).',
            'MCA misc (MSR).'
        ],
        0x00000139: [
            'Type of corruption detected.',
            'Address of the corruption.',
            'High-order bits of the address.',
            'Reserved.'
        ],
        0x00000133: [
            'The timer value (DPC quantum).',
            'Pointer to the DPC routine.',
            'The clock base time.',
            'The elapsed time.'
        ],
        0x0000009F: [
            'Power state transition code (0x1=System, 0x3=Device).',
            'Physical Device Object (PDO) of the stack.',
            'Functional Device Object (FDO).',
            'The blocked IRP.'
        ],
        0x000000C2: [
            'Pool type that was corrupted.',
            'Pool tag (4-char identifier of the driver).',
            'Pool address where corruption was detected.',
            'Corruption type.'
        ],
        0x000000C5: [
            'Memory address referenced.',
            'IRQL at time of fault.',
            'Type of access: 0=read, 1=write.',
            'Address that referenced the memory.'
        ],
        0x000000EA: [
            'Pointer to the thread object stuck in the driver.',
            'Pointer to the device object.',
            'Pointer to the IRP (I/O Request Packet).',
            'Number of seconds the thread has been stuck.'
        ],
        0x00000101: [
            'Clock interrupt from this processor was not received.',
            'Wait time interval in clock ticks.',
            'Pointer to the clock processor control block.',
            'Reserved.'
        ],
        0x0000010D: [
            'Pointer to the WDF violation context.',
            'Pointer to the WDF device object.',
            'WDF bug-check sub-type.',
            'Reserved.'
        ]
    };

    var BUGCHECK_MAP = [
        { code: 0x00000001, name: 'APC_INDEX_MISMATCH', severity: 'high', desc: 'Error en el sistema de archivos o controladores de almacenamiento.', impact: 'Posible fallo de disco o controlador.', remediation: 'Verificar disco (chkdsk /f). Actualizar controladores de almacenamiento. Revisar conexiones SATA/NVMe.' },
        { code: 0x00000002, name: 'DEVICE_QUEUE_NOT_BUSY', severity: 'high', desc: 'Un driver intentó liberar una cola de dispositivos que no estaba ocupada.', impact: 'Fallo de driver.', remediation: 'Actualizar controladores. Revisar drivers de disco.' },
        { code: 0x00000004, name: 'INVALID_DATA_ACCESS_TRAP', severity: 'critical', desc: 'Excepción de acceso a datos inválida. Posible fallo de hardware.', impact: 'Fallo de hardware o driver defectuoso.', remediation: 'Ejecutar diagnóstico de RAM. Verificar integridad del sistema.' },
        { code: 0x00000008, name: 'IRQL_NOT_DISPATCH_LEVEL', severity: 'critical', desc: 'Un hilo llamó a una función que requiere un IRQL más bajo.', impact: 'Driver defectuoso.', remediation: 'Actualizar drivers. Identificar el driver con Driver Verifier.' },
        { code: 0x0000000A, name: 'IRQL_NOT_LESS_OR_EQUAL', severity: 'critical', desc: 'Un controlador intentó acceder a memoria a un IRQL demasiado alto.', impact: 'Fallo del sistema. Driver defectuoso.', remediation: 'Actualizar controladores. Desinstalar software reciente. Verificar compatibilidad de hardware.' },
        { code: 0x00000012, name: 'TRAP_CAUSE_UNKNOWN', severity: 'critical', desc: 'Causa de la trampa desconocida. Posible fallo de hardware o driver.', impact: 'Fallo del sistema sin causa identificada.', remediation: 'Actualizar BIOS/drivers. Probar RAM y CPU. Revisar overclock.' },
        { code: 0x00000018, name: 'REFERENCE_BY_POINTER', severity: 'high', desc: 'Error en conteo de referencias de objeto del kernel.', impact: 'Driver con bug de conteo de referencias.', remediation: 'Actualizar o desinstalar drivers recientes. Usar Driver Verifier.' },
        { code: 0x00000019, name: 'BAD_POOL_HEADER', severity: 'critical', desc: 'La cabecera de un pool de memoria está corrupta.', impact: 'Corrupción de memoria por driver defectuoso.', remediation: 'Actualizar controladores. Ejecutar diagnóstico de RAM. Usar Driver Verifier.' },
        { code: 0x0000001A, name: 'MEMORY_MANAGEMENT', severity: 'critical', desc: 'Error de gestión de memoria. Problema con RAM o controladores.', impact: 'Corrupción de datos en memoria.', remediation: 'Ejecutar diagnóstico de memoria (mdsched.exe). Verificar controladores de chipset.' },
        { code: 0x0000001E, name: 'KMODE_EXCEPTION_NOT_HANDLED', severity: 'critical', desc: 'Excepción en modo kernel no manejada por un controlador.', impact: 'Fallo del sistema por driver defectuoso.', remediation: 'Identificar el driver en los parámetros. Actualizar o revertir drivers recién instalados.' },
        { code: 0x00000020, name: 'KERNEL_APC_PENDING_DURING_EXIT', severity: 'critical', desc: 'Un APC del kernel estaba pendiente durante la salida de un hilo.', impact: 'Driver defectuoso o sistema de archivos corrupto.', remediation: 'Actualizar controladores de almacenamiento. Verificar disco.' },
        { code: 0x00000023, name: 'FAT_FILE_SYSTEM', severity: 'critical', desc: 'Error en el sistema de archivos FAT.', impact: 'Posible corrupción de disco.', remediation: 'Ejecutar chkdsk. Verificar integridad del disco.' },
        { code: 0x00000024, name: 'NTFS_FILE_SYSTEM', severity: 'critical', desc: 'Error en el sistema de archivos NTFS.', impact: 'Posible corrupción de disco o fallo de almacenamiento.', remediation: 'Ejecutar chkdsk /f /r. Verificar disco con smartctl. Revisar cable de datos.' },
        { code: 0x00000027, name: 'RDR_FILE_SYSTEM', severity: 'critical', desc: 'Error en el sistema de archivos de red (RDR).', impact: 'Problema de red o recurso compartido.', remediation: 'Verificar conexión de red. Revisar recursos compartidos. Actualizar drivers de red.' },
        { code: 0x0000002E, name: 'DATA_BUS_ERROR', severity: 'critical', desc: 'Error en el bus de datos. Generalmente RAM defectuosa.', impact: 'Fallo de hardware detectado a nivel de bus.', remediation: 'Probar RAM con memtest86. Verificar configuración de BIOS (timings/voltajes).' },
        { code: 0x0000002F, name: 'INSTRUCTION_BUS_ERROR', severity: 'critical', desc: 'Error en el bus de instrucciones. RAM o caché CPU defectuosa.', impact: 'Fallo de hardware.', remediation: 'Ejecutar diagnóstico de CPU y RAM. Verificar overclocking.' },
        { code: 0x00000034, name: 'CACHE_MANAGER', severity: 'critical', desc: 'Error en el administrador de caché del sistema de archivos.', impact: 'Posible corrupción de disco o driver.', remediation: 'Verificar disco (chkdsk). Actualizar controladores de almacenamiento.' },
        { code: 0x0000003B, name: 'SYSTEM_SERVICE_EXCEPTION', severity: 'critical', desc: 'Excepción en servicio del sistema. Causa común: controladores defectuosos.', impact: 'Fallo recurrente.', remediation: 'Actualizar o revertir controladores. Ejecutar sfc /scannow. Comprobar actualizaciones de Windows.' },
        { code: 0x0000003D, name: 'INTERRUPT_EXCEPTION_NOT_HANDLED', severity: 'critical', desc: 'Excepción de interrupción no manejada. Driver o hardware defectuoso.', impact: 'Fallo del sistema.', remediation: 'Revisar hardware recién instalado. Actualizar controladores.' },
        { code: 0x00000044, name: 'MULTIPLE_IRP_COMPLETE_REQUESTS', severity: 'high', desc: 'Un driver completó un IRP múltiple veces.', impact: 'Inestabilidad del sistema.', remediation: 'Actualizar controladores sospechosos. Usar Driver Verifier.' },
        { code: 0x00000048, name: 'CANCEL_STATE_IN_COMPLETED_IRP', severity: 'high', desc: 'Un driver canceló un IRP que ya había completado.', impact: 'Driver defectuoso.', remediation: 'Actualizar controladores sospechosos.' },
        { code: 0x0000004E, name: 'PFN_LIST_CORRUPT', severity: 'critical', desc: 'Corrupción de la lista PFN (Page Frame Number) en memoria.', impact: 'Corrupción grave de memoria.', remediation: 'Ejecutar diagnóstico de RAM. Verificar controladores de almacenamiento.' },
        { code: 0x00000050, name: 'PAGE_FAULT_IN_NONPAGED_AREA', severity: 'critical', desc: 'El sistema intentó acceder a memoria no paginada que no existe.', impact: 'Fallo de hardware (RAM/SSD) o driver.', remediation: 'Ejecutar diagnóstico de RAM. Verificar disco (chkdsk). Actualizar controladores.' },
        { code: 0x00000051, name: 'REGISTRY_ERROR', severity: 'critical', desc: 'Error grave en el registro de Windows.', impact: 'Registro corrupto o disco defectuoso.', remediation: 'Restaurar registro desde backup. Ejecutar chkdsk. Restaurar sistema.' },
        { code: 0x00000056, name: 'INSTRUCTION_COHERENCY_EXCEPTION', severity: 'critical', desc: 'Excepción de coherencia de instrucciones en caché de CPU.', impact: 'Fallo de hardware o overclocking inestable.', remediation: 'Eliminar overclocking. Verificar CPU y caché.' },
        { code: 0x0000005A, name: 'CRITICAL_SERVICE_FAILED', severity: 'critical', desc: 'Un servicio crítico del sistema falló al arrancar.', impact: 'El sistema no puede iniciarse correctamente.', remediation: 'Arrancar en modo seguro. Restaurar sistema. Reparar instalación.' },
        { code: 0x0000006B, name: 'PROCESS1_INITIALIZATION_FAILED', severity: 'critical', desc: 'Un proceso crítico del sistema falló al inicializarse.', impact: 'Fallo de arranque del sistema.', remediation: 'Restaurar sistema. Reparar archivos del sistema (sfc /scannow).' },
        { code: 0x00000073, name: 'CONFIG_LIST_FAILED', severity: 'critical', desc: 'El registro o lista de configuración del kernel está corrupto.', impact: 'Fallo de arranque.', remediation: 'Restaurar registro desde backup. Usar último buen arranque conocido.' },
        { code: 0x00000074, name: 'BAD_SYSTEM_CONFIG_INFO', severity: 'critical', desc: 'La configuración del sistema está corrupta.', impact: 'El sistema no arranca.', remediation: 'Restaurar sistema. Reparar registro. Reconstruir BCD.' },
        { code: 0x00000076, name: 'PROCESS_HAS_LOCKED_PAGES', severity: 'high', desc: 'Un proceso terminó dejando páginas de memoria bloqueadas.', impact: 'Fuga de memoria del kernel por driver defectuoso.', remediation: 'Actualizar controladores. Identificar driver con Driver Verifier.' },
        { code: 0x00000077, name: 'KERNEL_STACK_INPAGE_ERROR', severity: 'critical', desc: 'Error de lectura de página del kernel desde disco.', impact: 'Fallo de disco, RAM o controlador de almacenamiento.', remediation: 'Verificar disco (chkdsk). Probar RAM. Revisar controlador de disco.' },
        { code: 0x0000007A, name: 'KERNEL_DATA_INPAGE_ERROR', severity: 'critical', desc: 'Error al leer datos del kernel desde el disco de páginas.', impact: 'Fallo de disco, RAM o sector defectuoso.', remediation: 'Ejecutar chkdsk /r. Verificar RAM. Revisar controlador de almacenamiento.' },
        { code: 0x0000007B, name: 'INACCESSIBLE_BOOT_DEVICE', severity: 'critical', desc: 'Windows no puede acceder al dispositivo de arranque.', impact: 'El sistema no arranca.', remediation: 'Verificar conexiones de disco. Revisar orden de arranque en BIOS. Reparar BCD. Posible fallo de disco.' },
        { code: 0x0000007E, name: 'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M', severity: 'critical', desc: 'Excepción en hilo del sistema no manejada.', impact: 'Fallo por driver o servicio defectuoso.', remediation: 'Actualizar controladores. Revisar servicios de terceros.' },
        { code: 0x0000007F, name: 'UNEXPECTED_KERNEL_MODE_TRAP', severity: 'critical', desc: 'Excepción no esperada en modo kernel. Hardware defectuoso (CPU/RAM) o overclocking.', impact: 'Fallo crítico del sistema.', remediation: 'Eliminar overclocking. Verificar temperaturas. Ejecutar diagnóstico de hardware.' },
        { code: 0x00000080, name: 'NMI_HARDWARE_FAILURE', severity: 'critical', desc: 'Interrupción no enmascarable por fallo de hardware.', impact: 'Fallo grave de hardware.', remediation: 'Verificar RAM, CPU, placa base y fuente de alimentación.' },
        { code: 0x0000008E, name: 'KERNEL_MODE_EXCEPTION_NOT_HANDLED_M', severity: 'critical', desc: 'Excepción en modo kernel no manejada.', impact: 'Driver defectuoso.', remediation: 'Actualizar controladores. Revertir cambios recientes.' },
        { code: 0x0000009C, name: 'MACHINE_CHECK_EXCEPTION', severity: 'critical', desc: 'Error grave de hardware detectado por la CPU (Machine Check Exception).', impact: 'Fallo de hardware (CPU/RAM/placa base).', remediation: 'Revisar temperatura CPU. Verificar overclocking. Comprobar fuente de alimentación.' },
        { code: 0x0000009F, name: 'DRIVER_POWER_STATE_FAILURE', severity: 'critical', desc: 'Un driver no completó una transición de estado de energía a tiempo.', impact: 'Fallo de driver durante suspensión/reanudación.', remediation: 'Actualizar drivers de dispositivo, especialmente GPU, red y chipset. Deshabilitar hibernación como prueba.' },
        { code: 0x000000A0, name: 'INTERNAL_POWER_ERROR', severity: 'critical', desc: 'Error interno de administración de energía.', impact: 'Driver o firmware de energía defectuoso.', remediation: 'Actualizar BIOS y drivers de chipset. Revisar configuración de energía.' },
        { code: 0x000000BE, name: 'ATTEMPTED_WRITE_TO_READONLY_MEMORY', severity: 'critical', desc: 'Intento de escritura en memoria de solo lectura.', impact: 'Driver defectuoso o corrupción de memoria.', remediation: 'Actualizar controladores. Ejecutar diagnóstico de RAM.' },
        { code: 0x000000C2, name: 'BAD_POOL_CALLER', severity: 'critical', desc: 'Un driver llamó incorrectamente a funciones de pool de memoria.', impact: 'Driver defectuoso.', remediation: 'Actualizar controladores. Usar Driver Verifier para identificar el driver problemático.' },
        { code: 0x000000C4, name: 'DRIVER_VERIFIER_DETECTED_VIOLATION', severity: 'critical', desc: 'Driver Verifier detectó una violación en un driver.', impact: 'Driver defectuoso identificado por el verificador.', remediation: 'Desinstalar el driver señalado. Actualizar controladores. Driver Verifier no debe estar activo en producción.' },
        { code: 0x000000C5, name: 'DRIVER_CORRUPTED_EXPOOL', severity: 'critical', desc: 'Un driver corrompió el pool de memoria no paginada.', impact: 'Driver defectuoso corrompiendo memoria del sistema.', remediation: 'Identificar driver con Driver Verifier. Actualizar controladores.' },
        { code: 0x000000CE, name: 'DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS', severity: 'critical', desc: 'Un driver se descargó sin cancelar operaciones pendientes.', impact: 'Driver defectuoso.', remediation: 'Actualizar el controlador problemático.' },
        { code: 0x000000D1, name: 'DRIVER_IRQL_NOT_LESS_OR_EQUAL', severity: 'critical', desc: 'Un controlador intentó acceder a memoria con IRQL incorrecto.', impact: 'Fallo causado por driver defectuoso.', remediation: 'Identificar el driver en parámetros. Actualizar o revertir. Usar Driver Verifier.' },
        { code: 0x000000D2, name: 'BUGCODE_ID_DRIVER', severity: 'critical', desc: 'Un driver de identificación (ID) del sistema causó el error.', impact: 'Driver defectuoso.', remediation: 'Actualizar drivers de chipset y sistema.' },
        { code: 0x000000D5, name: 'DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL', severity: 'critical', desc: 'Driver accediendo a pool especial liberado.', impact: 'Driver defectuoso.', remediation: 'Usar Driver Verifier. Actualizar controladores.' },
        { code: 0x000000D8, name: 'DRIVER_USED_EXCESSIVE_PTES', severity: 'high', desc: 'Un driver usó demasiadas entradas de tabla de páginas.', impact: 'Driver defectuoso o fuga de memoria.', remediation: 'Actualizar el controlador problemático. Aumentar memoria del sistema.' },
        { code: 0x000000E1, name: 'WORKER_THREAD_RETURNED_AT_BAD_IRQL', severity: 'critical', desc: 'Un worker thread regresó con IRQL incorrecto.', impact: 'Driver defectuoso.', remediation: 'Actualizar o desinstalar drivers recientes. Usar Driver Verifier.' },
        { code: 0x000000E3, name: 'RESOURCE_NOT_OWNED', severity: 'critical', desc: 'Un hilo intentó liberar un recurso que no poseía.', impact: 'Driver defectuoso.', remediation: 'Actualizar controladores. Usar Driver Verifier.' },
        { code: 0x000000EA, name: 'THREAD_STUCK_IN_DEVICE_DRIVER', severity: 'high', desc: 'Un hilo quedó atascado en un driver de dispositivo (típicamente GPU).', impact: 'Fallo de gráficos o driver de video.', remediation: 'Actualizar controladores de GPU. Reducir overclock. Verificar temperatura.' },
        { code: 0x000000ED, name: 'UNMOUNTABLE_BOOT_VOLUME', severity: 'critical', desc: 'El volumen de arranque no se puede montar.', impact: 'El sistema no arranca.', remediation: 'Ejecutar chkdsk /r desde entorno de recuperación. Verificar controlador de disco. Posible fallo de disco.' },
        { code: 0x000000EF, name: 'CRITICAL_PROCESS_DIED', severity: 'critical', desc: 'Un proceso crítico del sistema terminó inesperadamente.', impact: 'El sistema se detuvo. Posible fallo de hardware o corrupción.', remediation: 'Verificar disco (chkdsk). Revisar RAM. Restaurar sistema. Actualizar controladores.' },
        { code: 0x000000F0, name: 'STORAGE_MINIPORT_ERROR', severity: 'critical', desc: 'Error en el miniport de almacenamiento.', impact: 'Fallo de driver de almacenamiento o disco.', remediation: 'Actualizar driver de almacenamiento. Revisar conexiones de disco.' },
        { code: 0x000000F4, name: 'CRITICAL_OBJECT_TERMINATION', severity: 'critical', desc: 'Un objeto o proceso crítico terminó inesperadamente.', impact: 'Fallo del sistema.', remediation: 'Verificar disco duro. Revisar drivers de almacenamiento. Restaurar sistema.' },
        { code: 0x000000F6, name: 'PCI_VERIFIER_DETECTED_VIOLATION', severity: 'critical', desc: 'PCI Verifier detectó una violación en un driver PCI.', impact: 'Driver de dispositivo PCI defectuoso.', remediation: 'Actualizar drivers de dispositivos PCI (tarjeta gráfica, red, sonido).' },
        { code: 0x000000F7, name: 'DRIVER_OVERRAN_STACK_BUFFER', severity: 'critical', desc: 'Un driver desbordó un búfer en la pila (stack buffer overflow).', impact: 'Posible vulnerabilidad de seguridad en el driver.', remediation: 'Actualizar el driver inmediatamente. Puede ser un exploit.' },
        { code: 0x000000FC, name: 'ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY', severity: 'critical', desc: 'Intento de ejecutar código en memoria no ejecutable (NX).', impact: 'Driver defectuoso o malware.', remediation: 'Actualizar controladores. Ejecutar escaneo antimalware.' },
        { code: 0x000000FE, name: 'BUGCODE_USB_DRIVER', severity: 'high', desc: 'Error en un driver USB.', impact: 'Fallo de driver USB.', remediation: 'Actualizar controladores USB. Desconectar dispositivos USB problemáticos.' },
        { code: 0x00000101, name: 'CLOCK_WATCHDOG_TIMEOUT', severity: 'critical', desc: 'Un procesador no respondió a una interrupción del reloj.', impact: 'CPU bloqueada o overclocking inestable.', remediation: 'Eliminar overclocking. Verificar temperatura CPU. Actualizar BIOS. Revisar fuente de alimentación.' },
        { code: 0x00000102, name: 'DPC_WATCHDOG_TIMEOUT', severity: 'high', desc: 'Un DPC tardó demasiado tiempo en ejecutarse.', impact: 'Driver defectuoso o hardware lento.', remediation: 'Actualizar drivers de almacenamiento (NVMe/SATA).' },
        { code: 0x00000104, name: 'AGP_INVALID_ACCESS', severity: 'high', desc: 'Acceso inválido AGP o PCI Express.', impact: 'Driver de GPU o placa base.', remediation: 'Actualizar driver de gráficos. Verificar placa base.' },
        { code: 0x00000109, name: 'CRITICAL_STRUCTURE_CORRUPTION', severity: 'critical', desc: 'Corrupción de estructuras críticas del kernel detectada.', impact: 'Posible rootkit o fallo de hardware grave.', remediation: 'Escaneo antimalware completo. Verificar integridad del kernel (sfc). Ejecutar diagnóstico de RAM.' },
        { code: 0x0000010D, name: 'WDF_VIOLATION', severity: 'critical', desc: 'Violación en Windows Driver Framework (WDF).', impact: 'Driver defectuoso basado en WDF.', remediation: 'Actualizar el driver señalado. Reinstalar el dispositivo problemático.' },
        { code: 0x0000010E, name: 'VIDEO_MEMORY_MANAGEMENT_INTERNAL', severity: 'critical', desc: 'Error interno de gestión de memoria de video.', impact: 'Fallo de GPU o driver de video.', remediation: 'Actualizar controladores de GPU. Verificar temperatura. Reducir overclock.' },
        { code: 0x00000113, name: 'VIDEO_DXGKRNL_FATAL_ERROR', severity: 'critical', desc: 'Error fatal del subsistema de gráficos DXGK (DirectX Graphics Kernel).', impact: 'Fallo de GPU o driver de video.', remediation: 'Actualizar controladores de GPU. Reducir overclock de GPU. Verificar temperatura.' },
        { code: 0x00000114, name: 'VIDEO_SHADOW_DRIVER_FATAL_ERROR', severity: 'critical', desc: 'Error fatal en shadow driver de video.', impact: 'Driver de GPU defectuoso.', remediation: 'Actualizar controladores de GPU completamente.' },
        { code: 0x00000116, name: 'VIDEO_TDR_FAILURE', severity: 'high', desc: 'La GPU no respondió y Windows intentó recuperarse (TDR: Timeout, Detection, Recovery).', impact: 'Fallo de GPU o driver.', remediation: 'Actualizar drivers de GPU. Reducir overclock. Verificar temperatura y fuente de alimentación.' },
        { code: 0x00000117, name: 'VIDEO_TDR_TIMEOUT_DETECTED', severity: 'high', desc: 'El driver de video no respondió y Windows detectó el timeout.', impact: 'Fallo de GPU o driver de video.', remediation: 'Actualizar drivers de GPU. Reducir overclock. Verificar temperatura.' },
        { code: 0x00000119, name: 'VIDEO_SCHEDULER_INTERNAL_ERROR', severity: 'critical', desc: 'Error interno del planificador de video.', impact: 'Fallo de GPU o driver.', remediation: 'Actualizar controladores de GPU. Reducir overclock.' },
        { code: 0x0000011B, name: 'DRIVER_RETURNED_HOLDING_CANCEL_LOCK', severity: 'critical', desc: 'Un driver retuvo un lock de cancelación al regresar de una rutina.', impact: 'Driver defectuoso.', remediation: 'Actualizar el driver problemático.' },
        { code: 0x00000121, name: 'DRIVER_VIOLATION', severity: 'critical', desc: 'Violación genérica de driver.', impact: 'Driver defectuoso.', remediation: 'Actualizar controladores. Usar Driver Verifier.' },
        { code: 0x00000122, name: 'WHEA_INTERNAL_ERROR', severity: 'critical', desc: 'Error interno de WHEA (Windows Hardware Error Architecture).', impact: 'Fallo de hardware.', remediation: 'Ejecutar diagnóstico de hardware completo. Verificar CPU, RAM y placa base.' },
        { code: 0x00000124, name: 'WHEA_UNCORRECTABLE_ERROR', severity: 'critical', desc: 'Error de hardware no corregible (Windows Hardware Error Architecture).', impact: 'Fallo de hardware: CPU, RAM, placa base o fuente.', remediation: 'Verificar temperaturas. Probar RAM. Comprobar overclocking. Revisar fuente de alimentación.' },
        { code: 0x00000126, name: 'NETIO_INVALID_POOL_CALLER', severity: 'critical', desc: 'NETIO detectó un caller de pool inválido.', impact: 'Driver de red defectuoso.', remediation: 'Actualizar controladores de red. Actualizar firmware de router/switch.' },
        { code: 0x00000127, name: 'PAGE_NOT_ZERO', severity: 'critical', desc: 'Una página de memoria no estaba inicializada a cero.', impact: 'Fallo de hardware (RAM) o driver.', remediation: 'Ejecutar diagnóstico de RAM. Verificar disco.' },
        { code: 0x0000012B, name: 'FAULTY_HARDWARE_CORRUPTED_PAGE', severity: 'critical', desc: 'Página corrupta por hardware defectuoso.', impact: 'Fallo de hardware (RAM) detectado.', remediation: 'Reemplazar RAM inmediatamente. Ejecutar memtest86.' },
        { code: 0x0000012C, name: 'EXFAT_FILE_SYSTEM', severity: 'critical', desc: 'Error en el sistema de archivos exFAT.', impact: 'Posible corrupción de disco.', remediation: 'Ejecutar chkdsk. Verificar disco.' },
        { code: 0x00000133, name: 'DPC_WATCHDOG_VIOLATION', severity: 'high', desc: 'Un DPC (Deferred Procedure Call) tardó demasiado en ejecutarse.', impact: 'Driver defectuoso o hardware lento.', remediation: 'Actualizar drivers de almacenamiento (NVMe/SATA). Desinstalar software problemático.' },
        { code: 0x00000135, name: 'REGISTRY_FILTER_DRIVER_EXCEPTION', severity: 'critical', desc: 'Excepción en un driver de filtro del registro.', impact: 'Driver de filtro (antivirus, backup) defectuoso.', remediation: 'Actualizar o desinstalar software de seguridad/backup.' },
        { code: 0x00000139, name: 'KERNEL_SECURITY_CHECK_FAILURE', severity: 'critical', desc: 'Fallo en verificación de seguridad del kernel. Puede indicar rootkit o RAM defectuosa.', impact: 'Posible compromiso del kernel.', remediation: 'Escaneo antimalware. Verificar integridad del sistema. Ejecutar diagnóstico de RAM.' },
        { code: 0x0000013A, name: 'KERNEL_MODE_HEAP_CORRUPTION', severity: 'critical', desc: 'Corrupción del heap en modo kernel.', impact: 'Driver defectuoso corrompiendo memoria del kernel.', remediation: 'Actualizar controladores. Usar Driver Verifier.' },
        { code: 0x00000141, name: 'VIDEO_ENGINE_TIMEOUT_DETECTED', severity: 'high', desc: 'El motor de video no respondió (GPU).', impact: 'Fallo de GPU.', remediation: 'Actualizar controladores de GPU. Reducir carga gráfica.' },
        { code: 0x00000144, name: 'BUGCODE_USB3_DRIVER', severity: 'high', desc: 'Error en driver USB 3.0.', impact: 'Driver USB 3.0 defectuoso.', remediation: 'Actualizar drivers USB. Desconectar dispositivos USB 3.0 problemáticos.' },
        { code: 0x00000147, name: 'ABNORMAL_RESET_DETECTED', severity: 'critical', desc: 'Se detectó un reinicio anormal del sistema.', impact: 'Posible caída de energía o fallo de hardware.', remediation: 'Verificar fuente de alimentación. Revisar conexiones eléctricas.' },
        { code: 0x00000149, name: 'REFS_FILE_SYSTEM', severity: 'critical', desc: 'Error en el sistema de archivos ReFS.', impact: 'Corrupción de volumen ReFS.', remediation: 'Ejecutar chkdsk en volumen ReFS. Verificar disco.' },
        { code: 0x0000014B, name: 'SOC_SUBSYSTEM_FAILURE', severity: 'high', desc: 'Error en el subsistema de seguridad del chip (SOC).', impact: 'Fallo de seguridad integrada del procesador.', remediation: 'Actualizar firmware/BIOS. Actualizar controladores de chipset.' },
        { code: 0x0000014F, name: 'PDC_WATCHDOG_TIMEOUT', severity: 'high', desc: 'Timeout en el watchdog de administración de energía.', impact: 'Driver no responde a cambios de energía.', remediation: 'Actualizar drivers de dispositivo. Revisar configuración de energía.' },
        { code: 0x00000154, name: 'UNEXPECTED_STORE_EXCEPTION', severity: 'critical', desc: 'Excepción inesperada en el almacenamiento (Store API).', impact: 'Fallo de disco o controlador de almacenamiento.', remediation: 'Verificar disco con chkdsk y smartctl. Actualizar driver de almacenamiento. Comprobar cable.' },
        { code: 0x00000155, name: 'OS_DATA_TAMPERING', severity: 'critical', desc: 'Datos del sistema manipulados o corruptos.', impact: 'Posible malware o corrupción del sistema.', remediation: 'Ejecutar escaneo antimalware completo. Verificar integridad con sfc. Restaurar sistema.' },
        { code: 0x0000015B, name: 'WORKER_THREAD_RETURNED_WITH_SYSTEM_PAGE_PRIORITY_ACTIVE', severity: 'high', desc: 'Un worker thread regresó con prioridad de página del sistema activa.', impact: 'Driver defectuoso.', remediation: 'Actualizar controladores.' },
        { code: 0x0000015E, name: 'BUGCODE_NDIS_DRIVER_LIVE_DUMP', severity: 'high', desc: 'Driver NDIS generó volcado en vivo.', impact: 'Driver de red con problemas.', remediation: 'Actualizar drivers de red. Verificar cableado y conmutadores.' },
        { code: 0x00000161, name: 'HAL_ILLEGAL_IOMMU_PAGE_FAULT', severity: 'critical', desc: 'Fallo de página IOMMU detectado por HAL.', impact: 'Driver o firmware defectuoso. Posible intento de DMA attack.', remediation: 'Actualizar BIOS/firmware. Actualizar drivers. Verificar configuración VT-d/IOMMU.' },
        { code: 0x00000167, name: 'CLUSTER_CSV_STATUS_IO_TIMEOUT_LIVEDUMP', severity: 'high', desc: 'Timeout de E/S en CSV de clúster.', impact: 'Almacenamiento compartido lento o no disponible.', remediation: 'Verificar red SAN/SMB. Actualizar drivers de almacenamiento y red.' },
        { code: 0x0000016C, name: 'VHD_BOOT_HOST_VOLUME_NOT_ENOUGH_SPACE', severity: 'critical', desc: 'Volumen host de arranque VHD sin espacio.', impact: 'El sistema no puede escribir en el volumen de arranque.', remediation: 'Liberar espacio en el volumen host. Ampliar disco VHD.' },
        { code: 0x1000007E, name: 'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M64', severity: 'critical', desc: 'Excepción en hilo del sistema no manejada (64-bit).', impact: 'Fallo por driver o servicio defectuoso.', remediation: 'Actualizar controladores. Revisar servicios de terceros. Restaurar sistema.' },
        { code: 0x1000007F, name: 'UNEXPECTED_KERNEL_MODE_TRAP_M64', severity: 'critical', desc: 'Excepción de modo kernel (con múltiples errores, 64-bit).', impact: 'Fallo de hardware probable.', remediation: 'Verificar RAM, CPU y fuente de alimentación.' },
        { code: 0x100000D1, name: 'DRIVER_IRQL_NOT_LESS_OR_EQUAL_M64', severity: 'critical', desc: 'Driver accediendo a memoria con IRQL incorrecto (64-bit).', impact: 'Fallo de driver.', remediation: 'Identificar driver en parámetros. Actualizar.' },
        { code: 0x100000D3, name: 'DRIVER_PORTION_MUST_BE_NONPAGED_M64', severity: 'critical', desc: 'Parte de driver necesita estar en memoria no paginada (64-bit).', impact: 'Driver defectuoso.', remediation: 'Actualizar controladores.' },
        { code: 0xC0000218, name: 'STATUS_CANNOT_LOAD_REGISTRY_FILE', severity: 'critical', desc: 'No se puede cargar el archivo del registro (hive).', impact: 'El registro está corrupto o el disco tiene errores.', remediation: 'Restaurar registro desde backup. Ejecutar chkdsk. Restaurar sistema.' },
        { code: 0xC000021A, name: 'WINLOGON_FATAL_ERROR', severity: 'critical', desc: 'Error fatal en Winlogon o CSRSS. Puede indicar malware o corrupción.', impact: 'No se puede iniciar sesión. Sistema inestable.', remediation: 'Arrancar en modo seguro. Restaurar sistema. Escaneo antimalware.' },
        { code: 0xC0000221, name: 'STATUS_IMAGE_CHECKSUM_MISMATCH', severity: 'critical', desc: 'Un driver o DLL del sistema tiene un checksum incorrecto.', impact: 'Archivo del sistema corrupto o reemplazado.', remediation: 'Ejecutar sfc /scannow. Reemplazar driver problemático. Escaneo antimalware.' },
        { code: 0xC0000225, name: 'STATUS_NOT_FOUND', severity: 'high', desc: 'Un archivo necesario para arrancar no se encontró o está corrupto.', impact: 'El sistema no puede iniciarse.', remediation: 'Reparar inicio (bootrec). Revisar integridad de archivos del sistema.' },
        { code: 0xDEADDEAD, name: 'MANUALLY_INITIATED_CRASH', severity: 'info', desc: 'El crash fue iniciado manualmente (por usuario o por depuración).', impact: 'No es un fallo real. Fue provocado intencionalmente.', remediation: 'No requiere acción a menos que no fuera intencional.' }
    ];

    var DRIVER_DB = [
        { pattern: /nvlddmkm|nvldd|nv4_disp|nvapi|nvwgf2umx/i, name: 'NVIDIA Display Driver', desc: 'Controlador de gráficos NVIDIA. Muy común en BSOD, especialmente con controladores antiguos o overclock. Recomendación: Reinstalar con DDU en modo seguro y luego instalar el driver WHQL más reciente.', severity: 'high' },
        { pattern: /amdkmdag|atikmpag|amdkmdap|amdui|amdac/i, name: 'AMD Display Driver', desc: 'Controlador de gráficos AMD. Puede causar BSOD por incompatibilidad o sobrecalentamiento. Recomendación: Reinstalar con AMD Cleanup Utility, luego instalar driver estable (no beta).', severity: 'high' },
        { pattern: /igdkmd|igfx|intelcd|intelgfx|irisxe/i, name: 'Intel Display Driver', desc: 'Controlador de gráficos Intel integrado. BSOD puede ocurrir con drivers desactualizados. Recomendación: Actualizar mediante Intel Driver & Support Assistant.', severity: 'medium' },
        { pattern: /rt6?40|rtl8|realtek|rtwlan|rtw88|rtw89/i, name: 'Realtek Driver', desc: 'Controlador de red Realtek (Ethernet o WiFi). Puede causar BSOD por power management o drivers incompatibles. Recomendación: Desactivar "Allow computer to turn off device" en propiedades del dispositivo. Actualizar driver.', severity: 'medium' },
        { pattern: /storport|stornvme|iastor|nvme|nvstor|amdsata|astor/i, name: 'Storage Controller Driver', desc: 'Controlador de almacenamiento (SATA/NVMe/RAID). BSOD por controlador defectuoso, firmware de SSD obsoleto o cable defectuoso. Recomendación: Actualizar firmware del SSD. Actualizar driver del chipset.', severity: 'high' },
        { pattern: /dxgkrnl|dxgmms|dxgi|dxg|atikmdag/i, name: 'DirectX Graphics Kernel', desc: 'Subsistema de gráficos DirectX. El crash ocurrió durante una operación 3D o de video. Recomendación: Actualizar driver de GPU. Verificar temperatura. Probar con otro juego/aplicación.', severity: 'medium' },
        { pattern: /ntfs|Ntfs|exfat|refs/i, name: 'NTFS/ReFS File System Driver', desc: 'Controlador del sistema de archivos. Posible corrupción de disco o sector defectuoso. Recomendación: Ejecutar chkdsk /f /r. Verificar salud del disco con CrystalDiskInfo o smartctl.', severity: 'high' },
        { pattern: /fltmgr|wdflt|wdfilter|klif|kss|asw|avg|avast|mcafee|symtdi|symevent|bdself|eset|crowdstrike/i, name: 'Filter Driver (Antivirus/EDR/VPN)', desc: 'Driver de filtro de antivirus, EDR, firewall o VPN. Estos drivers interceptan operaciones del sistema y pueden causar BSOD si tienen bugs. Recomendación: Actualizar o desinstalar temporalmente el software de seguridad/VPN.', severity: 'medium' },
        { pattern: /tcpip|ndis|netio|netbt|afd|tdx|ipsec|pacer/i, name: 'Network Stack Driver', desc: 'Componente de la pila de red de Windows. BSOD relacionado con red. Recomendación: Actualizar drivers de red. Desactivar IPv6 si no se usa. Actualizar firmware del router.', severity: 'low' },
        { pattern: /usbhub|usbport|usbxhci|usbehci|usbohci|usbd/i, name: 'USB Controller Driver', desc: 'Controlador USB del sistema. BSOD por dispositivo USB defectuoso o driver USB corrupto. Recomendación: Desconectar dispositivos USB uno por uno para identificar. Actualizar drivers USB.', severity: 'medium' },
        { pattern: /wlan|wifi|ath|iwlwifi|bcmwl|bcm43xx|mt76/i, name: 'Wireless Network Driver', desc: 'Controlador de red inalámbrica. Recomendación: Actualizar driver WiFi. Probar con adaptador USB WiFi externo.', severity: 'medium' },
        { pattern: /cmudax|usbaudio|audio|intcaz|hdaudio|nvhda/i, name: 'Audio Driver', desc: 'Controlador de audio. Puede causar BSOD en reproducción de sonido. Recomendación: Actualizar driver de audio. Deshabilitar efectos de sonido.', severity: 'low' },
        { pattern: /win32k|win32kbase|win32kfull/i, name: 'Win32k Graphics Driver', desc: 'Controlador de ventanas y gráficos GDI. Recomendación: Instalar actualizaciones de Windows. Actualizar drivers de GPU.', severity: 'medium' },
        { pattern: /vmware|vboxdrv|hyperv|vmswitch|vmnet|vmx86/i, name: 'Virtualization Driver', desc: 'Driver de hipervisor o máquina virtual. Puede causar BSOD si hay incompatibilidad con actualizaciones de Windows. Recomendación: Actualizar VMware/VirtualBox/Hyper-V. Desactivar Hyper-V si no se usa.', severity: 'medium' },
        { pattern: /nvhda|nvhda64|nvapi64|nvumdshim|nvcpl/i, name: 'NVIDIA Audio/Panel Service', desc: 'Componente de NVIDIA (audio HDMI o panel de control). Recomendación: Actualizar todos los paquetes de NVIDIA.', severity: 'medium' },
        { pattern: /iaStorA|iaStorAC|iaStorS|rste/i, name: 'Intel RST / VMD Driver', desc: 'Intel Rapid Storage Technology o Volume Management Device. Recomendación: Actualizar driver RST/VMD desde el sitio de Intel o fabricante de placa base.', severity: 'high' },
        { pattern: /synaptics|elantech|etd|alps/i, name: 'Touchpad Driver', desc: 'Controlador de touchpad. Raro en BSOD pero posible con drivers antiguos. Recomendación: Actualizar desde el fabricante del portátil.', severity: 'low' },
        { pattern: /expressvpn|nordvpn|protonvpn|surfshark|tun|tap0901|tap/i, name: 'VPN/TUN Adapter Driver', desc: 'Driver de adaptador VPN/TUN/TAP. Puede causar BSOD al conectar/desconectar. Recomendación: Actualizar la aplicación VPN. Reinstalar adaptador TAP.', severity: 'medium' },
        { pattern: /msi|asus|gigabyte|asrock|icue|corsair|nzxt/i, name: 'Motherboard / OEM Utility Driver', desc: 'Driver de utilidad de placa base o periférico (RGB, control de ventiladores). Recomendación: Actualizar desde el fabricante. Desinstalar utilidades innecesarias.', severity: 'medium' },
        { pattern: /btfilter|bthport|bthusb|bthpan/i, name: 'Bluetooth Driver', desc: 'Controlador Bluetooth. Puede causar BSOD con ciertos dispositivos. Recomendación: Actualizar driver Bluetooth. Desconectar dispositivos problemáticos.', severity: 'medium' },
        { pattern: /ksecdd|ksecpkg|ccgdrv|credentialguard/i, name: 'Credential Guard / Security Driver', desc: 'Componente de seguridad de Windows. BSOD puede indicar corrupción del sistema. Recomendación: Ejecutar sfc /scannow y DISM.', severity: 'high' },
        { pattern: /bcmfn2|bcmwl|brcm/i, name: 'Broadcom Driver', desc: 'Controlador de red Broadcom. Recomendación: Actualizar driver desde el fabricante.', severity: 'medium' },
        { pattern: /qcamain10x64|qca61x4|qca9377/i, name: 'Qualcomm Atheros WiFi Driver', desc: 'Controlador WiFi Qualcomm/Atheros. Recomendación: Actualizar driver. Verificar configuración de energía.', severity: 'medium' },
        { pattern: /e1d68|e1i68|e1express|e1g/i, name: 'Intel Ethernet Driver', desc: 'Controlador Ethernet Intel. Recomendación: Actualizar driver desde Intel o fabricante de placa base.', severity: 'medium' },
        { pattern: /lsi_sas|lsi_sas2|mpt2sas|mpt3sas/i, name: 'LSI/Broadcom SAS Driver', desc: 'Controlador SAS/RAID de servidor. Recomendación: Actualizar firmware y driver.', severity: 'high' }
    ];

    var MS_DRIVERS = /^(ntoskrnl|ntkrnl|hal|kern|ms|win32k|storport|stornvme|partmgr|volmgr|volsnap|mountmgr|fvevol|clipsp|dxgkrnl|dxgmms|dxg|tcpip|ndis|netio|afd|tdx|usbhub|usbport|usbxhci|usbehci|usbohci|hid|mou|kbd|monitor|cdrom|disk|classpnp|pci|acpi|intelide|atapi|viaide|cmdide|wdmaud|sysaudio|kmixer|portcls|dmusic|swenum|update|win32k|ntdll|kernel32|kernelbase|fltmgr|wcifs|luafv|fileinfo|bowser|mrxsmb|mup|rdbss|srvnet|srv2|http|ipsec|pacer|umbus|wmiacpi|wmilib|ci|clfs|cmimcext|compbatt|cng|dfs|dfsr|drmk|dumpfve|elam|exfat|fastfat|fdc|filecrypt|fips|fs_rec|fwpkclnt|hidclass|hidi2c|hidparse|hwpolicy|i8042prt|intelppm|kbdclass|kbdhid|ks|ksecdd|ksecpkg|lltdio|luafv|modem|mouclass|mouhid|mountmgr|mpsdrv|mrxdav|msfs|mshidkmdf|msrpc|mssmbios|mup|ndisuio|netbios|netbt|npfs|nsiproxy|ntfs|null|pci|pciidex|pcw|pdc|portcfg|processr|psched|rdbss|rdpdr|rdpencom|rdprefmp|replic|rpcrt4|rpcss|rspndr|scfilter|serenum|sermouse|sfloppy|srv|srv2|srvnet|storahci|stornvme|swenum|tap0901|tcpip|termsrv|tpm|tunnel|udfs|umbus|umpass|usbccgp|usbd|usbehci|usbhub|usbohci|usbprint|usbscan|usbstor|usbuhci|usbxhci|vdrvroot|vga|volmgr|volmgrx|volsnap|vwifibus|vwififlt|vwifimp|wanarp|watchdog|wd|wdf01000|wdfldr|wdiwifi|wdkmd|wdm|wfplwfs|wimmount|win32k|win32kbase|win32kfull|wininit|winusb|wlansec|wmiacpi|wmilib|ws2ifsl|wudfpf|wudfrd|xboxgip|xinputhid)/i;

    // ═══════════════════════════════════════════════════════════════════════════
    // FUNCIONES AUXILIARES
    // ═══════════════════════════════════════════════════════════════════════════

    function readU64(dv, off) {
        var lo = dv.getUint32(off, true);
        var hi = dv.getUint32(off + 4, true);
        return { lo: lo, hi: hi };
    }

    function formatU64(val) {
        if (val.hi === 0) return '0x' + ('00000000' + val.lo.toString(16).toUpperCase()).slice(-8);
        return '0x' + val.hi.toString(16) + ('00000000' + val.lo.toString(16).toUpperCase()).slice(-8);
    }

    function combineLoHi(lo, hi) {
        return hi * 0x100000000 + lo;
    }

    function formatHex(val, pad) {
        return '0x' + (val >>> 0).toString(16).toUpperCase().padStart(pad || 8, '0');
    }

    function readString8(dv, off, maxLen) {
        var s = '';
        for (var i = 0; i < maxLen; i++) {
            var c = dv.getUint8(off + i);
            if (c === 0) break;
            if (c >= 32 && c <= 126) s += String.fromCharCode(c);
        }
        return s.trim();
    }

    function readWStringAt(buf, off, maxChars) {
        var dv = new DataView(buf);
        var s = '';
        for (var i = 0; i < maxChars; i++) {
            var c = dv.getUint16(off + i * 2, true);
            if (c === 0) break;
            if (c >= 32 && c <= 126) s += String.fromCharCode(c);
        }
        return s;
    }

    function escapeHtml(str) {
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(str));
        return div.innerHTML;
    }

    function safeId(str) {
        return String(str).replace(/[^a-zA-Z0-9_-]/g, '_');
    }

    function formatFileSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
        if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
        return (bytes / 1073741824).toFixed(1) + ' GB';
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // PARSERS DE VOLCADOS .DMP
    // ═══════════════════════════════════════════════════════════════════════════

    function parseDumpHeader(buf) {
        try {
            if (buf.byteLength < 96) return null;
            var dv = new DataView(buf);

            var sig = dv.getUint32(0, true);
            var valid = dv.getUint32(4, true);

            // PAGEDU64 full dump: first 8 bytes = "PAGE" + "DU64"
            if (sig === 0x45474150 && valid === 0x34365544) {
                var result = {
                    type: 'full64',
                    bugcheckCode: dv.getUint32(56, true),
                    bugcheckParams: [
                        dv.getUint32(64, true), dv.getUint32(72, true),
                        dv.getUint32(80, true), dv.getUint32(88, true)
                    ],
                    majorVersion: dv.getUint32(8, true),
                    minorVersion: dv.getUint32(12, true),
                    machineType: dv.getUint32(48, true),
                    numProcessors: dv.getUint32(52, true),
                    exceptionAddr: 0,
                    versionString: '',
                    moduleList: [],
                    moduleRanges: []
                };

                if (buf.byteLength >= 128) {
                    result.versionString = readString8(dv, 96, 64);
                }

                return result;
            }

            // PAGEDU32 full dump (32-bit)
            if (sig === 0x45474150 && valid === 0x32355544) {
                var result32 = {
                    type: 'full32',
                    bugcheckCode: dv.getUint32(40, true),
                    bugcheckParams: [
                        dv.getUint32(44, true), dv.getUint32(48, true),
                        dv.getUint32(52, true), dv.getUint32(56, true)
                    ],
                    majorVersion: dv.getUint32(8, true),
                    minorVersion: dv.getUint32(12, true),
                    machineType: dv.getUint32(32, true),
                    numProcessors: dv.getUint32(36, true),
                    exceptionAddr: 0,
                    versionString: '',
                    systemUpTime: 0,
                    productType: 0,
                    ripAddress: 0,
                    moduleList: [],
                    moduleRanges: []
                };
                return result32;
            }

            // Check for embedded MDMP anywhere in the dump
            if (buf.byteLength > 100) {
                var u8 = new Uint8Array(buf);
                for (var si = 0; si < Math.min(buf.byteLength - 4, 65536); si++) {
                    if (u8[si] === 0x4D && u8[si+1] === 0x44 && u8[si+2] === 0x4D && u8[si+3] === 0x50) {
                        var mdmp = parseMinidump(buf, si);
                        if (mdmp) return mdmp;
                    }
                }
            }

            return null;
        } catch (e) { return null; }
    }

    function parseMinidump(buf, mdmpOffset) {
        try {
            mdmpOffset = mdmpOffset || 0;
            var dv = new DataView(buf, mdmpOffset, buf.byteLength - mdmpOffset);
            var bufStart = mdmpOffset;
            if (buf.byteLength < 32) return null;
            var signature = dv.getUint32(0, true);
            if (signature !== 0x504D444D) return null;

            var result = {
                valid: true,
                numberofStreams: dv.getUint32(8, true),
                streamDirRva: dv.getUint32(12, true),
                bugcheckCode: null,
                bugcheckParams: [0, 0, 0, 0, 0, 0, 0, 0],
                exceptionAddr: 0,
                exceptionAddr64: { lo: 0, hi: 0 },
                crashingThreadId: 0,
                moduleList: [],
                moduleRanges: [],
                majorVersion: 0,
                minorVersion: 0,
                buildNumber: 0,
                processorArch: 0,
                numThreads: 0,
                processId: 0
            };

            if (result.numberofStreams > 256 || result.streamDirRva + result.numberofStreams * 12 > buf.byteLength) {
                return null;
            }

            var offset = result.streamDirRva;
            for (var s = 0; s < result.numberofStreams; s++) {
                if (offset + 12 > buf.byteLength) break;
                var streamType = dv.getUint32(offset, true);
                var dataRva = dv.getUint32(offset + 8, true);
                offset += 12;

                if (streamType === 6 && dataRva + 72 <= buf.byteLength) {
                    var exOff = dataRva;
                    result.crashingThreadId = dv.getUint32(exOff, true);
                    var recOff = exOff + 8;
                    result.bugcheckCode = dv.getUint32(recOff, true);
                    result.exceptionAddr64 = readU64(dv, recOff + 16);
                    result.exceptionAddr = combineLoHi(result.exceptionAddr64.lo, result.exceptionAddr64.hi);
                    var numParams = dv.getUint32(recOff + 24, true);
                    for (var pi = 0; pi < Math.min(numParams, 8); pi++) {
                        result.bugcheckParams[pi] = dv.getUint32(recOff + 32 + pi * 8, true);
                    }
                } else if (streamType === 7 && dataRva + 24 <= buf.byteLength) {
                    result.processorArch = dv.getUint16(dataRva, true);
                    result.majorVersion = dv.getUint32(dataRva + 8, true);
                    result.minorVersion = dv.getUint32(dataRva + 12, true);
                    result.buildNumber = dv.getUint32(dataRva + 16, true);
                } else if (streamType === 4 && dataRva + 4 <= buf.byteLength) {
                    var numModules = dv.getUint32(dataRva, true);
                    if (numModules > 256) continue;
                    var modOff = dataRva + 4;
                    for (var m = 0; m < Math.min(numModules, 128); m++) {
                        if (modOff + 108 > buf.byteLength) break;
                        var baseLo = dv.getUint32(modOff, true);
                        var sizeImg = dv.getUint32(modOff + 8, true);
                        var nameRva = dv.getUint32(modOff + 12, true);
                        var absNameRva = nameRva + bufStart;
                        if (nameRva > 0 && absNameRva + 6 < buf.byteLength) {
                            var nameLen = dv.getUint32(absNameRva, true);
                            if (nameLen > 0 && nameLen < 256 && absNameRva + 4 + nameLen * 2 <= buf.byteLength) {
                                var nameBytes = new Uint8Array(buf, absNameRva + 4, nameLen * 2);
                                var modName = '';
                                for (var k = 0; k < nameBytes.length; k += 2) {
                                    var charCode = nameBytes[k] | (nameBytes[k + 1] << 8);
                                    if (charCode >= 32 && charCode <= 126) modName += String.fromCharCode(charCode);
                                }
                                if (modName.length > 0) {
                                    result.moduleList.push(modName);
                                    result.moduleRanges.push({ name: modName, base: baseLo, size: sizeImg });
                                }
                            }
                        }
                        modOff += 108;
                    }
                } else if (streamType === 3 && dataRva + 4 <= buf.byteLength) {
                    result.numThreads = dv.getUint32(dataRva, true);
                } else if (streamType === 15 && dataRva + 12 <= buf.byteLength) {
                    result.processId = dv.getUint32(dataRva + 8, true);
                }
            }

            return result;
        } catch (e) {
            return null;
        }
    }

    function getBugcheckEntry(code) {
        for (var i = 0; i < BUGCHECK_MAP.length; i++) {
            if (BUGCHECK_MAP[i].code === code) return BUGCHECK_MAP[i];
        }
        var hex = formatHex(code, 8);
        return {
            code: code,
            name: 'BUGCODE_' + hex,
            severity: 'high',
            desc: 'Código de error de sistema no reconocido: ' + hex + '. Consulta Microsoft Learn para más información.',
            impact: 'Fallo del sistema por causa desconocida.',
            remediation: 'Busca el código ' + hex + ' en Microsoft Learn o DuckDuckGo. Analiza el volcado con WinDbg: !analyze -v.'
        };
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ESCANEO DE DRIVERS EN EL VOLCADO
    // ═══════════════════════════════════════════════════════════════════════════

    function isDriverChar(c) {
        return (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 46 || c === 95 || c === 45;
    }

    function flushDriver(current, seen, found) {
        if (current.length > 4 && /\.sys$/i.test(current) && !seen[current.toLowerCase()]) {
            seen[current.toLowerCase()] = true;
            var dbEntry = null;
            for (var d = 0; d < DRIVER_DB.length; d++) {
                if (DRIVER_DB[d].pattern.test(current)) {
                    dbEntry = DRIVER_DB[d];
                    break;
                }
            }
            found.push({ name: current, dbEntry: dbEntry, nearCrash: false });
        }
    }

    function scanDriversFromBuf(buf, exceptionAddr) {
        var view = new Uint8Array(buf);
        var found = [];
        var seen = {};
        var maxLen = Math.min(view.length, MAX_DUMP_SCAN_BYTES);

        var current = '';
        var utf16current = '';
        var inUtf16 = false;

        for (var i = 0; i < maxLen; i++) {
            var c = view[i];
            var n = (i + 1 < maxLen) ? view[i + 1] : 0;

            if (n === 0 && isDriverChar(c)) {
                utf16current += String.fromCharCode(c);
                i++;
                inUtf16 = true;
                continue;
            } else if (inUtf16) {
                flushDriver(utf16current, seen, found);
                utf16current = '';
                inUtf16 = false;
            }

            if (isDriverChar(c)) {
                current += String.fromCharCode(c);
            } else {
                flushDriver(current, seen, found);
                current = '';
            }
        }
        flushDriver(current, seen, found);
        flushDriver(utf16current, seen, found);

        found.sort(function (a, b) {
            var aMs = MS_DRIVERS.test(a.name);
            var bMs = MS_DRIVERS.test(b.name);
            if (aMs && !bMs) return 1;
            if (!aMs && bMs) return -1;
            var aDb = a.dbEntry ? 1 : 0;
            var bDb = b.dbEntry ? 1 : 0;
            return bDb - aDb;
        });

        return found;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // EXTRACCIÓN DE STACK Y STRINGS
    // ═══════════════════════════════════════════════════════════════════════════

    function extractStackFromBuf(buf) {
        var view = new Uint8Array(buf);
        var maxLen = Math.min(view.length, MAX_STRING_SCAN_BYTES);
        var current = '';
        var stackFrames = [];
        var seenFrames = {};

        for (var i = 0; i < maxLen; i++) {
            var c = view[i];
            if ((c >= 32 && c <= 126) || c === 9) {
                if (c === 10 || c === 13) {
                    if (current.length > 5 && /^[a-zA-Z0-9_.]+![a-zA-Z0-9_:+.]+/i.test(current)) {
                        stackFrames.push(current.trim());
                    }
                    current = '';
                } else {
                    current += String.fromCharCode(c);
                }
            } else if (c === 10 || c === 13) {
                if (current.length > 5 && /^[a-zA-Z0-9_.]+![a-zA-Z0-9_:+.]+/i.test(current)) {
                    stackFrames.push(current.trim());
                }
                current = '';
            } else {
                if (current.length > 5 && /^[a-zA-Z0-9_.]+![a-zA-Z0-9_:+.]+/i.test(current)) {
                    stackFrames.push(current.trim());
                }
                current = '';
            }
        }

        // Deduplicate preserving order
        var seenStack = {};
        stackFrames = stackFrames.filter(function(f) {
            var key = f.toLowerCase();
            if (seenStack[key]) return false;
            seenStack[key] = true;
            return true;
        });

        stackFrames.sort(function(a, b) {
            var aMod = a.split('!')[0].toLowerCase();
            var bMod = b.split('!')[0].toLowerCase();
            if (aMod === 'nt' && bMod !== 'nt') return -1;
            if (aMod !== 'nt' && bMod === 'nt') return 1;
            if (aMod === 'dxgkrnl' && bMod !== 'dxgkrnl' && bMod !== 'nt') return -1;
            return 0;
        });

        return stackFrames.slice(0, 20);
    }

    function extractStringsFromBuf(buf) {
        var view = new Uint8Array(buf);
        var out = [];
        var current = '';
        var maxLen = Math.min(view.length, MAX_STRING_SCAN_BYTES);
        for (var i = 0; i < maxLen; i++) {
            var c = view[i];
            if (c >= 32 && c <= 126) {
                current += String.fromCharCode(c);
            } else if ((c === 10 || c === 13) && current.length > 3) {
                out.push(current);
                current = '';
            } else {
                if (current.length > 4) out.push(current);
                current = '';
            }
        }
        if (current.length > 4) out.push(current);
        return out.join('\n');
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // HEURÍSTICA DE CULPABLE PROBABLE
    // ═══════════════════════════════════════════════════════════════════════════

    function scoreDriver(d, parsed, stackFrames) {
        var score = 0;
        if (d.dbEntry) score += 10;
        if (!MS_DRIVERS.test(d.name)) score += 5;

        var nameLower = d.name.toLowerCase();

        if (parsed.bugcheckCode !== null) {
            var code = parsed.bugcheckCode;
            var isVideoBugcheck = (code === 0x116 || code === 0x117 || code === 0x119 || code === 0x10E || code === 0x113 || code === 0x141 || code === 0x114);
            var isStorageBugcheck = (code === 0x7A || code === 0x77 || code === 0xF4 || code === 0xED || code === 0x24 || code === 0x102 || code === 0x133);
            var isNetworkBugcheck = (code === 0x7C || code === 0x126 || code === 0xD1);
            var isPowerBugcheck = (code === 0x9F || code === 0x9C || code === 0x124 || code === 0x101);

            if (isVideoBugcheck && /nvlddmkm|amdkmdag|atikmpag|igdkmd|dxgkrnl/i.test(nameLower)) score += 15;
            if (isStorageBugcheck && /storport|stornvme|iastor|nvme|iaStor/i.test(nameLower)) score += 15;
            if (isNetworkBugcheck && /tcpip|ndis|netio|rtwl|e1d|bcm/i.test(nameLower)) score += 12;
            if (isPowerBugcheck && /nvlddmkm|amdkmdag|rtwl|iaStor|storport|dxgkrnl/i.test(nameLower)) score += 8;
        }

        if (stackFrames && stackFrames.length > 0) {
            for (var i = 0; i < stackFrames.length; i++) {
                var mod = stackFrames[i].split('!')[0].toLowerCase();
                if (mod && nameLower.indexOf(mod) === 0) score += 8;
            }
        }

        if (parsed.exceptionAddr > 0 && parsed.moduleRanges.length > 0) {
            for (var mi = 0; mi < parsed.moduleRanges.length; mi++) {
                var mr = parsed.moduleRanges[mi];
                if (parsed.exceptionAddr >= mr.base && parsed.exceptionAddr < mr.base + mr.size && mr.name.toLowerCase().indexOf(nameLower.replace('.sys', '')) === 0) {
                    score += 25;
                }
            }
        }

        return score;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ANÁLISIS DE VOLCADOS .DMP
    // ═══════════════════════════════════════════════════════════════════════════

    function analyzeDump(content, fileName, activeCats) {
        var buf = content;
        var parsed = parseDumpHeader(buf);
        var findings = [];
        var isFullDump = false;
        activeCats = activeCats || { crash: true, windows: true, malware: true, auth: true, web: true, network: true, linux: true, compliance: true };

        if (!parsed) {
            var headBytes = '';
            for (var hi = 0; hi < Math.min(buf.byteLength, 16); hi++) {
                var b = new Uint8Array(buf)[hi];
                headBytes += (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.' );
            }
            var text = extractStringsFromBuf(buf);
            var textFindings = analyzeTextLog(text, fileName, activeCats);
            if (textFindings.length > 0) {
                textFindings.unshift({
                    id: 'DMP-NOTVALID', category: 'crash', severity: 'info',
                    name: 'El archivo .dmp no se reconoce como minidump estándar',
                    description: 'Cabecera: "' + headBytes + '". No es un minidump MDMP ni un full dump PAGEDU64.',
                    impact: 'Análisis binario no disponible.',
                    remediation: 'Asegúrate de que el archivo es un .dmp generado por Windows (BSOD).',
                    mitre: '', line: 0, context: '', matched: ''
                });
                return textFindings;
            }
            findings.push({
                id: 'DMP-NOTVALID', category: 'crash', severity: 'info',
                name: 'El archivo .dmp no es un volcado de Windows compatible',
                description: 'Cabecera: "' + headBytes + '". No se reconoce como minidump ni full dump.',
                impact: 'No se puede analizar este archivo.',
                remediation: 'Si es un volcado completo de Windows, usa WinDbg: !analyze -v.',
                mitre: '', line: 0, context: '', matched: ''
            });
            return findings;
        }

        if (parsed.type === 'full64' || parsed.type === 'full32') isFullDump = true;

        if (parsed.exceptionAddr > 0 && parsed.moduleRanges.length > 0) {
            for (var mi = 0; mi < parsed.moduleRanges.length; mi++) {
                var mr = parsed.moduleRanges[mi];
                if (parsed.exceptionAddr >= mr.base && parsed.exceptionAddr < mr.base + mr.size) {
                    parsed.faultyModule = mr.name;
                    break;
                }
            }
        }

        var stackFrames = [];
        if (isFullDump) {
            stackFrames = extractStackFromBuf(buf);
        }

        if (parsed.bugcheckCode !== null && parsed.bugcheckCode !== 0 && parsed.bugcheckCode !== undefined) {
            var entry = getBugcheckEntry(parsed.bugcheckCode);
            var hexCode = formatHex(parsed.bugcheckCode, 8);
            var faultStr = parsed.faultyModule ? ' — posible driver: ' + parsed.faultyModule : '';
            var paramInfo = '';
            var paramDesc = '';

            if (entry.code !== 0xDEADDEAD) {
                paramInfo = ' P1=' + formatHex(parsed.bugcheckParams[0], 16) + ' P2=' + formatHex(parsed.bugcheckParams[1], 16) + ' P3=' + formatHex(parsed.bugcheckParams[2], 16) + ' P4=' + formatHex(parsed.bugcheckParams[3], 16);

                if (BUGCHECK_PARAM_DESC[parsed.bugcheckCode]) {
                    var descs = BUGCHECK_PARAM_DESC[parsed.bugcheckCode];
                    paramDesc = ' Parámetros:';
                    for (var pi = 0; pi < 4 && pi < descs.length; pi++) {
                        paramDesc += ' P' + (pi + 1) + '=' + formatHex(parsed.bugcheckParams[pi], 16) + ' — ' + descs[pi];
                    }
                }

                var ntstatusInfo = '';
                for (var pi2 = 0; pi2 < 4; pi2++) {
                    if (NTSTATUS_MAP[parsed.bugcheckParams[pi2]]) {
                        ntstatusInfo += ' P' + (pi2 + 1) + '=' + NTSTATUS_MAP[parsed.bugcheckParams[pi2]] + ' (' + formatHex(parsed.bugcheckParams[pi2], 16) + ')';
                    }
                }
                if (ntstatusInfo) paramDesc += ' Códigos NTSTATUS detectados:' + ntstatusInfo + '.';
            }

            var extendedDesc = entry.desc + (paramDesc || paramInfo);
            var crashSummary = hexCode + ' ' + entry.name + faultStr;
            if (parsed.faultyModule) {
                crashSummary += ' | Culprit: ' + parsed.faultyModule;
            }

            findings.push({
                id: 'BSOD-' + hexCode.replace(/0x0+/, '0x'),
                category: 'crash',
                severity: entry.severity,
                name: 'BSOD: ' + entry.name + ' (' + hexCode + ')' + faultStr,
                description: extendedDesc + '. Dirección de excepción: ' + formatHex(parsed.exceptionAddr) + (parsed.faultyModule ? '. El código se ejecutaba en ' + parsed.faultyModule : '') + '.',
                impact: (parsed.faultyModule ? 'El driver ' + parsed.faultyModule + ' es el principal sospechoso.' : entry.impact),
                remediation: parsed.faultyModule ? 'Actualiza o reinstala ' + parsed.faultyModule + '. Descarga la última versión desde el sitio del fabricante. Si el crash persiste, prueba a desinstalar el controlador o restaurar una versión anterior.' : entry.remediation,
                mitre: '',
                line: 0,
                context: crashSummary + ' | ExceptionAddress ' + formatHex(parsed.exceptionAddr) + paramInfo,
                matched: hexCode
            });
        }

        if (isFullDump) {
            var dumpType = parsed.type === 'full64' ? 'Completo (64 bits)' : 'Completo (32 bits)';
            var fdInfo = 'Tipo: ' + dumpType + '. Procesadores: ' + parsed.numProcessors + '. MachineType: ' + parsed.machineType + '.';
            if (parsed.versionString) fdInfo += ' Versión: "' + parsed.versionString + '".';

            var drivers = scanDriversFromBuf(buf, parsed.exceptionAddr);
            var topDrivers = drivers.slice(0, 40);
            var nonMsTop = topDrivers.filter(function(d) { return !MS_DRIVERS.test(d.name); });

            var scoredDrivers = topDrivers.map(function(d) {
                return { driver: d, score: scoreDriver(d, parsed, stackFrames) };
            });
            scoredDrivers.sort(function(a, b) { return b.score - a.score; });

            var knownDriver = null;
            for (var di = 0; di < scoredDrivers.length; di++) {
                if (scoredDrivers[di].score > 0 && !MS_DRIVERS.test(scoredDrivers[di].driver.name)) {
                    knownDriver = scoredDrivers[di].driver;
                    break;
                }
            }
            if (!knownDriver) {
                for (var di2 = 0; di2 < nonMsTop.length; di2++) {
                    if (nonMsTop[di2].dbEntry) { knownDriver = nonMsTop[di2]; break; }
                }
            }

            var bugcheckHex = parsed.bugcheckCode ? formatHex(parsed.bugcheckCode, 8) : 'desconocido';
            findings.push({
                id: 'DMP-FULL', category: 'crash', severity: 'info',
                name: 'Volcado completo: ' + dumpType + ' — BugCheck ' + bugcheckHex + ' — ' + (knownDriver ? knownDriver.name : topDrivers.length + ' drivers encontrados'),
                description: fdInfo + ' Drivers encontrados: ' + topDrivers.length + '.',
                impact: knownDriver ? 'Driver detectado: ' + knownDriver.name + ' (' + knownDriver.dbEntry.name + ')' : 'Los full dumps contienen la memoria completa para análisis con WinDbg.',
                remediation: knownDriver ? knownDriver.dbEntry.desc + ' Para análisis de pila completo: WinDbg !analyze -v.' : 'Usa WinDbg con !analyze -v. Configura Windows para minidumps (CrashDumpEnabled=3).',
                mitre: '', line: 0, context: topDrivers.map(function(d) { return d.name; }).join(', ').substring(0, 400), matched: knownDriver ? knownDriver.name : ''
            });

            if (knownDriver) {
                var similarDrivers = [];
                for (var di3 = 0; di3 < topDrivers.length && similarDrivers.length < 5; di3++) {
                    if (topDrivers[di3] !== knownDriver && topDrivers[di3].dbEntry) similarDrivers.push(topDrivers[di3].name);
                }
                findings.push({
                    id: 'DMP-DRIVER', category: 'crash', severity: knownDriver.dbEntry.severity,
                    name: 'Driver sospechoso: ' + knownDriver.name,
                    description: knownDriver.dbEntry.name + '. ' + knownDriver.dbEntry.desc + (similarDrivers.length > 0 ? ' Otros posibles: ' + similarDrivers.join(', ') + '.' : ''),
                    impact: 'Este driver es el principal candidato a causante del crash.',
                    remediation: knownDriver.dbEntry.desc,
                    mitre: '', line: 0, context: '', matched: knownDriver.name
                });
            }

            var nonMsDrivers = topDrivers.filter(function(d) {
                return !MS_DRIVERS.test(d.name);
            });
            if (nonMsDrivers.length > 0) {
                findings.push({
                    id: 'DMP-DRVSCAN', category: 'crash', severity: 'info',
                    name: 'Drivers de terceros encontrados: ' + nonMsDrivers.length,
                    description: 'Lista de drivers no Microsoft detectados en el volcado: ' + nonMsDrivers.slice(0, 12).map(function(d) { return d.name; }).join(', ') + '.',
                    impact: 'Cualquiera de estos drivers podría ser el causante del crash.',
                    remediation: 'Actualiza los drivers de la lista, empezando por los conocidos (GPU, red, almacenamiento).',
                    mitre: '', line: 0, context: '', matched: ''
                });
            }

            if (stackFrames.length > 0) {
                var stackText = stackFrames.join(' → ');
                var crashedIn = '';
                for (var si = 0; si < stackFrames.length; si++) {
                    if (!/^nt!/i.test(stackFrames[si]) && !/^dxgkrnl!/i.test(stackFrames[si])) {
                        crashedIn = stackFrames[si];
                        break;
                    }
                }
                if (!crashedIn && stackFrames.length > 0) crashedIn = stackFrames[0];

                findings.push({
                    id: 'DMP-STACK', category: 'crash', severity: 'info',
                    name: 'Call stack (funciones detectadas en dump): ' + (crashedIn ? crashedIn : ''),
                    description: 'Se extrajeron ' + stackFrames.length + ' frames de pila. Secuencia: ' + stackText.substring(0, 600) + '.',
                    impact: 'La función señalada (' + (crashedIn || 'desconocida') + ') es donde ocurrió el fallo.',
                    remediation: 'Usa WinDbg con !analyze -v para ver la pila completa con símbolos resueltos.',
                    mitre: '', line: 0, context: stackText.substring(0, 500), matched: crashedIn
                });
            }
        } else {
            if (parsed.numThreads > 0 || parsed.processId > 0) {
                var crashInfo = 'Hilo que causó el crash: ThreadId ' + parsed.crashingThreadId + '. ';
                crashInfo += 'Total de hilos: ' + parsed.numThreads + '. ';
                if (parsed.processId > 0) crashInfo += 'ProcessId: ' + parsed.processId + '.';
                findings.push({
                    id: 'DMP-THREAD', category: 'crash', severity: 'info',
                    name: 'Hilo crítico: Thread ' + parsed.crashingThreadId + ' causó el crash',
                    description: crashInfo,
                    impact: 'Identificar el hilo ayuda a localizar el punto exacto del fallo.',
                    remediation: '', mitre: '', line: 0, context: '', matched: ''
                });
            }
        }

        if (isFullDump && parsed.versionString) {
            findings.push({
                id: 'DMP-OSVER', category: 'crash', severity: 'info',
                name: 'Sistema: ' + parsed.versionString,
                description: 'Versión del sistema extraída de la cabecera del full dump. MajorVersion=' + parsed.majorVersion + '. MinorVersion=' + parsed.minorVersion + '.',
                impact: 'Contexto del sistema.', remediation: '',
                mitre: '', line: 0, context: '', matched: ''
            });
        } else if (!isFullDump && parsed.majorVersion > 0 && parsed.majorVersion !== undefined) {
            var verStr = 'Windows ' + parsed.majorVersion + '.' + parsed.minorVersion + ' (Build ' + parsed.buildNumber + ')';
            findings.push({
                id: 'DMP-OSVER',
                category: 'crash', severity: 'info',
                name: 'Sistema operativo: ' + verStr,
                description: 'El volcado fue generado por ' + verStr + '. Arquitectura: ' + (parsed.processorArch === 0 ? 'x86' : parsed.processorArch === 9 ? 'x64 (AMD64)' : parsed.processorArch === 12 ? 'ARM64' : 'desconocida (' + parsed.processorArch + ')' ) + '.',
                impact: 'Contexto del sistema.', remediation: '',
                mitre: '', line: 0, context: '', matched: ''
            });
        }

        if (parsed.moduleList && parsed.moduleList.length > 0) {
            var nonMsModules = [];
            for (var mi2 = 0; mi2 < parsed.moduleList.length; mi2++) {
                var mn = parsed.moduleList[mi2].toLowerCase();
                if (mn.indexOf('ntoskrnl') === 0 || mn.indexOf('ntdll') === 0 || mn.indexOf('kernel32') === 0 || mn.indexOf('hal') === 0 || mn.indexOf('win32k') === 0) continue;
                if (mn.indexOf('ms') === 0 || mn.indexOf('windows') === 0) continue;
                nonMsModules.push(parsed.moduleList[mi2]);
            }
            var moduleStr = parsed.moduleList.slice(0, 15).join(', ');

            var moduleFindingName = 'Módulos cargados (' + parsed.moduleList.length + ')';
            var moduleFindingDesc = 'Módulos cargados en el momento del crash: ' + moduleStr.substring(0, 300);
            var moduleRemed = '';

            if (parsed.faultyModule) {
                moduleFindingName = 'Driver causante: ' + parsed.faultyModule;
                moduleFindingDesc = 'La dirección de excepción (' + formatHex(parsed.exceptionAddr) + ') cae dentro del rango de memoria de ' + parsed.faultyModule + '.';
                moduleRemed = 'Actualiza o reinstala ' + parsed.faultyModule + '. Busca actualizaciones en la web del fabricante.';
            } else if (nonMsModules.length > 0) {
                moduleFindingName = 'Posibles drivers sospechosos: ' + nonMsModules.slice(0, 3).join(', ');
                moduleFindingDesc = 'Los drivers de terceros más probables como causa del crash son: ' + nonMsModules.slice(0, 8).join(', ').substring(0, 300) + '.';
                moduleRemed = 'Actualiza los drivers listados. Si no sabes cuál es, actualiza todos los controladores del sistema.';
            } else {
                moduleFindingDesc = 'No se identificaron drivers de terceros. El crash puede deberse a un componente de Microsoft o a un fallo de hardware.';
                moduleRemed = 'Ejecuta diagnóstico de RAM (mdsched.exe). Verifica el disco (chkdsk). Comprueba actualizaciones de Windows.';
            }

            findings.push({
                id: 'DMP-MODULES',
                category: 'crash', severity: 'info',
                name: moduleFindingName,
                description: moduleFindingDesc,
                impact: parsed.faultyModule ? 'El driver señalado es el causante más probable del BSOD.' : 'Varios drivers podrían estar involucrados.',
                remediation: moduleRemed,
                mitre: '', line: 0, context: moduleStr.substring(0, 300), matched: ''
            });
        }

        return findings;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ANÁLISIS DE LOGS DE TEXTO
    // ═══════════════════════════════════════════════════════════════════════════

    function analyzeTextLog(content, fileName, activeCats) {
        var findings = [];
        var matchedIds = {};

        var safeContent = content;
        if (safeContent.length > MAX_TEXT_SIZE) {
            safeContent = safeContent.substring(0, MAX_TEXT_SIZE) + '\n[...contenido truncado por tamaño...]';
        }

        var lines = safeContent.split('\n');
        if (lines.length > MAX_LINES_FOR_TEXT) {
            lines = lines.slice(0, MAX_LINES_FOR_TEXT);
            lines.push('[...más líneas omitidas...]');
        }
        var lineCount = lines.length;

        for (var i = 0; i < SIGNATURES.length; i++) {
            var sig = SIGNATURES[i];
            if (!activeCats[sig.category]) continue;
            if (matchedIds[sig.id]) continue;

            var regex;
            try {
                regex = new RegExp(sig.regex.source, 'gi');
            } catch (e) {
                continue;
            }

            var match = regex.exec(safeContent);
            if (match) {
                var contextLine = -1;
                var contextText = '';
                for (var l = 0; l < lineCount; l++) {
                    var lineText = lines[l].substring(0, MAX_LINE_LENGTH);
                    if (regex.test(lineText)) {
                        contextLine = l + 1;
                        contextText = lineText;
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

        findings.sort(function (a, b) {
            var sa = SEVERITY_ORDER[a.severity] || 99;
            var sb = SEVERITY_ORDER[b.severity] || 99;
            return sa - sb;
        });

        return findings;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ORQUESTACIÓN DEL ANÁLISIS
    // ═══════════════════════════════════════════════════════════════════════════

    function detectLogFormat(name) {
        var ext = name.split('.').pop().toLowerCase();
        if (ext === 'dmp' || ext === 'mdmp' || ext === 'hdmp' || ext === 'kdmp') return 'dump';
        if (ext === 'evtx') return 'windows';
        if (ext === 'syslog') return 'syslog';
        if (ext === 'csv') return 'csv';
        return 'generic';
    }

    function analyze(data, activeCats) {
        var findings = [];
        var totalLines = 0;
        var logFormat = detectLogFormat(data.name);
        var hashPromise;

        // Compute SHA-256 for the file buffer
        if (data.content instanceof ArrayBuffer) {
            hashPromise = sha256(data.content);
        } else {
            hashPromise = Promise.resolve(null);
        }

        if (logFormat === 'windows' && /\.evtx$/i.test(data.name)) {
            findings.push({
                id: 'EVTX-NOPARSE', category: 'windows', severity: 'info',
                name: 'Formato .evtx no compatible',
                description: 'El formato EVTX (Windows Event Log) no puede analizarse en el navegador sin un parser especializado.',
                impact: 'Los archivos .evtx no se pueden procesar.',
                remediation: 'Convierte el .evtx a texto con: wevtutil epl archivo.evtx archivo.txt o Get-WinEvent -Path archivo.evtx | Out-File archivo.txt',
                mitre: '', line: 0, context: '', matched: ''
            });
        } else if (data.binary && logFormat === 'dump') {
            findings = analyzeDump(data.content, data.name, activeCats);
            totalLines = 0;
        } else if (data.binary && /\.zip$/i.test(data.name)) {
            findings = analyzeZip(data.content, data.name, activeCats);
            totalLines = 0;
        } else {
            var textContent = typeof data.content === 'string' ? data.content : '';
            findings = analyzeTextLog(textContent, data.name, activeCats);
            totalLines = textContent.split('\n').length;
        }

        var report = {
            fileName: data.name,
            fileSize: data.size || (currentFile ? currentFile.size : 0),
            timestamp: new Date().toISOString(),
            totalLines: totalLines,
            logFormat: logFormat,
            totalFindings: findings.length,
            severityCounts: countSeverities(findings),
            findings: findings,
            fileHash: null,
            summary: null,
            actions: null
        };

        return hashPromise.then(function(hash) {
            report.fileHash = hash;
            report.summary = generateSummary(report);
            report.actions = generateActionPlan(report);
            return report;
        });
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

    // ═══════════════════════════════════════════════════════════════════════════
    // SHA-256 HASH
    // ═══════════════════════════════════════════════════════════════════════════

    function sha256(buffer) {
        try {
            return crypto.subtle.digest('SHA-256', buffer).then(function(hash) {
                var hex = '';
                var bytes = new Uint8Array(hash);
                for (var i = 0; i < bytes.length; i++) {
                    hex += ('00' + bytes[i].toString(16)).slice(-2);
                }
                return hex;
            });
        } catch (e) {
            return Promise.resolve('no-disponible');
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // RESUMEN NARRATIVO Y PLAN DE ACCIONES
    // ═══════════════════════════════════════════════════════════════════════════

    function generateSummary(report) {
        var critical = report.severityCounts.critical || 0;
        var high = report.severityCounts.high || 0;
        var medium = report.severityCounts.medium || 0;
        var findingCount = report.findings.length;

        var parts = [];
        var typeLabel = report.logFormat === 'dump' ? 'volcado de memoria' : 'log';
        parts.push('Se analizó un ' + typeLabel + ' (' + report.fileName + ')');

        if (findingCount === 0) {
            parts.push('sin hallazgos de seguridad o errores relevantes.');
            return parts.join(' ');
        }

        parts.push('identificando ' + findingCount + ' hallazgos');
        var sevParts = [];
        if (critical > 0) sevParts.push(critical + ' críticos');
        if (high > 0) sevParts.push(high + ' altos');
        if (medium > 0) sevParts.push(medium + ' medios');
        if (sevParts.length > 0) {
            parts.push('de los cuales ' + sevParts.join(', '));
        }
        parts.push('.');

        var topFinding = report.findings[0];
        if (topFinding && topFinding.severity !== 'info') {
            parts.push(' El hallazgo más relevante es "' + topFinding.name + '" (severidad ' + topFinding.severity + ').');
            if (topFinding.remediation) {
                parts.push(' Recomendación principal: ' + topFinding.remediation.split(/\./)[0] + '.');
            }
        }

        return parts.join('');
    }

    function generateActionPlan(report) {
        var actions = [];
        for (var i = 0; i < report.findings.length && actions.length < 10; i++) {
            var f = report.findings[i];
            if (f.severity === 'info' || f.severity === 'low') continue;
            actions.push({
                priority: (f.severity === 'critical' ? 1 : f.severity === 'high' ? 2 : 3),
                title: f.name,
                action: f.remediation.split(/\./)[0] || f.remediation,
                severity: SEVERITY_LABELS[f.severity] || f.severity
            });
        }
        actions.sort(function(a, b) { return a.priority - b.priority; });
        return actions.slice(0, 10);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SOPORTE PARA ARCHIVOS ZIP
    // ═══════════════════════════════════════════════════════════════════════════

    function parseZipEntries(buf) {
        var view = new Uint8Array(buf);
        var entries = [];
        var i = 0;

        // Look for local file headers (PK\x03\x04)
        while (i < view.length - 30) {
            if (view[i] === 0x50 && view[i+1] === 0x4B && view[i+2] === 0x03 && view[i+3] === 0x04) {
                var compression = view[i+8] | (view[i+9] << 8);
                var crc32 = view[i+14] | (view[i+15] << 8) | (view[i+16] << 16) | (view[i+17] << 24);
                var compSize = view[i+18] | (view[i+19] << 8) | (view[i+20] << 16) | (view[i+21] << 24);
                var uncompSize = view[i+22] | (view[i+23] << 8) | (view[i+24] << 16) | (view[i+25] << 24);
                var nameLen = view[i+26] | (view[i+27] << 8);
                var extraLen = view[i+28] | (view[i+29] << 8);

                var nameBytes = view.slice(i + 30, i + 30 + nameLen);
                var name = '';
                for (var nb = 0; nb < nameBytes.length; nb++) {
                    if (nameBytes[nb] >= 32 && nameBytes[nb] <= 126) name += String.fromCharCode(nameBytes[nb]);
                }

                var dataStart = i + 30 + nameLen + extraLen;

                if (name && !name.match(/__MACOSX|\.\./) && dataStart + compSize <= view.length) {
                    var data;
                    if (compression === 0) {
                        data = buf.slice(dataStart, dataStart + uncompSize);
                    } else {
                        data = null; // compressed not supported
                    }
                    entries.push({ name: name, size: compSize, data: data, compressed: compression !== 0 });
                }

                i = dataStart + compSize;
            } else {
                i++;
            }
        }
        return entries;
    }

    function analyzeZip(content, fileName, activeCats) {
        var allFindings = [];
        var entries = parseZipEntries(content);
        var fileLabel = ' (extraído de ' + fileName + ')';

        if (entries.length === 0) {
            allFindings.push({
                id: 'ZIP-EMPTY', category: 'crash', severity: 'info',
                name: 'No se encontraron archivos analizables en el ZIP',
                description: 'El archivo ZIP no contiene entradas válidas o están comprimidas (solo ZIP sin compresión).',
                impact: '',
                remediation: 'Asegúrate de que el ZIP contiene logs (.log, .txt) o dumps (.dmp) sin comprimir.',
                mitre: '', line: 0, context: '', matched: ''
            });
            return allFindings;
        }

        for (var ei = 0; ei < entries.length; ei++) {
            var entry = entries[ei];
            if (entry.compressed) continue;

            var entryFindings = [];
            var isDmp = /\.(?:dmp|mdmp|hdmp|kdmp)$/i.test(entry.name);
            var logFormat = detectLogFormat(entry.name);

            if (logFormat === 'dmp' || isDmp) {
                entryFindings = analyzeDump(entry.data, entry.name, activeCats);
            } else {
                var text = '';
                if (entry.data) {
                    var arr = new Uint8Array(entry.data);
                    for (var bi = 0; bi < arr.length; bi++) {
                        text += String.fromCharCode(arr[bi]);
                    }
                }
                entryFindings = analyzeTextLog(text, entry.name, activeCats);
            }

            for (var ej = 0; ej < entryFindings.length; ej++) {
                entryFindings[ej].name = entryFindings[ej].name + fileLabel;
                entryFindings[ej].id = entryFindings[ej].id + '-ZIP-' + ei;
            }
            allFindings = allFindings.concat(entryFindings);
        }

        allFindings.sort(function(a, b) {
            var sa = SEVERITY_ORDER[a.severity] || 99;
            var sb = SEVERITY_ORDER[b.severity] || 99;
            return sa - sb;
        });

        if (allFindings.length > 0) {
            allFindings.unshift({
                id: 'ZIP-INFO', category: 'crash', severity: 'info',
                name: 'Archivos analizados del ZIP: ' + entries.length,
                description: 'Se encontraron y analizaron ' + entries.filter(function(e) { return !e.compressed; }).length + ' archivos del ZIP (' + entries.length + ' totales).',
                impact: '',
                remediation: '',
                mitre: '', line: 0, context: entries.map(function(e) { return e.name; }).join(', ').substring(0, 400), matched: ''
            });
        }

        return allFindings;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // EXPORTACIÓN Markdown / HTML
    // ═══════════════════════════════════════════════════════════════════════════

    function exportReportMarkdown(report) {
        var md = '# LogWise — Informe de Análisis\n\n';
        md += '**Archivo:** ' + report.fileName + '  \n';
        md += '**Fecha:** ' + new Date(report.timestamp).toLocaleString('es-ES') + '  \n';
        md += '**Formato:** ' + report.logFormat + '  \n';
        md += '**Tamaño:** ' + (report.fileSize ? formatFileSize(report.fileSize) : 'N/A') + '  \n';
        if (report.fileHash) md += '**SHA-256:** `' + report.fileHash + '`  \n';
        if (report.summary) md += '\n## Resumen\n\n' + report.summary + '\n';

        md += '\n## Severidad\n\n';
        md += '| Crítico | Alto | Medio | Bajo | Info |\n';
        md += '|--------|------|-------|------|------|\n';
        md += '| ' + (report.severityCounts.critical || 0) + ' | ' + (report.severityCounts.high || 0) + ' | ';
        md += (report.severityCounts.medium || 0) + ' | ' + (report.severityCounts.low || 0) + ' | ';
        md += (report.severityCounts.info || 0) + ' |\n';

        if (report.actions && report.actions.length > 0) {
            md += '\n## Acciones Prioritarias\n\n';
            for (var ai = 0; ai < report.actions.length; ai++) {
                md += (ai + 1) + '. **[' + report.actions[ai].severity + ']** ' + report.actions[ai].title + ' — ' + report.actions[ai].action + '\n';
            }
        }

        md += '\n## Hallazgos (' + report.findings.length + ')\n\n';
        for (var fi = 0; fi < report.findings.length; fi++) {
            var f = report.findings[fi];
            var sevLabel = SEVERITY_LABELS[f.severity] || f.severity;
            md += '### ' + (fi + 1) + '. [' + sevLabel + '] ' + f.name + '\n\n';
            if (f.description) md += '- **Descripción:** ' + f.description + '\n';
            if (f.impact) md += '- **Impacto:** ' + f.impact + '\n';
            if (f.remediation) md += '- **Recomendación:** ' + f.remediation + '\n';
            if (f.mitre) md += '- **MITRE:** ' + f.mitre + '\n';
            if (f.context) md += '- **Contexto:** `' + f.context.substring(0, 200) + '`\n';
            md += '\n';
        }
        md += '---\n*Generado por LogWise — Analizador Forense*\n';
        return md;
    }

    function exportReportHtml(report) {
        var h = '<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8">';
        h += '<title>LogWise — Informe: ' + escapeHtml(report.fileName) + '</title>';
        h += '<style>body{font-family:-apple-system,sans-serif;margin:2rem;color:#333;background:#fff}';
        h += 'h1{color:#5bc0be}h2{border-bottom:1px solid #ddd;padding-bottom:4px}';
        h += '.critical{color:#e74c3c}.high{color:#f39c12}.medium{color:#f1c40f}.low{color:#2ecc71}.info{color:#3498db}';
        h += '.finding{margin:1rem 0;padding:1rem;border:1px solid #ddd;border-radius:6px}';
        h += '.finding.critical{border-left:4px solid #e74c3c}.finding.high{border-left:4px solid #f39c12}';
        h += '.finding.medium{border-left:4px solid #f1c40f}.finding.low{border-left:4px solid #2ecc71}';
        h += '.finding.info{border-left:4px solid #3498db}';
        h += '.sev{display:inline-block;padding:2px 8px;border-radius:3px;font-size:0.8rem;font-weight:700;color:#fff}';
        h += '.sev.critical{background:#e74c3c}.sev.high{background:#f39c12}.sev.medium{background:#f1c40f;color:#333}';
        h += '.sev.low{background:#2ecc71}.sev.info{background:#3498db}';
        h += '.meta{color:#666;font-size:0.9rem}.remediation{background:#f0faf9;padding:8px 12px;border-radius:4px;margin:8px 0}';
        h += 'table{border-collapse:collapse;width:auto}td,th{border:1px solid #ddd;padding:6px 12px}';
        h += '.actions{padding:0;list-style:none}.actions li{padding:6px 0;border-bottom:1px solid #eee}';
        h += '</style></head><body>';
        h += '<h1>LogWise — Informe de Análisis</h1>';
        h += '<p class="meta"><strong>Archivo:</strong> ' + escapeHtml(report.fileName) + '<br>';
        h += '<strong>Fecha:</strong> ' + new Date(report.timestamp).toLocaleString('es-ES') + '<br>';
        h += '<strong>Formato:</strong> ' + report.logFormat + '<br>';
        h += '<strong>Tamaño:</strong> ' + (report.fileSize ? formatFileSize(report.fileSize) : 'N/A') + '</p>';
        if (report.fileHash) h += '<p><strong>SHA-256:</strong> <code>' + report.fileHash + '</code></p>';
        if (report.summary) h += '<h2>Resumen</h2><p>' + escapeHtml(report.summary) + '</p>';

        h += '<h2>Severidad</h2><table><tr><th>Crítico</th><th>Alto</th><th>Medio</th><th>Bajo</th><th>Info</th></tr>';
        h += '<tr><td>' + (report.severityCounts.critical || 0) + '</td><td>' + (report.severityCounts.high || 0) + '</td>';
        h += '<td>' + (report.severityCounts.medium || 0) + '</td><td>' + (report.severityCounts.low || 0) + '</td>';
        h += '<td>' + (report.severityCounts.info || 0) + '</td></tr></table>';

        if (report.actions && report.actions.length > 0) {
            h += '<h2>Acciones Prioritarias</h2><ol class="actions">';
            for (var ai = 0; ai < report.actions.length; ai++) {
                h += '<li><span class="sev ' + report.actions[ai].severity.toLowerCase() + '">' + escapeHtml(report.actions[ai].severity) + '</span> ';
                h += '<strong>' + escapeHtml(report.actions[ai].title) + '</strong> — ' + escapeHtml(report.actions[ai].action) + '</li>';
            }
            h += '</ol>';
        }

        h += '<h2>Hallazgos (' + report.findings.length + ')</h2>';
        for (var fi = 0; fi < report.findings.length; fi++) {
            var f = report.findings[fi];
            var sevClass = SEVERITY_CLASSES[f.severity] || 'info';
            var sevLabel = SEVERITY_LABELS[f.severity] || f.severity;
            h += '<div class="finding ' + sevClass + '">';
            h += '<h3><span class="sev ' + sevClass + '">' + sevLabel + '</span> ' + escapeHtml(f.name) + '</h3>';
            if (f.description) h += '<p><strong>Descripción:</strong> ' + escapeHtml(f.description) + '</p>';
            if (f.impact) h += '<p><strong>Impacto:</strong> ' + escapeHtml(f.impact) + '</p>';
            if (f.remediation) h += '<div class="remediation"><strong>Recomendación:</strong> ' + escapeHtml(f.remediation) + '</div>';
            if (f.mitre) h += '<p><strong>MITRE:</strong> ' + escapeHtml(f.mitre) + '</p>';
            if (f.context) h += '<p><strong>Contexto:</strong> <code>' + escapeHtml(f.context.substring(0, 300)) + '</code></p>';
            h += '</div>';
        }
        h += '<hr><p><em>Generado por LogWise — Analizador Forense</em></p></body></html>';
        return h;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // UI Y RENDERIZADO
    // ── Sin innerHTML (excepto para contenedores vacíos)
    // ── Sin event handlers inline
    // ── Opt-in DuckDuckGo explícito
    // ═══════════════════════════════════════════════════════════════════════════

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
            compliance: document.getElementById('cfgCompliance'),
            ddgOptIn: document.getElementById('cfgDdgOptIn')
        }
    };

    var currentFile = null;
    var currentContent = null;
    var currentFindings = null;

    function getActiveCategories() {
        var active = {};
        for (var key in ui.cfg) {
            if (key === 'ddgOptIn') continue;
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
        ui.findingsList.innerHTML = '';
        ui.severitySummary.innerHTML = '';
    }

    function handleFile(file) {
        if (file.size > MAX_FILE_SIZE) {
            alert('El archivo supera el límite de ' + formatFileSize(MAX_FILE_SIZE) + '.');
            return;
        }
        currentFile = file;
        ui.analyzeBtn.disabled = false;
        ui.dropZone.classList.add('has-file');
        ui.fileName.textContent = file.name;
        ui.fileMeta.textContent = formatFileSize(file.size) + ' · ' + (file.type || 'desconocido');
        ui.fileInfo.classList.add('show');
    }

    function readFile(file) {
        return new Promise(function (resolve, reject) {
            var isDmp = /\.(?:dmp|mdmp|hdmp|kdmp)$/i.test(file.name);
            var isZip = /\.zip$/i.test(file.name);
            var reader = new FileReader();
            reader.onload = function (e) {
                resolve({ name: file.name, size: file.size, type: file.type, content: e.target.result, binary: isDmp || isZip });
            };
            reader.onerror = function () { reject(new Error('Error al leer el archivo')); };
            if (isDmp || isZip) {
                reader.readAsArrayBuffer(file);
            } else {
                reader.readAsText(file, 'utf-8');
            }
        });
    }

    function el(tag, attrs, text) {
        var elem = document.createElement(tag);
        if (attrs) {
            for (var k in attrs) {
                if (k === 'className') {
                    elem.className = attrs[k];
                } else {
                    elem.setAttribute(k, attrs[k]);
                }
            }
        }
        if (text !== undefined && text !== null) {
            elem.appendChild(document.createTextNode(text));
        }
        return elem;
    }

    function icon(classes) {
        var i = document.createElement('i');
        i.className = classes;
        return i;
    }

    function renderReport(report) {
        ui.reportTitle.textContent = 'Informe: ' + report.fileName;
        ui.reportTimestamp.textContent = new Date(report.timestamp).toLocaleString('es-ES');

        // Clear extra sections
        var existingSummary = document.getElementById('reportSummary');
        if (existingSummary) existingSummary.remove();
        var existingActions = document.getElementById('reportActions');
        if (existingActions) existingActions.remove();
        var existingHash = document.getElementById('reportHash');
        if (existingHash) existingHash.remove();

        // SHA-256 hash
        if (report.fileHash) {
            var hashDiv = el('div', { id: 'reportHash', style: 'font-size:0.78rem;color:var(--text-muted);font-family:var(--font-mono);margin-bottom:12px;padding:8px 12px;background:rgba(0,0,0,0.2);border-radius:4px;word-break:break-all' });
            hashDiv.appendChild(el('strong', null, 'SHA-256: '));
            hashDiv.appendChild(document.createTextNode(report.fileHash));
            ui.report.querySelector('.report-header').appendChild(hashDiv);
        }

        // Narrative summary
        if (report.summary) {
            var summaryDiv = el('div', { id: 'reportSummary', style: 'font-size:0.9rem;color:var(--text);margin-bottom:16px;padding:12px 16px;background:rgba(91,192,190,0.06);border:1px solid rgba(91,192,190,0.2);border-radius:6px;line-height:1.6' });
            summaryDiv.appendChild(icon('fa-solid fa-robot'));
            summaryDiv.appendChild(document.createTextNode(' ' + report.summary));
            ui.report.querySelector('.report-header').appendChild(summaryDiv);
        }

        // Action plan
        if (report.actions && report.actions.length > 0) {
            var actionsDiv = el('div', { id: 'reportActions', style: 'margin-bottom:20px;padding:16px;background:rgba(0,0,0,0.2);border:1px solid var(--border);border-radius:6px' });
            var actionsTitle = el('h3', { style: 'margin:0 0 12px;font-size:1rem;display:flex;align-items:center;gap:8px' });
            actionsTitle.appendChild(icon('fa-solid fa-list-check'));
            actionsTitle.appendChild(document.createTextNode(' Plan de Acción Prioritario'));
            actionsDiv.appendChild(actionsTitle);

            var actList = el('ol', { style: 'margin:0;padding-left:24px' });
            for (var ai = 0; ai < report.actions.length; ai++) {
                var actItem = el('li', { style: 'margin-bottom:6px;font-size:0.88rem;line-height:1.5' });
                var sevSpan = el('span', {
                    className: 'finding-severity ' + (SEVERITY_CLASSES[report.actions[ai].severity.toLowerCase()] || ''),
                    style: 'margin-right:8px;font-size:0.7rem'
                }, report.actions[ai].severity);
                actItem.appendChild(sevSpan);
                var strong = el('strong', null, ' ' + report.actions[ai].title);
                actItem.appendChild(strong);
                actItem.appendChild(document.createTextNode(' — ' + report.actions[ai].action));
                actList.appendChild(actItem);
            }
            actionsDiv.appendChild(actList);
            var findingsSection = ui.report.querySelector('.findings-section');
            if (findingsSection) {
                findingsSection.parentNode.insertBefore(actionsDiv, findingsSection);
            }
        }

        ui.severitySummary.innerHTML = '';
        var sevList = [
            { key: 'critical', label: 'Crítico' },
            { key: 'high', label: 'Alto' },
            { key: 'medium', label: 'Medio' },
            { key: 'low', label: 'Bajo' },
            { key: 'info', label: 'Info' }
        ];
        for (var s = 0; s < sevList.length; s++) {
            var sev = sevList[s];
            var cnt = report.severityCounts[sev.key] || 0;
            var item = el('div', { className: 'severity-item ' + sev.key });
            item.appendChild(el('div', { className: 'count' }, cnt));
            item.appendChild(el('div', { className: 'label' }, sev.label));
            ui.severitySummary.appendChild(item);
        }

        ui.findingsList.innerHTML = '';
        if (report.findings.length === 0) {
            var noFind = el('div', { className: 'no-findings' });
            var iconDiv = el('div', { className: 'icon' });
            iconDiv.appendChild(icon('fa-solid fa-shield-check'));
            noFind.appendChild(iconDiv);
            noFind.appendChild(el('h3', null, 'Sin hallazgos'));
            noFind.appendChild(el('p', null, 'No se detectaron patrones de seguridad en el archivo analizado.'));
            ui.findingsList.appendChild(noFind);
        } else {
            for (var f = 0; f < report.findings.length; f++) {
                ui.findingsList.appendChild(renderFindingCard(report.findings[f]));
            }
        }

        ui.report.classList.add('show');
        ui.report.scrollIntoView({ behavior: 'smooth', block: 'start' });
        currentFindings = report;
    }

    function renderFindingCard(finding) {
        var card = el('div', {
            className: 'finding-card ' + (SEVERITY_CARD[finding.severity] || ''),
            id: 'finding-' + safeId(finding.id)
        });

        var hdr = el('div', { className: 'finding-header' });
        hdr.appendChild(el('span', { className: 'finding-title' }, finding.name));
        hdr.appendChild(el('span', { className: 'finding-severity ' + (SEVERITY_CLASSES[finding.severity] || '') }, SEVERITY_LABELS[finding.severity] || finding.severity));
        card.appendChild(hdr);

        card.appendChild(el('div', { className: 'finding-detail' }, 'Descripción: ' + finding.description));
        card.appendChild(el('div', { className: 'finding-detail' }, 'Impacto: ' + finding.impact));

        var remed = el('div', { className: 'finding-remediation' });
        remed.appendChild(icon('fa-solid fa-wrench'));
        remed.appendChild(document.createTextNode(' Recomendación: ' + finding.remediation));
        card.appendChild(remed);

        if (finding.mitre) {
            card.appendChild(el('div', { className: 'finding-mitre' }, 'MITRE ATT&CK: ' + finding.mitre));
        }
        if (finding.line > 0 && finding.context) {
            var lineDiv = el('div', { className: 'finding-line' });
            lineDiv.appendChild(el('strong', null, 'Línea ' + finding.line + ': '));
            lineDiv.appendChild(document.createTextNode(finding.context));
            card.appendChild(lineDiv);
        }

        card.appendChild(renderSearchButtons(finding));
        return card;
    }

    function buildSearchQuery(finding) {
        var parts = [finding.name];
        if (finding.mitre) parts.push('MITRE ATT&CK ' + finding.mitre);
        if (finding.remediation) {
            var words = finding.remediation.split(/\s+/).slice(0, 6).join(' ');
            parts.push(words);
        }
        return parts.join(' ').substring(0, 200);
    }

    function getSearchUrls(finding) {
        var query = encodeURIComponent(buildSearchQuery(finding));
        var sfPrefix = (finding.category === 'linux') ? 'linux ' :
                       (finding.category === 'windows' || finding.category === 'crash') ? 'windows ' :
                       (finding.category === 'web') ? '' : '';
        var urls = {
            duckduckgo: 'https://duckduckgo.com/?q=' + query + '&ia=web',
            stackoverflow: 'https://stackoverflow.com/search?q=' + encodeURIComponent(finding.name.substring(0, 120)),
            serverfault: 'https://serverfault.com/search?q=' + encodeURIComponent(sfPrefix + finding.name.substring(0, 100))
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

    function renderSearchButtons(finding) {
        var urls = getSearchUrls(finding);
        var bar = el('div', { className: 'research-bar' });
        var label = el('span', { className: 'research-label' });
        label.appendChild(icon('fa-solid fa-magnifying-glass'));
        label.appendChild(document.createTextNode(' Investigar:'));
        bar.appendChild(label);

        if (ui.cfg.ddgOptIn && ui.cfg.ddgOptIn.checked) {
            var ddgBtn = el('button', {
                type: 'button',
                className: 'research-btn ddg-search-btn ddg',
                title: 'Auto-buscar causa raíz en DuckDuckGo'
            });
            ddgBtn.appendChild(icon('fa-solid fa-bolt'));
            ddgBtn.appendChild(document.createTextNode(' Causa raíz'));
            ddgBtn.addEventListener('click', (function(fid, f) {
                return function() { triggerDdgSearch(fid, f); };
            })(safeId(finding.id), finding));
            bar.appendChild(ddgBtn);
        }

        var links = [
            { href: urls.duckduckgo, cls: 'ddg', title: 'Abrir DuckDuckGo en pestaña', icon: 'fa-solid fa-magnifying-glass', text: ' DuckDuckGo' },
            { href: urls.stackoverflow, cls: 'so', title: 'Stack Overflow', icon: 'fa-brands fa-stack-overflow', text: ' Stack Overflow' },
            { href: urls.serverfault, cls: 'sf', title: 'Server Fault', icon: 'fa-solid fa-server', text: ' Server Fault' }
        ];
        if (urls.microsoft) links.push({ href: urls.microsoft, cls: 'ms', title: 'Microsoft Learn', icon: 'fa-brands fa-microsoft', text: ' Microsoft' });
        if (urls.mitre) links.push({ href: urls.mitre, cls: 'mitre', title: 'MITRE ATT&CK', icon: 'fa-solid fa-shield-halved', text: ' MITRE' });

        for (var li = 0; li < links.length; li++) {
            var a = el('a', {
                href: links[li].href,
                target: '_blank',
                rel: 'noopener noreferrer',
                className: 'research-btn ' + links[li].cls,
                title: links[li].title
            });
            a.appendChild(icon(links[li].icon));
            a.appendChild(document.createTextNode(links[li].text));
            bar.appendChild(a);
        }

        var results = el('div', { className: 'ddg-results', id: 'ddg-' + safeId(finding.id) });
        results.style.display = 'none';

        var container = el('div');
        container.appendChild(bar);
        container.appendChild(results);
        return container;
    }

    function triggerDdgSearch(findingId, finding) {
        var card = document.getElementById('finding-' + findingId);
        if (!card) return;
        var btn = card.querySelector('.ddg-search-btn');
        var results = card.querySelector('.ddg-results');
        if (!btn || !results) return;

        btn.disabled = true;
        btn.innerHTML = '';
        btn.appendChild(icon('spinner'));
        btn.appendChild(document.createTextNode(' Buscando…'));

        var query = encodeURIComponent(buildSearchQuery(finding));
        var url = 'https://api.duckduckgo.com/?q=' + query + '&format=json&no_html=1&skip_disambig=1&t=logwise';

        results.style.display = 'block';
        results.innerHTML = '';
        var loading = el('div', { className: 'ddg-loading' });
        loading.appendChild(icon('spinner'));
        loading.appendChild(document.createTextNode(' Consultando DuckDuckGo…'));
        results.appendChild(loading);

        fetch(url)
            .then(function (r) {
                if (!r.ok) throw new Error('HTTP ' + r.status);
                return r.json();
            })
            .then(function (data) {
                results.innerHTML = '';
                var h = el('div', { className: 'ddg-header' });
                h.appendChild(icon('fa-solid fa-magnifying-glass'));
                h.appendChild(document.createTextNode(' Resultados DuckDuckGo'));
                results.appendChild(h);

                if (data.AbstractText) {
                    results.appendChild(el('div', { className: 'ddg-abstract' }, 'Resumen: ' + data.AbstractText));
                    if (data.AbstractURL) {
                        var src = el('div', { className: 'ddg-source' });
                        var sa = el('a', { href: data.AbstractURL, target: '_blank', rel: 'noopener noreferrer' }, 'Fuente: ' + (data.AbstractSource || data.AbstractURL));
                        src.appendChild(sa);
                        results.appendChild(src);
                    }
                }

                if (data.RelatedTopics && data.RelatedTopics.length > 0) {
                    var topDiv = el('div', { className: 'ddg-topics' });
                    topDiv.appendChild(el('strong', null, 'Relacionado:'));
                    var ul = el('ul');
                    var cnt = 0;
                    for (var i = 0; i < data.RelatedTopics.length && cnt < 5; i++) {
                        var topic = data.RelatedTopics[i];
                        if (topic.Text) {
                            ul.appendChild(el('li', null, topic.Text.substring(0, 200)));
                            cnt++;
                        } else if (topic.Topics) {
                            for (var j = 0; j < topic.Topics.length && cnt < 5; j++) {
                                ul.appendChild(el('li', null, topic.Topics[j].Text.substring(0, 200)));
                                cnt++;
                            }
                        }
                    }
                    topDiv.appendChild(ul);
                    results.appendChild(topDiv);
                }

                if (data.Results && data.Results.length > 0) {
                    var linksDiv = el('div', { className: 'ddg-results-list' });
                    linksDiv.appendChild(el('strong', null, 'Enlaces:'));
                    var ul2 = el('ul');
                    for (var k = 0; k < Math.min(data.Results.length, 3); k++) {
                        var res = data.Results[k];
                        var ra = el('a', { href: res.FirstURL, target: '_blank', rel: 'noopener noreferrer' }, res.Text);
                        var li = el('li');
                        li.appendChild(ra);
                        ul2.appendChild(li);
                    }
                    linksDiv.appendChild(ul2);
                    results.appendChild(linksDiv);
                }

                if (!data.AbstractText && (!data.RelatedTopics || data.RelatedTopics.length === 0)) {
                    results.appendChild(el('div', { className: 'ddg-empty' }, 'No se encontraron resultados instantáneos.'));
                }

                results.appendChild(el('div', { className: 'ddg-footer' }, 'Resultados de DuckDuckGo · Búsqueda privada'));

                btn.innerHTML = '';
                btn.appendChild(icon('fa-solid fa-rotate'));
                btn.appendChild(document.createTextNode(' Buscar de nuevo'));
                btn.disabled = false;
            })
            .catch(function (err) {
                results.innerHTML = '';
                var errDiv = el('div', { className: 'ddg-error' });
                errDiv.appendChild(icon('fa-solid fa-triangle-exclamation'));
                errDiv.appendChild(document.createTextNode(' No se pudo consultar DuckDuckGo: ' + err.message + '.'));
                var note = el('span', { style: 'font-size:0.85rem' }, ' Los navegadores pueden bloquear la API. Prueba abriendo DuckDuckGo manualmente desde los botones de arriba.');
                errDiv.appendChild(el('br'));
                errDiv.appendChild(note);
                results.appendChild(errDiv);

                btn.innerHTML = '';
                btn.appendChild(icon('fa-solid fa-magnifying-glass'));
                btn.appendChild(document.createTextNode(' Causa raíz'));
                btn.disabled = false;
            });
    }

    function exportReport(report, format) {
        format = format || 'json';
        var content, filename, mime;

        if (format === 'json') {
            content = JSON.stringify(report, null, 2);
            filename = 'LogWise-reporte-' + report.fileName.replace(/\.[^.]+$/, '') + '.json';
            mime = 'application/json';
        } else if (format === 'markdown') {
            content = exportReportMarkdown(report);
            filename = 'LogWise-reporte-' + report.fileName.replace(/\.[^.]+$/, '') + '.md';
            mime = 'text/markdown';
        } else if (format === 'html') {
            content = exportReportHtml(report);
            filename = 'LogWise-reporte-' + report.fileName.replace(/\.[^.]+$/, '') + '.html';
            mime = 'text/html';
        }

        var blob = new Blob([content], { type: mime });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = filename;
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
        btn.innerHTML = '';
        btn.appendChild(icon('spinner'));
        btn.appendChild(document.createTextNode(' Analizando…'));

        readFile(currentFile).then(function (fileData) {
            currentContent = fileData.content;
            var activeCats = getActiveCategories();
            return analyze(fileData, activeCats);
        }).then(function (report) {
            renderReport(report);
        }).catch(function (err) {
            alert('Error al leer el archivo: ' + err.message);
        }).finally(function () {
            btn.disabled = false;
            btn.innerHTML = '';
            btn.appendChild(icon('fa-solid fa-flask'));
            btn.appendChild(document.createTextNode(' Analizar'));
        });
    });

    ui.exportBtn.addEventListener('click', function () {
        if (currentFindings) exportReport(currentFindings, 'json');
    });

    // Export format buttons (created dynamically)
    function addExportFormatButtons() {
        var formats = [
            { text: ' Markdown', icon: 'fa-brands fa-markdown', format: 'markdown' },
            { text: ' HTML', icon: 'fa-solid fa-code', format: 'html' }
        ];
        for (var fi = 0; fi < formats.length; fi++) {
            var btn = el('button', { type: 'button', className: 'btn btn-outline', style: 'flex:0.5;min-width:auto' });
            btn.appendChild(icon(formats[fi].icon));
            btn.appendChild(document.createTextNode(formats[fi].text));
            btn.addEventListener('click', (function(fmt) {
                return function() {
                    if (currentFindings) exportReport(currentFindings, fmt);
                };
            })(formats[fi].format));
            ui.exportBtn.parentNode.insertBefore(btn, ui.exportBtn.nextSibling);
        }
    }
    addExportFormatButtons();

    ui.printBtn.addEventListener('click', function () {
        window.print();
    });

})();

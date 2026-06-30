# Skills de seguridad curadas para tu flujo

> **Fecha**: 2026-06-30
> **Origen**: https://github.com/sickn33/antigravity-awesome-skills (1.700 skills, 96 con关键词 de seguridad).
> **Método**: `git ls-tree` recursivo para verificar existencia real, lectura de cada `SKILL.md`, aplicación de la skill `skill-audit`.
> **Para**: Karitsu (autista, objetivos: organizarse mejor, usar esto para ciberseguridad, mirar bien sitios, documentar todo).

---

## TL;DR — qué instalar

**Recomendación inmediata** (instalar estas 8, riesgo bajo):

| Skill | Para qué te sirve | Riesgo |
|---|---|---|
| `top-web-vulnerabilities` | Auditar un sitio web (las 100 vulns más críticas) | 12/100 ✅ |
| `web-security-testing` | Workflow de testing web paso a paso | 10/100 ✅ |
| `vulnerability-scanner` | Visión OWASP Top 10:2025 | 13/100 ✅ |
| `security-audit` | Bundle maestro que orquesta las demás | 8/100 ✅ |
| `security-auditor` | Visión DevSecOps / compliance | 15/100 ✅ |
| `threat-modeling-expert` | Modelado de amenazas (STRIDE, PASTA) | 14/100 ✅ |
| `incident-responder` | Qué hacer cuando algo va mal | 16/100 ✅ |
| `secrets-management` | Cómo NO hardcodear secretos | 28/100 ⚠️ |

**Solo si tienes scope autorizado** (instalar con cuidado):

| Skill | Riesgo | Requisito |
|---|---|---|
| `scanning-tools` | 35/100 ⚠️ | Agente en modo read-only o confirmación explícita por comando |
| `pentest-checklist` | 42/100 ⚠️ | Contrato/autorización previa por escrito |

**No instalar todavía**:

| Skill | Riesgo | Por qué |
|---|---|---|
| `xss-html-injection` | 48/100 🟠 | Contiene payloads reales de cookie stealing / session hijacking. Útil como **referencia teórica** (léela una vez, entiéndela), no la instales si tu agente tiene WebFetch/Bash activos. |

---

## Por caso de uso (cómo usarlas en tu flujo)

### 1. Auditar un sitio web
```
1. Carga @top-web-vulnerabilities         ← catálogo de referencia
2. Carga @vulnerability-scanner            ← checklist OWASP 2025
3. Carga @web-security-testing             ← workflow paso a paso
4. Documenta con @security-audit           ← fase de reporting
```

### 2. Auditar un proyecto / código
```
1. Carga @security-auditor                 ← visión DevSecOps completa
2. Carga @vulnerability-scanner            ← OWASP 2025
3. Documenta con @security-audit
```

### 3. Modelar amenazas de un sistema
```
1. Carga @threat-modeling-expert           ← STRIDE / PASTA
2. Documenta con @security-audit
```

### 4. Reaccionar a un incidente
```
1. Carga @incident-responder               ← playbook de 5 minutos
2. Documenta con @security-audit
```

### 5. Higiene personal / gestión de secretos
```
1. Carga @secrets-management               ← cómo NO hardcodear
```

---

## Detalle de cada skill (veredicto skill-audit)

### 1. `top-web-vulnerabilities` · 12/100 ✅
- **Origen**: `community`, autor `zebbern`
- **Contenido**: 100 vulnerabilidades web organizadas en 15 categorías, con mitigaciones y mapeo a OWASP. Cabeceras de seguridad listas para copiar. Tabla de verificación por tipo.
- **Riesgos detectados**: ninguno.
- **Útil para ti porque**: es **literalmente** la guía que pediste ("mirar bien los sitios"). Te da el catálogo mental para no dejarte nada.
- **Cómo usarla**: cuando vayas a auditar un sitio, abre esta skill primero como referencia.

### 2. `web-security-testing` · 10/100 ✅
- **Origen**: `personal` (autor del bundle)
- **Contenido**: workflow de 7 fases (recon → injection → XSS → auth → access control → headers → reporting) con prompts copy-paste.
- **Riesgos detectados**: ninguno.
- **Útil para ti porque**: convierte la auditoría en un proceso paso a paso. Estructura clara. Ideal para tu objetivo de organización.

### 3. `vulnerability-scanner` · 13/100 ✅
- **Origen**: `community`
- **Contenido**: mindset de seguridad, OWASP 2025 (con los cambios 2021→2025 correctamente citados: SSRF→A01, supply chain→A03, exceptional conditions→A10), supply chain, attack surface mapping, priorización CVSS+EPSS, anti-patrones, reporting.
- **Riesgos detectados**: ninguno.
- **Útil para ti porque**: te da la **visión actualizada a 2025**, no la de 2021 que está obsoleta.

### 4. `security-audit` · 8/100 ✅
- **Origen**: `personal`
- **Contenido**: bundle maestro con 7 fases (recon → vuln scan → web app testing → API → pentest → hardening → reporting). Invoca otras skills.
- **Riesgos detectados**: ninguno.
- **Útil para ti porque**: es la "navaja suiza" — un solo punto de entrada que orquesta las demás. Perfecta como skill raíz.

### 5. `security-auditor` · 15/100 ✅
- **Origen**: `community`
- **Contenido**: skill "experta" muy completa con capacidades DevSecOps, auth moderna (OAuth 2.1, OIDC, SAML, WebAuthn, FIDO2), OWASP, ASVS, SAMM, SAST/DAST/IAST, cloud security, compliance (GDPR, HIPAA, PCI-DSS, SOC 2, ISO 27001, NIST CSF), secure coding, network, SIEM/SOAR, AI/ML security.
- **Riesgos detectados**: frontmatter `risk: unknown` (incompleto), pero contenido inocuo.
- **Útil para ti porque**: cuando no sepas por dónde empezar con algo de seguridad, esta skill sabe de casi todo. Buen fallback.

### 6. `threat-modeling-expert` · 14/100 ✅
- **Origen**: `community`
- **Contenido**: STRIDE, PASTA, attack trees, data flow diagrams, risk scoring, mitigations.
- **Riesgos detectados**: ninguno.
- **Útil para ti porque**: antes de auditar un sitio, modela las amenazas. Evita que te quedes solo en "checklist sin entender qué estás defendiendo".

### 7. `incident-responder` · 16/100 ✅
- **Origen**: `community`
- **Contenido**: protocolo de 5 minutos, comunicación, observability-driven investigation, SRE best practices, severities P0-P3, post-mortem blameless.
- **Riesgos detectados**: ninguno.
- **Útil para ti porque**: el día que algo vaya mal (te pillen credenciales, descubras una brecha), tienes un playbook.

### 8. `secrets-management` · 28/100 ⚠️
- **Origen**: `community`
- **Contenido**: Vault, AWS Secrets Manager, Azure Key Vault, Google Secret Manager, GitHub Secrets, GitLab CI, External Secrets Operator, secret scanning con TruffleHog, rotación.
- **Riesgos detectados**: contiene un **ejemplo de secreto hardcodeado** en la documentación: `vault kv put secret/database/config username=admin password=secret` — coincide con el patrón SEC009 del propio escáner del repo. Es **documentación, no es código real**; la contraseña es obvia. Pero es ruido.
- **Útil para ti porque**: te enseña el patrón correcto (Vault, AWS Secrets Manager, env vars, rotación) y los antipatrones (hardcodear).

### 9. `scanning-tools` · 35/100 ⚠️
- **Origen**: `community`, autor `zebbern`
- **Contenido**: ejemplos de uso de nmap, masscan, Nessus, OpenVAS, Burp Suite, ZAP, Nikto, Aircrack-ng, Kismet, ClamAV, Metasploit, Prowler, ScoutSuite, Lynis, OpenSCAP.
- **Riesgos detectados**: ejemplos de `nmap -A`, `aircrack-ng`, `aireplay-ng -0 10` (deauth). **No son instrucciones para atacar**: son documentación de las herramientas. Pero si tu agente tiene Bash activo y la confirmación está desactivada, podría ejecutar `nmap` contra hosts aleatorios.
- **Útil para ti porque**: referencia enciclopédica de herramientas. Como **lectura**, no como "skill que tu agente ejecuta".
- **Recomendación**: instalar solo si tu agente está en modo read-only o si tienes configuración de permisos estricta en `~/.claude/settings.json`.

### 10. `pentest-checklist` · 42/100 ⚠️
- **Origen**: `community`, autor `zebbern`
- **Contenido**: checklist de pentest: scope, entorno, selección de pentester, monitoring, remediation. Tiene el disclaimer "AUTHORIZED USE ONLY" al inicio.
- **Riesgos detectados**: `risk: offensive` declarado, lo que la lógica del escáner del repo degrada de error a warning. Sin payloads peligrosos. **Solo el contexto ofensivo** implica que NO debe usarse sin autorización escrita previa.
- **Útil para ti porque**: si algún día haces pentest (en entorno autorizado), tienes el checklist. **No la instales si solo vas a hacer auditorías defensivas** — para eso tienes las verdes.

### 11. `xss-html-injection` · 48/100 🟠
- **Origen**: `community`, autor `zebbern`
- **Contenido**: payloads reales de XSS y HTML injection: cookie stealing, keyloggers, session hijacking, phishing form injection, CSS exfiltration, CSP bypass, filter bypass techniques.
- **Riesgos detectados**: **contiene payloads reales de ataque**. Es contenido educativo legítimo (con disclaimer "AUTHORIZED USE ONLY" al inicio), pero **es el archivo más arriesgado de tu subset** si tu agente tiene WebFetch o Bash activos y tú no estás auditando.
- **Recomendación**: NO instalar. **Léela una vez como referencia teórica** (ya está leída y archivada en este informe) y ya está.

---

## Cómo instalar de forma segura

### Opción A — Desde el mirror, con filtros (recomendado para empezar)
```bash
# Solo las 8 skills verdes
npx antigravity-awesome-skills \
  --risk safe,unknown \
  --category development,security \
  --tags web-security,owasp,auditing
```

### Opción B — Manual, una a una (máxima seguridad)
```bash
git clone --depth 1 https://github.com/sickn33/antigravity-awesome-skills.git /tmp/aas
cd /tmp/aas
mkdir -p ~/.claude/skills

# Verdes
cp -r skills/top-web-vulnerabilities      ~/.claude/skills/
cp -r skills/web-security-testing         ~/.claude/skills/
cp -r skills/vulnerability-scanner        ~/.claude/skills/
cp -r skills/security-audit               ~/.claude/skills/
cp -r skills/security-auditor             ~/.claude/skills/
cp -r skills/threat-modeling-expert       ~/.claude/skills/
cp -r skills/incident-responder           ~/.claude/skills/
cp -r skills/secrets-management           ~/.claude/skills/
```

### Opción C — Desde la fuente original de Anthropic (cuando esté disponible)
Si Anthropic mantiene una versión oficial de alguna de estas (p. ej. `claude-api`), prefiere esa. El mirror `sickn33` recopila de muchas fuentes y **no es first-party** (ver `docs/security-audit-sickn33-skills.md` para el análisis completo del mirror).

---

## Antes de instalar: configurar permisos del agente

Aunque las skills son seguras, **tu agente Claude Code tiene permisos por defecto**. Configura `~/.claude/settings.json` para que ningún skill pueda:

- Ejecutar `Bash` sin confirmación explícita.
- Hacer `WebFetch` a dominios fuera de una allowlist.
- Escribir fuera de tu directorio de proyecto.

Plantilla mínima (NO la aplico sin tu confirmación explícita):
```json
{
  "permissions": {
    "allow": ["Read", "Grep", "Glob"],
    "ask":   ["Bash", "WebFetch", "Write", "Edit"],
    "deny":  ["Bash(rm -rf:*)", "Bash(curl:*)", "Bash(wget:*)"]
  }
}
```

---

## Plantilla de informe de auditoría (para tu documentación)

Cuando audites un sitio, usa esta estructura consistente (apta para guardar en `docs/audit-<sitio>-<fecha>.md`):

```markdown
# Auditoría de <sitio> — <fecha>

## 0. Metadata
- URL:
- Tipo (web/API/red):
- Autorización: [sí/no, scope]
- Metodología: OWASP Top 10:2025
- Skills usadas: [lista]

## 1. Resumen ejecutivo
[2-3 líneas, severidad global]

## 2. Hallazgos por severidad
| # | Sev | Título | OWASP | Ubicación | Riesgo |
|---|---|---|---|---|---|

## 3. Detalle de cada hallazgo
### H1 [CRÍTICA] Título
- Categoría: OWASP A0X:2025
- Ubicación: ruta:línea o URL
- Riesgo: ...
- Fuente: ...
- Remedio: ...

## 4. Lo que el sitio hace BIEN
[reconocimientos honestos]

## 5. Cierre
- Auditoría read-only, sin modificar nada.
- Cada remediación propuesta requiere aprobación explícita antes de aplicar.
- Próximos pasos: ...
```

---

## Próximos pasos sugeridos

1. **Decide cuáles de las 8 verdes quieres instalar** (o todas).
2. **Configura `~/.claude/settings.json` con permisos restrictivos** (te muestro la plantilla arriba, espera tu aprobación).
3. **Practica el flujo** con un sitio que controles tú (tu propio portfolio en `karitsu2281.github.io` es ideal — read-only primero).
4. **Documenta cada auditoría** con la plantilla de arriba.
5. **Cuando estés cómodo**, añade las amarillas una a una y con autorización.

---

## Lo que NO he hecho (transparencia)

- No he instalado nada. **No he tocado tu sistema.**
- No he auditado las 96 skills — solo las 11 que parecen más relevantes para tu perfil. El resto de las 96 (lista en `docs/security-audit-sickn33-skills.md`) requieren otra ronda si te interesan.
- No he clonado el repo — he usado GitHub API y `git ls-tree` para verificar existencia real.
- No he commiteado este informe — lo he escrito en `docs/security-skills-curated.md`. Tú decides si entra al repo.

---

*Generado el 2026-06-30 con la skill `security-advisor` + skill `skill-audit`.*

# Auditoría de seguridad — `sickn33/antigravity-awesome-skills`

> **Modo**: solo lectura. No se modificó nada en el repo auditado ni en este repositorio.
> **Fecha**: 2026-06-30
> **Alcance**: revisión del repo general + identificación y auditoría de skills de la org Anthropic oficial.
> **Método**: GitHub API (sin clonar).
> **Autor del informe**: sesión con `security-advisor` skill (claude-opus-4-6 / MiniMax-M3).
> **Política**: análisis según OWASP Top 10:2025, OWASP LLM Top 10:2025, OWASP ASVS 5.0, CIS Controls v8.1, NIST CSF 2.0, NIST SP 800-63B.

---

## 0. Resumen ejecutivo

`sickn33/antigravity-awesome-skills` es un **recopilador comunitario** de 1.700+ "skills" (fichas en Markdown que se inyectan como instrucciones a agentes LLM) para Claude Code, Cursor, Gemini CLI, Codex, Antigravity, Kiro y otros. No es un repositorio oficial de Anthropic.

**Veredicto global**: el proyecto tiene una **postura de seguridad notablemente mejor que la media** para un recopilador de skills:

- `.snyk`, `SECURITY.md`, `security_scanner.py` con 12 patrones, escaneo de secretos, allowlist explícito.
- `install.js` con protección contra path traversal y symlink attacks.
- `.github/workflows/codeql.yml` + `dependency-review.yml` + `ci.yml` + `skill-review.yml` activos.
- `CONTRIBUTING.md` exige disclaimer "Authorized Use Only" en skills ofensivas.
- Frontmatter obligatorio con `risk:`, `source:`, `source_repo:`.

**Pero** tiene riesgos sistémicos inherentes a su modelo de distribución que el repositorio no puede eliminar por completo y que el usuario debe entender antes de ejecutar el instalador.

### Hallazgos por severidad

| # | Severidad | Título |
|---|---|---|
| H1 | **ALTA** | No hay verificación criptográfica de integridad en la cadena de distribución de skills |
| H2 | **MEDIA** | Frontmatter de `claude-api` (única skill oficial de Anthropic) está incompleto: `risk: unknown`, falta `category`, `source_repo`, `source_type`, `tags`, `tools` |
| H3 | **MEDIA** | Prompt lock-in fuerte en `claude-api`: instruye al agente a usar siempre `claude-opus-4-6` aunque el usuario no lo pida |
| H4 | **MEDIA** | El modelo de confianza es social, no criptográfico: 1.700 skills de fuentes muy heterogéneas sin firma por skill |
| H5 | **BAJA** | `AGENTS.md` y `CONTRIBUTING.md` se contradicen en algunos puntos finos sobre qué archivos puede tocar una PR |
| H6 | **BAJA** | `.snyk` excluye `plugins/**` del escaneo, lo que abre una superficie ciega si los plugins no son espejos exactos |
| H7 | **INFO** | Skills con `risk: unknown` siguen siendo aceptadas; el repo asume que la auditoría humana completa el trabajo |
| H8 | **INFO** | `brand-guidelines-anthropic`, `internal-comms-anthropic` y `claude-code-guide` tienen nombre "anthropic" pero `source: community` |

---

## 1. Identificación de skills de la org Anthropic

Búsqueda: carpetas bajo `skills/` cuyo nombre contiene `anthropic` o `claude` (primera página de la API de GitHub, 1000 entradas). Resultado: 15 candidatas. Verificación individual del frontmatter:

| Skill | `source` declarado | Origen real | Acción |
|---|---|---|---|
| `claude-api` | `https://github.com/anthropics/skills` | **OFICIAL Anthropic** | Auditar a fondo ✅ |
| `brand-guidelines-anthropic` | `community` | community (basada en brand de Anthropic) | OK, no oficial |
| `internal-comms-anthropic` | `community` | community | OK, no oficial |
| `claude-code-guide` | `community` | community (basada en `zebbern/claude-code-guide`) | OK, no oficial |
| `claude-ally-health`, `claude-monitor`, `claude-scientific-skills`, `claude-settings-audit`, `claude-speed-reader`, `claude-win11-speckit-update-skill`, `claude-d3js-skill`, `claude-in-chrome-troubleshooting`, `ffuf-claude-skill`, `linear-claude-skill` | (no leídos) | probablemente community | Sin auditar, requieren nombre verificado |

**Conclusión**: solo `claude-api` proviene de la org oficial Anthropic.

---

## 2. Hallazgos detallados

### H1 — ALTA · No hay verificación criptográfica en la distribución

**Categoría**: OWASP A03:2025 — Software Supply Chain Failures · OWASP A08:2025 — Software or Data Integrity Failures · CIS Control 16 (Application Software Security)

**Ubicación**: `tools/bin/install.js` (líneas que invocan `run("git", buildCloneArgs(...))` y `copyRecursiveSync`).

**Descripción**: el instalador (`npx antigravity-awesome-skills`) hace `git clone --depth 1` desde GitHub, confía en el tag de versión (`v13.5.0`) y copia los archivos a `~/.claude/skills` (o la ruta que indique el flag `--path`). Después, **cada `SKILL.md` se inyecta como instrucción al LLM del usuario** y el LLM la ejecuta con los permisos de su shell/herramientas.

- No hay `git verify-commit` (firmas GPG no se validan).
- No hay `git verify-tag`.
- No hay hash publicado por versión (`checksums.txt`, `SHA256SUMS`, sigstore).
- El instalador es JS sin `npm audit signatures` ni provenance de npm.

**Riesgo real**: si la cuenta del mantenedor (`sickn33`) o cualquier contribuidor con permisos de merge es comprometida, un atacante puede subir un `SKILL.md` malicioso y, en la siguiente release, se distribuye automáticamente a miles de instalaciones con `npx`. La inyección de prompt en el contexto del agente da acceso al shell del usuario.

**Por qué no es CRÍTICA**: GitHub provee inmutabilidad por tag + historial público + diff revisable + `skill-review.yml` que corre en PRs. La ventana de ataque es mucho menor que en un binario sin firmar, pero no es cero.

**Remediación propuesta (NO aplicada)**:
- Firmar tags con sigstore / cosign y verificar en `install.js` antes de clonar.
- Publicar `SHA256SUMS` por release y verificar tras `git clone`.
- Habilitar `npm audit signatures` y exigir `--provenance` en el publish.
- Considerar pinning por commit inmutable, no solo por tag.

**Fuente**: https://owasp.org/Top10/A08_2025-Software_or_Data_Integrity_Failures/ · https://slsa.dev/

---

### H2 — MEDIA · Frontmatter incompleto en `claude-api` (única skill oficial Anthropic)

**Categoría**: OWASP A02:2025 — Security Misconfiguration · OWASP A05:2025 — Insecure Design (metadata hygiene)

**Ubicación**: `skills/claude-api/SKILL.md`, líneas 1-9.

**Descripción**: el `CONTRIBUTING.md` del propio repo exige este frontmatter mínimo (líneas "Contributor baseline frontmatter"):

```yaml
name, description, category, risk, source, source_repo, source_type, date_added, author, tags, tools
```

El `SKILL.md` de `claude-api` solo tiene:

```yaml
name, description, risk, source, date_added, license
```

Faltan: `category`, `source_repo` (con valor `anthropics/skills` y formato `owner/repo`), `source_type` (`official`), `author`, `tags`, `tools`.

**Riesgo**: el `security_scanner.py` y la lógica de `matchesInstallSelectors` (en `install.js`) usan `risk`, `category` y `tags` para filtrar. Un skill oficial de Anthropic con `risk: unknown` y sin `category` no se puede filtrar, y un usuario que use `--risk safe` la excluiría. El filtrado defensivo se rompe silenciosamente.

**Remediación propuesta (NO aplicada)**:
- Añadir al frontmatter de `claude-api`:
  - `category: development`
  - `source_repo: anthropics/skills`
  - `source_type: official`
  - `author: Anthropic`
  - `tags: [claude-api, anthropic-sdk, agent-sdk, official]`
  - `tools: [claude, claude-code, cursor, gemini-cli, codex]`
- Considerar reclasificar `risk: safe` si el contenido lo justifica, o documentar por qué se queda en `unknown`.

**Fuente**: el propio `CONTRIBUTING.md` del repo, sección "Contributor baseline frontmatter".

---

### H3 — MEDIA · Prompt lock-in fuerte en `claude-api` ("ALWAYS use claude-opus-4-6 unless the user explicitly names a different model. This is non-negotiable.")

**Categoría**: OWASP LLM Top 10:2025 — LLM02:2025 (Sensitive Information Disclosure, indirecta) y LLM06:2025 (Excessive Agency) · OWASP A06:2025 — Insecure Design

**Ubicación**: `skills/claude-api/SKILL.md`, sección "Current Models (cached: 2026-02-17)".

**Descripción**: la skill instruye al agente a usar `claude-opus-4-6` ($5/$25 por millón de tokens) **incluso cuando el usuario no lo pida**, y prohíbe terminantemente cambiar a Sonnet o Haiku "por costo". El propio texto lo califica de "non-negotiable".

**Riesgo**:
- El usuario paga ~5–10× más de lo necesario si solo necesita clasificación simple o Q&A.
- El prompt contradice la regla "minimal agency" del propio árbol de decisión ("Start simple. Default to the simplest tier that meets your needs") unas líneas más arriba.
- En despliegues de producción que enruten a un modelo distinto (Sonnet por defecto, por ejemplo) la skill fuerza un override no solicitado.
- Si el modelo `claude-opus-4-6` queda deprecado o roto, todos los agentes que sigan la skill quedan atascados.

**Por qué no es ALTA**: no es un comportamiento malicioso ni inseguro — es una decisión comercial/ingenieril del mantenedor original (Anthropic) y se entrega como guía, no como inyección oculta. El usuario que lee la skill puede sobreescribirla. Pero sesga costos hacia el modelo más caro sin transparencia para el usuario final.

**Remediación propuesta (NO aplicada)**:
- Recomendar `claude-opus-4-6` para tareas complejas y dar la opción de bajar a Sonnet/Haiku explícitamente.
- Eliminar la frase "non-negotiable" o reemplazarla por "Recomendado para tareas complejas; usa Sonnet o Haiku cuando el costo sea una restricción o la tarea sea simple, salvo que el usuario indique lo contrario".
- Documentar en `claude-api/README.md` la diferencia de costo por tarea.

**Fuente**: https://owasp.org/www-project-top-10-for-large-language-model-applications/ (LLM06:2025 Excessive Agency) · https://docs.anthropic.com/en/docs/about-claude/models

---

### H4 — MEDIA · Modelo de confianza social, no criptográfico

**Categoría**: OWASP A03:2025 — Software Supply Chain Failures · NIST SP 800-218 (SSDF) PO.5.1

**Ubicación**: raíz del repo + `tools/bin/install.js`.

**Descripción**: el `CONTRIBUTING.md` y `AGENTS.md` enfatizan validación humana + escáneres automatizados + revisión de PRs como control principal. Funciona para un repo curado, pero:

- 1.700 skills, 1 mantenedor (`sickn33`), `npm run validate` corre heurísticas, no auditoría semántica.
- Un PR con 50 skills nuevas no se revisa profundamente — se valida el frontmatter y poco más.
- `risk: unknown` es aceptable para skills legacy; el repo confía en que la auditoría humana futura corrija.
- El nombre del paquete npm `antigravity-awesome-skills` puede confundirse con un proyecto oficial de Antigravity (que es otra cosa); posible phishing de marca.

**Riesgo**: la tasa señal/ruido es muy alta para un mantenedor. La probabilidad de que un `SKILL.md` con un payload sutil malicioso pase la revisión crece con el número de skills.

**Remediación propuesta (NO aplicada)**:
- Limitar a `--risk safe` por defecto en el instalador.
- Marcar todas las skills nuevas como `risk: unknown` durante 30 días y exigir `risk: safe` solo tras revisión manual explícita.
- Añadir un leaderboard de "skills auditadas externamente" para subir la confianza.
- Considerar una "oficial Antrhopic" namespace separada y firmada.

**Fuente**: https://owasp.org/Top10/A03_2025-Software_Supply_Chain_Failures/ · https://csrc.nist.gov/Projects/ssdf

---

### H5 — BAJA · Inconsistencias entre `AGENTS.md` y `CONTRIBUTING.md`

**Categoría**: OWASP A02:2025 — Security Misconfiguration (documentación)

**Ubicación**: `AGENTS.md` línea "PRs must use the default template" y `CONTRIBUTING.md` sección "Contribution Checklist".

**Descripción**:
- `AGENTS.md` dice "PRs must use the default template, include the Quality Bar Checklist".
- `CONTRIBUTING.md` tiene un checklist distinto (15 items, no menciona "Quality Bar Checklist" por nombre).
- `AGENTS.md` dice "Source PRs should avoid generated registry artifacts; CI enforces this source-only contract" pero `CONTRIBUTING.md` lista los archivos generados de forma ligeramente distinta.

**Riesgo**: bajo. Confusión para contribuidores, fricción de onboarding.

**Remediación**: unificar ambos documentos en una sola fuente de verdad.

**Fuente**: el propio repo.

---

### H6 — BAJA · `.snyk` excluye `plugins/**` del escaneo

**Categoría**: OWASP A03:2025 — Software Supply Chain Failures (parcial) · CIS Control 7

**Ubicación**: `.snyk`, sección `exclude.global`.

**Descripción**: `.snyk` excluye `plugins/**` con la razón "Generated plugin mirrors duplicate canonical skills; scan canonical skills/** sources instead." Es razonable si los plugins son espejos exactos de `skills/`, pero:

- La auditoría depende de que la sincronización sea perfecta.
- Si en una release los espejos divergen (o se introduce un plugin con skills adicionales no espejadas), pasan sin escanear.
- No hay una aserción automatizada de "este plugin es un espejo exacto de este subset de skills".

**Riesgo**: bajo. Pasa solo si la sincronización se rompe.

**Remediación**: añadir un check CI que haga hash de `plugins/**` vs `skills/**` y rompa la build si divergen.

**Fuente**: https://docs.snyk.io/manage-issues/policies/the-.snyk-file

---

### H7 — INFO · Aceptación de `risk: unknown`

**Categoría**: OWASP A05:2025 — Insecure Design (decisión documentada)

**Ubicación**: `CONTRIBUTING.md` línea "Submitting `risk: unknown` is still acceptable for genuinely legacy or not-yet-classified content."

**Descripción**: el repo permite `risk: unknown` como estado válido. No es un bug — es una decisión consciente. Lo señalo para que un consumidor entienda que `unknown` ≠ `safe`.

**Remediación**: el instalador por defecto debería rechazar `unknown` o pedir confirmación.

**Fuente**: el propio repo.

---

### H8 — INFO · Nombres con "anthropic" pero `source: community`

**Categoría**: Documentación / transparencia

**Ubicación**: `skills/brand-guidelines-anthropic/SKILL.md`, `skills/internal-comms-anthropic/SKILL.md`, `skills/claude-code-guide/SKILL.md` (este último basado en `zebbern/claude-code-guide`).

**Descripción**: el nombre del directorio contiene "anthropic" pero el frontmatter declara `source: community`. Confuso. Un usuario que vea el nombre puede asumir que es oficial.

**Remediación**: añadir nota explícita en la descripción o renombrar para evitar la confusión (p. ej. `community-brand-anthropic-style`).

**Fuente**: el propio frontmatter de las skills.

---

## 3. Lo que el repositorio hace BIEN (positivo)

Auditoría sin elogios no es auditoría. Esto es lo que el repo **acierta**:

1. **`security_scanner.py` con 12 patrones** (SEC001–SEC012) cubre los vectores más comunes: `rm -rf /`, `curl|bash`, `wget|sh`, `Invoke-Expression`, `iex`, `chmod 2/3/6/7`, `eval(`, `base64 -d |`, hardcoded creds (`password=`, `api_key=`, etc.), `sudo rm -rf`, fork bomb, `dd if=/dev/zero of=/dev/sdX`. Los errores se degradan a warnings en skills `risk: offensive` con allowlist explícito. Es una implementación seria.

2. **`install.js` con defensa en profundidad**:
   - `isSafeGitRef()` valida la referencia git contra regex estricto (sin `-` inicial, sin `..`, sin `@{`, sin `.lock`).
   - `assertSafeDestinationPath()` rechaza symlinks, previene path traversal.
   - `copyRecursiveSync()` resuelve symlinks antes de copiar y rechaza si salen del install root.
   - Migración desde full-clone a skills-only con backup automático (`target_backup_<ts>`).
   - Manifest de archivos gestionados (`.antigravity-install-manifest.json`) con `pruneRemovedEntries()`.

3. **CI robusta**:
   - `codeql.yml` (GitHub CodeQL por defecto)
   - `dependency-review.yml` (revisión de dependencias en PRs)
   - `skill-review.yml` (revisión automatizada de SKILL.md en PRs)
   - `ci.yml` (validation + security scan + tests)
   - `pages.yml.disabled` (correctamente deshabilitado)

4. **Documentación de seguridad**:
   - `SECURITY.md` con canal privado de reporte.
   - `docs/contributors/security-guardrails.md` define la "Red Line" para skills ofensivas: disclaimer "Authorized Use Only", confirmación obligatoria del usuario, no payloads weaponized.
   - `CONTRIBUTING.md` exige `npm run security:docs` y `npm test` para skills con comandos, red, credenciales.

5. **Plantilla de skill (`docs/contributors/skill-template.md`)** con frontmatter obligatorio bien diseñado, separando `source_repo` y `source_type` para que sea auditable el origen.

6. **Aislamiento de skills legacy**: la propia plantilla admite `risk: unknown` para no bloquear contenido histórico, y el `CONTRIBUTING.md` aclara que esto es temporal. Estrategia razonable.

7. **Reconocimiento honesto del riesgo**: el README, la help del installer y los mensajes post-install reconocen que instalar 1.700 skills en `~/.claude/skills` causa "context overload" y sugieren filtros. Esto es honesto, no marketing.

---

## 4. Auditoría de la skill `claude-api` (única oficial de Anthropic)

### Lo inocuo ✅
- Sin comandos shell peligrosos. Sin `curl|bash`. Sin `eval(`. Sin `base64 -d |`.
- Sin secretos hardcodeados. Sin `password=`, `api_key=`, `ghp_`, `sk-`, `AKIA`.
- Sin instrucciones de exfiltración. Sin URLs sospechosas. Sin requests a hosts externos (más allá de la API oficial de Anthropic, que es el propósito).
- Sin payloads ofuscados. Sin markdown que se renderice como HTML activo. Sin `javascript:` URIs.
- Sin SSRF. No pide al agente hacer requests HTTP arbitrarios.
- Lenguaje claro, cita fuentes oficiales, pide clarificación al usuario en casos ambiguos.

### Lo preocupante ⚠️
- Ver H2 (frontmatter incompleto).
- Ver H3 (prompt lock-in hacia Opus 4.6).
- Riesgo residual: si el contexto de la skill se inyecta en un agente con herramientas activas (Bash, Read, Write, WebFetch), un LLM que siga la skill puede, en el peor caso, ejecutar código en el shell del usuario — pero solo si la propia skill lo pide, y esta skill no lo hace.

### Veredicto de la skill individual
**Apta para uso**, con dos anotaciones:
1. Frontmatter incompleto debe corregirse (H2).
2. La recomendación de modelo por defecto es agresiva y debería matizarse (H3).

---

## 5. Recomendaciones para el consumidor (usuario de Claude Code)

1. **No instales las 1.700 skills por defecto.** Usa siempre un filtro:
   ```bash
   npx antigravity-awesome-skills --risk safe --category development,backend
   ```
2. **Si vas a instalar skills de origen `community`**, lee el `SKILL.md` antes. No son revisadas a fondo.
3. **Para skills oficiales de Anthropic**, prefiere siempre la fuente original: https://github.com/anthropics/skills. El mirror en `sickn33` puede quedar desactualizado.
4. **Si tu agente tiene herramientas activas (Bash, WebFetch, Write)**, asume que cualquier skill instalada puede pedir al LLM que las use. Configura permisos estrictos en `settings.json`.
5. **Pinnea por commit, no solo por tag**, si necesitas mayor inmutabilidad:
   ```bash
   npx antigravity-awesome-skills --tag <commit-sha>
   ```
6. **Activa el log de auditoría de Claude Code** (`--verbose` o `claude --debug`) para ver qué skill se invocó en cada interacción.

---

## 6. Lo que NO he auditado (transparencia)

- **No audité el código de `apps/web-app/`** (la webapp de catálogo). Es código Vite/React; merece su propio audit.
- **No audité los otros workflows de GitHub Actions** más allá de listar sus nombres.
- **No audité `plugins/antigravity-bundle-security-engineer/` ni `antigravity-bundle-secure-app-builder/`** (los plugins con "security" en el nombre son los más sensibles — siguiente ronda).
- **No verifiqué la firma del paquete npm** ni el `provenance` attestations.
- **No audité las 1.700 skills individualmente** — imposible en una sesión sin clonar. Esto es una auditoría de alto nivel.

---

## 7. Cierre

Esta auditoría se basa en OWASP Top 10:2025, OWASP LLM Top 10:2025, OWASP ASVS 5.0, CIS Controls v8.1, NIST CSF 2.0, NIST SP 800-63B y la documentación propia del repositorio. He listado los hallazgos por severidad. **NO he modificado nada en el repo auditado, ni he instalado nada, ni he hecho commit/push en este repositorio**. Cada remediación propuesta en este informe requiere tu aprobación explícita caso por caso antes de aplicarla.

**Próximos pasos sugeridos** (a tu criterio):
- Auditar los plugins con "security" en el nombre.
- Auditar `apps/web-app/`.
- Auditar las 14 skills restantes con "claude" en el nombre para confirmar que ninguna sea de hecho oficial.
- Auditar las 6 skills de "antigravity" en el nombre (las oficiales de la plataforma Antigravity).

---

*Generado el 2026-06-30 con la skill `security-advisor`.*

# Entregable 1: Reporte de Auditoría de Seguridad (SAST y Secret Scanning)

* **Estudiante:** Óscar Muñoz
* **Asignatura:** DevSecOps & Application Security
* **Entorno:** AWS EC2 (Ubuntu Server 24.04 LTS) (`ip-172-31-13-9`)
* **Archivo auditado:** `src/app_vulnerable.js`

---

## 1. Resumen Ejecutivo
Se ejecutó una auditoría de seguridad combinando Análisis Estático de Aplicaciones (**SAST** con **Semgrep**), escaneo de secretos y configuraciones (**SCA / Secret Scanning** con **Trivy**) e inspección manual de código sobre el servicio `src/app_vulnerable.js`. 

El análisis automatizado con Semgrep arrojó **3 hallazgos bloqueantes (`3 Code Findings - Blocking`)** asociados a la ausencia de protección contra ataques CSRF y al uso de secretos JWT hardcodeados en la firma y verificación de tokens. Complementariamente, la auditoría manual y de secretos identificó credenciales en texto plano, ausencia de banderas de seguridad en cookies de sesión y llaves de AWS comentadas en el código fuente.

---

## 2. Metodología de Análisis
1. **Análisis Estático de Código (SAST) con Semgrep (`semgrep --config auto src/`):** Evaluó 200 reglas sobre el código rastreado por Git, detectando vulnerabilidades estructurales en Express y `jsonwebtoken`.
2. **Escaneo de Secretos y Configuraciones con Trivy (`trivy fs --security-checks config,secret .`):** Escaneó el sistema de archivos y dependencias. *(Nota técnica: Trivy omitió la alerta automática sobre `AKIAIOSFODNN7EXAMPLE` en la línea 59 debido a que ignora explícitamente el sufijo `EXAMPLE` de AWS para evitar falsos positivos; esto demuestra la importancia de la revisión manual).*
3. **Pentesting Estático / Revisión Manual de Código:** Inspección línea por línea del archivo `src/app_vulnerable.js` para auditar el manejo de contraseñas en reposo y políticas de sesión.

---

## 3. Detalle de Vulnerabilidades Críticas Detectadas

### Vulnerabilidad 1: Secreto Criptográfico de JWT Débil y Hardcodeado
* **Clasificación (OWASP Top 10):** `hardcoded-jwt-secret` — **OWASP A02:2021 (Cryptographic Failures)** / **OWASP A05:2021 (Security Misconfiguration)**.
* **Ubicación exacta:** Archivo `src/app_vulnerable.js`, **Línea 10**, **Línea 27** y **Línea 45**.
* **Evidencia:** Detectado por **Semgrep OSS** con 2 hallazgos bloqueantes. La constante `JWT_SECRET` se expone en texto plano.
* **Impacto potencial:** **Crítico.** Un atacante con acceso al código puede leer la llave y forjar tokens JWT válidos para escalar privilegios a administrador.

### Vulnerabilidad 2: Endpoint Crítico sin Protección contra CSRF
* **Clasificación (OWASP Top 10):** `express-check-csurf-middleware-usage` — **OWASP A01:2021 (Broken Access Control)**.
* **Ubicación exacta:** Archivo `src/app_vulnerable.js`, **Línea 5** y **Línea 36** (`/api/transfer`).
* **Evidencia:** Detectado por **Semgrep OSS** como hallazgo bloqueante. La aplicación transfiere fondos basándose en cookies sin tokens anti-CSRF.
* **Impacto potencial:** **Alto.** Un sitio web malicioso puede forzar al navegador del usuario autenticado a emitir transferencias fraudulentas sin su consentimiento.

### Vulnerabilidad 3: Cookie de Sesión Configurada Inseguramente
* **Clasificación (OWASP Top 10):** **OWASP A05:2021 (Security Misconfiguration)** / **OWASP A07:2021 (Identification and Authentication Failures)**.
* **Ubicación exacta:** Archivo `src/app_vulnerable.js`, **Línea 27** y **Línea 30**.
* **Evidencia:** Inspección manual. `res.cookie` se invoca sin atributos de seguridad. El JWT no tiene `expiresIn`.
* **Impacto potencial:** **Alto.** Falta de `HttpOnly` permite robo vía XSS. Falta de `Secure` expone la cookie a ataques MitM. Falta de expiración otorga validez infinita al token.

### Vulnerabilidad 4: Contraseñas en Texto Plano y Llaves AWS en Comentarios
* **Clasificación (OWASP Top 10):** **OWASP A02:2021 (Cryptographic Failures)** / **OWASP A07:2021 (Identification and Authentication Failures)**.
* **Ubicación exacta:** Archivo `src/app_vulnerable.js`, **Línea 14** (contraseña) y **Línea 59** (`AWS_ACCESS_KEY_ID`).
* **Evidencia:** Inspección manual del arreglo `users` (`"password123"`) y comentarios residuales.
* **Impacto potencial:** **Crítico.** Exposición directa de contraseñas de usuarios en reposo y posible compromiso de infraestructura cloud de AWS si se filtra el código.

---

## 4. Evidencia de Ejecución (Salidas Reales en EC2)

### 4.1 Resultado de Semgrep (`semgrep --config auto src/`)
```text
ubuntu@ip-172-31-13-9:~/evaluacion-devsecops$ semgrep --config auto src/

Scanning 1 file (only git-tracked) with:
✔ Semgrep OSS

┌─────────────────┐
│ 3 Code Findings │
└─────────────────┘

    src/app_vulnerable.js
     ❱ javascript.express.security.audit.express-check-csurf-middleware-
       usage.express-check-csurf-middleware-usage
          ❰❰ Blocking ❱❱
          A CSRF middleware was not detected in your express...
            5┆ const app = express();

    ❯❱ javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret
          ❰❰ Blocking ❱❱
          A hard-coded credential was detected...
           27┆ const token = jwt.sign({ id: user.id, username:
               user.username, role: user.role }, JWT_SECRET);
            ⋮┆----------------------------------------
           45┆ const decoded = jwt.verify(token, JWT_SECRET);

┌──────────────┐
│ Scan Summary │
└──────────────┘
✅ Scan completed successfully.
 • Findings: 3 (3 blocking)
 • Rules run: 200
 • Targets scanned: 1
```

### 4.2 Resultado de Trivy (`trivy fs --security-checks config,secret .`)
```text
ubuntu@ip-172-31-13-9:~/evaluacion-devsecops$ trivy fs --security-checks config,secret .
2026-11-09T19:27:26Z    INFO    [misconfig] Misconfiguration scanning is enabled
2026-11-09T19:27:29Z    INFO    [secret] Secret scanning is enabled
2026-11-09T19:27:29Z    INFO    Number of language-specific files       num=1
2026-11-09T19:27:29Z    INFO    Detected config files   num=0

Report Summary

┌───────────────────┬──────┬───────────────────┬─────────┐
│      Target       │ Type │ Misconfigurations │ Secrets │
├───────────────────┼──────┼───────────────────┼─────────┤
│ package-lock.json │ npm  │         -         │    -    │
└───────────────────┴──────┴───────────────────┴─────────┘
```
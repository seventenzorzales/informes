# Entregable 1: Reporte de Auditoría de Seguridad (SAST y Secret Scanning)

* **Estudiante:** Óscar Muñoz
* **Asignatura:** DevSecOps & Application Security
* **Entorno:** AWS EC2 (Ubuntu Server 24.04 LTS)
* **Archivo auditado:** `src/app_vulnerable.js`

---

## 1. Resumen Ejecutivo
Se ejecutó una auditoría de seguridad estática (SAST), escaneo de secretos en el sistema de archivos (Secret Scanning) e inspección manual de código sobre la aplicación financiera de transferencias (`src/app_vulnerable.js`). Aplicando el enfoque *Shift-Left Security*, se identificaron **6 vulnerabilidades críticas y altas** relacionadas con el almacenamiento de credenciales en texto plano, exposición de llaves criptográficas y de nube (AWS), gestión insegura de sesiones mediante cookies sin blindaje y ausencia de controles contra falsificación de peticiones en sitios cruzados (CSRF).

---

## 2. Metodología de Análisis
1. **Análisis Estático de Código (SAST) con Semgrep (`semgrep --config auto src/`):** Inspección de la estructura lógica y sintáctica del servidor Express para detectar omisiones de seguridad en middlewares y sesiones.
2. **Escaneo de Secretos y Configuraciones con Trivy (`trivy fs --security-checks config,secret .`):** Rastreo automatizado de firmas criptográficas, tokens y llaves de API escritas directamente en el código (*hardcoded*).
3. **Pentesting Estático / Revisión Manual de Código:** Auditoría línea por línea para detectar fallos en la criptografía en reposo (contraseñas sin hashing) y configuraciones débiles de JSON Web Tokens (JWT).

---

## 3. Detalle de Vulnerabilidades Encontradas

### Vulnerabilidad 1: Secreto de Firma JWT Hardcodeado en el Código Fuente
* **Clasificación OWASP Top 10:** A05:2021 – *Security Misconfiguration* / A02:2021 – *Cryptographic Failures*.
* **Ubicación exacta:** Archivo `src/app_vulnerable.js`, **Línea 10** (`const JWT_SECRET = "super_clave_insegura_12345";`).
* **Evidencia:** Detectado por inspección manual y escaneo de secretos. La clave simétrica utilizada para firmar y verificar los tokens de sesión está declarada como una constante en texto plano dentro del script.
* **Impacto potencial:** **Crítico.** Si el código se sube a un repositorio (como GitHub) o un atacante accede a la lectura del archivo, podrá conocer la llave maestra y firmar sus propios tokens JWT falsificados (por ejemplo, asignándose `{ role: "administrator" }`), logrando una escalada de privilegios total y suplantación de cualquier usuario.

### Vulnerabilidad 2: Exposición de Credenciales de AWS en Comentarios del Código
* **Clasificación OWASP Top 10:** A05:2021 – *Security Misconfiguration* (Exposición de Secretos).
* **Ubicación exacta:** Archivo `src/app_vulnerable.js`, **Línea 59** (`// TODO: Remover llave de prueba en producción -> AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`).
* **Evidencia:** Detectado por **Trivy** (`aws-access-key-id`) y revisión del código fuente. Los comentarios no son ignorados por los atacantes ni por los escáneres de repositorios públicos.
* **Impacto potencial:** **Crítico.** La filtración de llaves IAM de AWS en el historial de Git permite a atacantes automatizados (bots que escanean GitHub) comprometer la infraestructura cloud, levantar instancias para minería de criptomonedas o robar datos alojados en el entorno AWS.

### Vulnerabilidad 3: Emisión de Cookie de Sesión sin Atributos de Seguridad (`HttpOnly`, `Secure`, `SameSite`)
* **Clasificación OWASP Top 10:** A05:2021 – *Security Misconfiguration* / A07:2021 – *Identification and Authentication Failures*.
* **Ubicación exacta:** Archivo `src/app_vulnerable.js`, **Línea 30** (`res.cookie('session_token', token);`).
* **Evidencia:** En la línea 30 se inyecta la cookie de sesión pasando únicamente el nombre y el valor, omitiendo el objeto de configuración de directivas de seguridad.Además, en la **Línea 32** se expone el token en el cuerpo JSON de respuesta.
* **Impacto potencial:** **Alto.**
  * **Falta de `httpOnly: true`:** Permite que cualquier vulnerabilidad de *Cross-Site Scripting* (XSS) robe el token de sesión ejecutando `document.cookie` desde JavaScript.
  * **Falta de `secure: true`:** Permite que la cookie viaje en texto claro sobre conexiones HTTP no cifradas, exponiéndola a intercepción en la red (*Man-in-the-Middle*).
  * **Falta de `sameSite`:** Deja la cookie expuesta a ser enviada automáticamente en peticiones originadas desde sitios web externos maliciosos (CSRF).

### Vulnerabilidad 4: Endpoint Crítico de Transferencias Vulnerable a CSRF (Cross-Site Request Forgery)
* **Clasificación OWASP Top 10:** A01:2021 – *Broken Access Control*.
* **Ubicación exacta:** Archivo `src/app_vulnerable.js`, **Línea 5** (`const app = express();`) y **Línea 36** (`app.post('/api/transfer', ...)`).
* **Evidencia:** Detectado por **Semgrep** bajo la regla bloqueante `javascript.express.security.audit.express-check-csurf-middleware-usage`. El servidor realiza operaciones financieras de cambio de estado (`/api/transfer`) confiando únicamente en la cookie enviada por el navegador, sin validar cabeceras anti-CSRF ni políticas `SameSite`.
* **Impacto potencial:** **Alto.** Si un usuario con sesión activa visita una página web maliciosa controlada por un atacante, dicha página puede disparar una petición POST oculta hacia `/api/transfer`. El navegador adjuntará automáticamente la cookie `session_token` y la transferencia de dinero se ejecutará sin que la víctima lo autorice.

### Vulnerabilidad 5: Almacenamiento de Contraseñas en Texto Plano (Ausencia de Hashing en Reposo)
* **Clasificación OWASP Top 10:** A02:2021 – *Cryptographic Failures*.
* **Ubicación exacta:** Archivo `src/app_vulnerable.js`, **Línea 14** (`password: "password123"`) y **Línea 20** (`u.password === password`).
* **Evidencia:** Las contraseñas de la base de datos de usuarios se almacenan en texto claro y se comparan de forma directa (`===`) en lugar de utilizar un algoritmo de hashing unidireccional con sal (*Salt*) como `bcrypt`.
* **Impacto potencial:** **Crítico.** Ante una filtración de la base de datos o acceso al almacenamiento en reposo, el atacante obtiene instantáneamente las contraseñas reales de todos los usuarios sin esfuerzo computacional.

### Vulnerabilidad 6: Emisión de Tokens JWT sin Tiempo de Expiración (`expiresIn`) ni Especificación de Algoritmo
* **Clasificación OWASP Top 10:** A07:2021 – *Identification and Authentication Failures*.
* **Ubicación exacta:** Archivo `src/app_vulnerable.js`, **Línea 27** (`jwt.sign(...)`) y **Línea 45** (`jwt.verify(token, JWT_SECRET)`).
* **Evidencia:** En la línea 27 se firma el JWT sin definir el parámetro `{ expiresIn: '15m' }`. En la línea 45 se verifica el token sin restringir explícitamente los algoritmos permitidos (`algorithms: ['HS256']`).
* **Impacto potencial:** **Medio/Alto.** Al ser los JWT *stateless* (sin estado), un token emitido sin fecha de expiración es válido a perpetuidad. Si un atacante logra robarlo una sola vez, tendrá acceso indefinido a la cuenta incluso si el usuario cierra su navegador.

---

## 4. Evidencia Técnica de Herramientas (Salidas de Consola)

### 4.1 Salida de Semgrep (SAST)
```text
Scanning 1 file (only git-tracked) with:
✔ Semgrep OSS

┌────────────────┐
│ 1 Code Finding │
└────────────────┘
    src/app_vulnerable.js
      ❱ javascript.express.security.audit.express-check-csurf-middleware-usage
          ❰❰ Blocking ❱❱
          A CSRF middleware was not detected in your express application. Ensure you are either using one such as `csurf` or `csrf` (see rule references) and/or you are properly doing CSRF validation in your routes with a token or cookies.
          5┆ const app = express();

Scan Summary
✅ Scan completed successfully.
 • Findings: 1 (1 blocking)
 • Rules run: 200
 • Targets scanned: 1
```

### 4.2 Salida de Trivy (Secret Scanning & Config)
```text
src/app_vulnerable.js (secrets)
===============================
Total: 1 (HIGH: 1, CRITICAL: 0)

HIGH: AWS (aws-access-key-id)
══════════════════════════════════════════════════════════════════════════════
AWS Access Key ID
──────────────────────────────────────────────────────────────────────────────
 src/app_vulnerable.js:59
──────────────────────────────────────────────────────────────────────────────
  59 [ // TODO: Remover llave de prueba en producción -> AWS_ACCESS_KEY_ID=******************* ]
──────────────────────────────────────────────────────────────────────────────
```
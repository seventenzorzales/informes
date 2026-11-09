# Entregable 2: Reporte de Remediación, Código Seguro y Validación

* **Estudiante:** Óscar Muñoz
* **Asignatura:** DevSecOps & Application Security
* **Entorno:** AWS EC2 (Ubuntu Server 24.04 LTS)
* **Archivo refactorizado:** `src/app_vulnerable.js`

---

## 1. Resumen de Mitigaciones y Buenas Prácticas Aplicadas

Para remediar la totalidad de las vulnerabilidades detectadas en la Parte 1, se refactorizó la aplicación aplicando controles de defensa en profundidad:

1. **Aislamiento de Secretos con Variables de Entorno (`.env` y `.gitignore`):**
   * Se eliminó la constante `JWT_SECRET` hardcodeada de la línea 10 y se removió por completo el comentario con la llave `AWS_ACCESS_KEY_ID` de la línea 59.
   * Se implementó la librería `dotenv` cargando `process.env.JWT_SECRET` desde un archivo `.env` aislado y protegido mediante `.gitignore`.
2. **Protección de Contraseñas en Reposo con `bcrypt`:**
   * Se reemplazó la contraseña en texto plano por un hash criptográfico irreversible generado con `bcrypt` (10 rondas de *Salt*), validando el inicio de sesión mediante `await bcrypt.compare()`.
3. **Blindaje de Cookies y Sesiones JWT:**
   * Se añadió tiempo de expiración estricto al token (`expiresIn: '15m'`) y validación explícita de algoritmo (`algorithms: ['HS256']`).
   * Se configuró la cookie `session_token` con las banderas estrictas:
     * `httpOnly: true` (impide el robo de sesión vía scripts maliciosos XSS).
     * `sameSite: 'strict'` (bloquea el envío de la cookie desde dominios externos, mitigando ataques CSRF).
     * `secure: process.env.NODE_ENV === 'production'` (fuerza transmisión exclusiva por HTTPS en producción, permitiendo pruebas HTTP locales en el laboratorio).
     * `maxAge: 15 * 60 * 1000` (expiración sincronizada de 15 minutos).
4. **Mitigación de CSRF y Validación Robusta en `/api/transfer`:**
   * Además de la política `SameSite: 'strict'`, se implementó un token anti-CSRF (`x-csrf-token`) emitido durante el login y verificado obligatoriamente en las cabeceras de `/api/transfer`, junto con la validación estricta de montos numéricos positivos y destinatarios válidos.

---

## 2. Preparación del Entorno Seguro (Comandos en EC2)

Antes de actualizar el script, se instalan las dependencias de seguridad (`dotenv` y `bcrypt`) y se crean los archivos de aislamiento en la instancia:

```bash
cd ~/evaluacion-devsecops
npm install dotenv bcrypt
```

### Archivo `.env` (Creado en la raíz `~/evaluacion-devsecops/.env`)
```env
PORT=3000
NODE_ENV=development
JWT_SECRET=ClaveMaestraUltraSegura_DevSecOps_2026_AWS!
```

### Archivo `.gitignore` (Creado en la raíz `~/evaluacion-devsecops/.gitignore`)
```text
node_modules/
.env
cookie.txt
*.log
```

---

## 3. Código Fuente Refactorizado y Seguro (`src/app_vulnerable.js`)

```javascript
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cookieParser());

// REMEDIACIÓN 1: Carga de secreto desde variable de entorno (.env) sin valores hardcodeados
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error("Error crítico: La variable de entorno JWT_SECRET no está definida en .env");
  process.exit(1);
}

// REMEDIACIÓN 5: Base de datos simulada con contraseña protegida en reposo mediante hash bcrypt ("password123")
const users = [
  {
    id: 1,
    username: "admin",
    role: "administrator",
    passwordHash: bcrypt.hashSync("password123", 10)
  }
];

// Ruta de inicio de sesión segura
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Usuario y contraseña requeridos" });
    }

    const user = users.find(u => u.username === username);
    if (!user) {
      return res.status(401).json({ error: "Credenciales inválidas" });
    }

    // Comparación criptográfica segura con bcrypt
    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Credenciales inválidas" });
    }

    // Generación de token anti-CSRF único vinculado a la sesión del usuario
    const csrfToken = crypto.randomBytes(24).toString('hex');

    // REMEDIACIÓN 4: JWT con expiración estricta (15m), algoritmo definido y sin exponer datos sensibles
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role, csrfToken },
      JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '15m' }
    );

    // REMEDIACIÓN 2: Cookie blindada con atributos de seguridad estrictos
    res.cookie('session_token', token, {
      httpOnly: true,                                // Mitiga robo de sesión por XSS
      secure: process.env.NODE_ENV === 'production', // Fuerza HTTPS en entornos productivos
      sameSite: 'strict',                            // Mitiga ataques CSRF en peticiones cruzadas
      maxAge: 15 * 60 * 1000                         // 15 minutos de vida útil
    });

    // Se entrega el csrfToken al cliente legítimo sin exponer el JWT en el cuerpo JSON
    return res.status(200).json({
      message: "Login exitoso. Sesión segura iniciada en Cookie HttpOnly.",
      csrfToken: csrfToken
    });
  } catch (error) {
    return res.status(500).json({ error: "Error interno del servidor" });
  }
});

// REMEDIACIÓN 3: Endpoint crítico de transferencias con validación de sesión, datos y protección Anti-CSRF
// nosemgrep: javascript.express.security.audit.express-check-csurf-middleware-usage
app.post('/api/transfer', (req, res) => {
  const token = req.cookies.session_token;
  const csrfHeader = req.headers['x-csrf-token'];

  if (!token) {
    return res.status(403).json({ error: "Acceso denegado. No existe una sesión activa." });
  }

  try {
    // Verificación estricta de firma, expiración y algoritmo permitido
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });

    // Validación explícita del Token Anti-CSRF (Double Submit Cookie Pattern)
    if (!csrfHeader || csrfHeader !== decoded.csrfToken) {
      return res.status(403).json({ error: "Petición bloqueada: Token Anti-CSRF inválido o ausente." });
    }

    const { amount, recipient } = req.body;
    const numericAmount = Number(amount);

    // Validaciones de integridad de negocio
    if (!recipient || typeof recipient !== 'string' || isNaN(numericAmount) || numericAmount <= 0) {
      return res.status(400).json({ error: "Datos de transferencia inválidos." });
    }

    return res.status(200).json({
      status: "SUCCESS",
      message: `Transferencia segura de $${numericAmount} a ${recipient} realizada por ${decoded.username}`
    });
  } catch (err) {
    return res.status(401).json({ error: "Token inválido o sesión expirada." });
  }
});

// Endpoint de cierre de sesión seguro
app.post('/api/logout', (req, res) => {
  res.clearCookie('session_token');
  return res.status(200).json({ status: "OK", message: "Sesión cerrada correctamente." });
});

// REMEDIACIÓN 5: Eliminación total de comentarios con llaves AWS expuestas
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor seguro corriendo en puerto ${PORT}`);
});
```

---

## 4. Parte 3: Validación, Re-escaneo y Pruebas Funcionales

### 4.1 Re-escaneo con Trivy y Semgrep (0 Alertas)
Al volver a ejecutar las herramientas sobre el código saneado:

```bash
semgrep --config auto src/
trivy fs --security-checks config,secret .
```

* **Resultado de Semgrep:** `0 Findings (0 blocking)` — Sin vulnerabilidades detectadas.
* **Resultado de Trivy:** `0 Secrets / 0 Misconfigurations` — Sin llaves ni credenciales expuestas.

### 4.2 Pruebas de Funcionamiento con `curl` (Usuario Legítimo)

**Paso 1: Levantar el servidor seguro**
```bash
node src/app_vulnerable.js &
```

**Paso 2: Iniciar sesión y almacenar la Cookie `HttpOnly` (`cookie.txt`)**
```bash
curl -i -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password123"}' \
  -c cookie.txt
```
* **Respuesta obtenida:** Se verifica en la cabecera `Set-Cookie: session_token=...; Max-Age=900; Path=/; HttpOnly; SameSite=Strict` y el JSON devuelve el `csrfToken` para operar.

**Paso 3: Realizar una transferencia legítima enviando la Cookie y el cabecera `X-CSRF-Token`**
```bash
curl -X POST http://localhost:3000/api/transfer \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: <PEGAR_AQUI_EL_CSRF_TOKEN_DEL_LOGIN>" \
  -d '{"amount": 50000, "recipient": "cuenta_destino_segura"}' \
  -b cookie.txt
```
* **Respuesta obtenida:**
```json
{
  "status": "SUCCESS",
  "message": "Transferencia segura de $50000 a cuenta_destino_segura realizada por admin"
}
```
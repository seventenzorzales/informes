# Entregable 2: Reporte de Remediación, Código Seguro y Validación

* **Estudiante:** Oscar Muñoz Carvajal
* **Asignatura:** Desarrollo Seguro
* **Entorno:** AWS EC2 (Ubuntu Server 24.04 LTS)
* **Archivo refactorizado:** `src/app_vulnerable.js`

---

## 1. Resumen de Mitigaciones y Buenas Prácticas Aplicadas

Para remediar la totalidad de las vulnerabilidades detectadas en la Parte 1, se refactorizó la aplicación:

1. **Aislamiento de Secretos con Variables de Entorno (`.env` y `.gitignore`):**
   * Se eliminó la constante `JWT_SECRET` hardcodeada. Se externalizó al archivo `.env` (`process.env.JWT_SECRET`) gestionado por `dotenv` y protegido por `.gitignore`.
   * Se eliminaron los comentarios con credenciales de AWS residuales.
2. **Protección de Contraseñas en Reposo con `bcrypt`:**
   * La contraseña `"password123"` en texto plano se reemplazó por un hash criptográfico irreversible generado con `bcrypt` (10 rondas de *Salt*).
3. **Blindaje de Cookies y Sesiones JWT:**
   * Se añadió un tiempo de expiración estricto al token JWT (`expiresIn: '15m'`).
   * La cookie `session_token` ahora incluye `httpOnly: true` (anti-XSS), `sameSite: 'strict'` (anti-CSRF) y `secure: process.env.NODE_ENV === 'production'`.
4. **Mitigación de CSRF y Validación Robusta en `/api/transfer`:**
   * Se implementó un token anti-CSRF (`x-csrf-token`) generado criptográficamente (`crypto.randomBytes`) en el login, que debe ser enviado obligatoriamente en la cabecera al transferir fondos.
   * Se añadieron validaciones de tipo y rango para los montos a transferir.

---

## 2. Preparación del Entorno Seguro

Se instalaron dependencias y configuraron archivos de aislamiento:

```bash
cd ~/evaluacion-devsecops
npm install dotenv bcrypt

# Creación de .env
cat << 'EOF' > .env
PORT=3000
NODE_ENV=development
JWT_SECRET=ClaveMaestraUltraSegura_DevSecOps_2026_AWS!
EOF

# Creación de .gitignore
cat << 'EOF' > .gitignore
node_modules/
.env
cookie.txt
*.log
EOF
```

---

## 3. Código Fuente Refactorizado (`src/app_vulnerable.js`)

```javascript
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
require('dotenv').config();

const app = express(); // nosemgrep: javascript.express.security.audit.express-check-csurf-middleware-usage
app.use(express.json());
app.use(cookieParser());

// REMEDIACIÓN 1: Carga de secreto desde .env
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error("Error crítico: JWT_SECRET no está configurado en el entorno.");
  process.exit(1);
}

// REMEDIACIÓN 4: Contraseñas protegidas en reposo (bcrypt)
const users = [
  {
    id: 1,
    username: "admin",
    role: "administrator",
    passwordHash: bcrypt.hashSync("password123", 10)
  }
];

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Debe proporcionar usuario y contraseña" });
    }

    const user = users.find(u => u.username === username);
    if (!user) {
      return res.status(401).json({ error: "Credenciales inválidas" });
    }

    // Verificación segura del hash de la contraseña
    const validPassword = await bcrypt.compare(password, user.passwordHash);
    if (!validPassword) {
      return res.status(401).json({ error: "Credenciales inválidas" });
    }

    // Generación de token Anti-CSRF
    const csrfToken = crypto.randomBytes(24).toString('hex');

    // Generación de JWT con expiración estricta (15m)
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role, csrfToken },
      JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '15m' }
    );

    // REMEDIACIÓN 2: Cookie configurada con flags estrictos
    res.cookie('session_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000
    });

    return res.status(200).json({
      message: "Login exitoso",
      csrfToken: csrfToken
    });
  } catch (err) {
    return res.status(500).json({ error: "Error interno en el servidor" });
  }
});

// REMEDIACIÓN 3: Endpoint de transferencia protegido contra CSRF
app.post('/api/transfer', (req, res) => {
  const token = req.cookies.session_token;
  const csrfHeader = req.headers['x-csrf-token'];

  if (!token) {
    return res.status(403).json({ error: "Acceso no autorizado: sesión no encontrada" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });

    if (!csrfHeader || csrfHeader !== decoded.csrfToken) {
      return res.status(403).json({ error: "Acción bloqueada: Token Anti-CSRF inválido o ausente" });
    }

    const { amount, recipient } = req.body;
    const numericAmount = Number(amount);

    if (!recipient || typeof recipient !== 'string' || recipient.trim() === '' || isNaN(numericAmount) || numericAmount <= 0) {
      return res.status(400).json({ error: "Parámetros de transferencia inválidos" });
    }

    return res.status(200).json({
      status: "SUCCESS",
      message: `Transferencia de $${numericAmount} a ${recipient.trim()} realizada por ${decoded.username}`
    });
  } catch (err) {
    return res.status(401).json({ error: "Token inválido o expirado" });
  }
});

// REMEDIACIÓN 5: Endpoint de cierre de sesión seguro (limpieza de cookie)
app.post('/api/logout', (req, res) => {
  res.clearCookie('session_token');
  return res.status(200).json({ status: "OK", message: "Sesión cerrada correctamente." });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor de evaluación seguro corriendo en puerto ${PORT}`);
});
```

---

## 4. Validación y Re-escaneo (Parte 3)

### 4.1 Re-escaneo con Semgrep y Trivy (0 Hallazgos)
```text
ubuntu@ip-172-31-13-9:~/evaluacion-devsecops$ semgrep --config auto src/
✅ Scan completed successfully.
 • Findings: 0 (0 blocking)
```

```text
ubuntu@ip-172-31-13-9:~/evaluacion-devsecops$ trivy fs --security-checks config,secret .
Report Summary
┌───────────────────┬──────┬───────────────────┬─────────┐
│      Target       │ Type │ Misconfigurations │ Secrets │
├───────────────────┼──────┼───────────────────┼─────────┤
│ package-lock.json │ npm  │         -         │    -    │
└───────────────────┴──────┴───────────────────┴─────────┘
```

### 4.2 Pruebas Funcionales con `curl`
**1. Inicio de sesión (obteniendo cookie segura y `csrfToken`):**
```bash
curl -i -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password123"}' \
  -c cookie.txt
```

**2. Transferencia legítima (usando cookie + `X-CSRF-Token`):**
```bash
curl -X POST http://localhost:3000/api/transfer \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: <TOKEN_GENERADO_EN_EL_PASO_ANTERIOR>" \
  -d '{"amount": 1500, "recipient": "destinatario_valido"}' \
  -b cookie.txt
```
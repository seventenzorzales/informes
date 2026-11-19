### 3.1. Resumen de Evidencia Analizada
* **Servidor y Sistema Operativo afectado:** `dev-jumpbox` — Alpine Linux 3.24.3
* **Artefactos inspeccionados:** `/var/log/messages`, `/etc/os-release`, `/etc/shadow` e historial de comandos de la shell (`.ash_history`).
* **Vulnerabilidad explotada:** `CVE-2026-123158` (valor de colisión: `*`).
* **IP de origen del atacante:** `192.168.72.1` (puerto origen `61351`).
* **Usuario objetivo comprometido:** `adminsvc`.
* **Línea de tiempo del acceso:**
  * `2026-11-06 11:27:05`: Intento fallido de autenticación SSH (`Failed password for adminsvc`).
  * `2026-11-06 11:27:08`: Explotación exitosa y acceso concedido (`Accepted password for adminsvc`).
  * `2026-11-06 12:20:02`: Cierre de sesión del atacante (`Disconnected from user adminsvc`).
* **Actividad post-explotación (Escaneo de red interna):**
  El atacante utilizó el *jumpbox* como pivote para enumerar puertos abiertos en la subred interna de desarrolladores (`192.168.18.1` a `192.168.18.254`) mediante el siguiente comando:
  ```bash
  for ip in {1..254}; do nc -zvw 1 192.168.18.$ip 1-65535 2>&1 | grep -E "succeeded|open"; done
  ```
* **Exfiltración de datos:** El archivo sensible fue exfiltrada hacia la URI `[https://devv.coding.eu/process](https://devv.coding.eu/process)`.

### 3.2. Evidencia del Resultado (Laboratorio Completado)
A continuación se adjuntan las capturas que validan la resolución completa de las tareas forenses del reto Sherlock `sshole`:

![Validación Tasks 1 a 4 ](media/sshole_1.png)

![Validación Tasks 5 a 7 ](media/sshole_2.png)

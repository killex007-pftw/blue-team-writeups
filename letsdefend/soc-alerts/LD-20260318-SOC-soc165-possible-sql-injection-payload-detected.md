# SOC165 - Possible SQL Injection Payload Detected — SOC Alert Writeup

<!-- Archivo: LD-20260319-SOC-SOC165-possible-sql-injection-payload-detected.md -->

---

## Metadata

| Campo | Valor |
|---|---|
| **Plataforma** | LetsDefend |
| **Categoría** | SOC Alert |
| **Alert ID** | 115 |
| **Regla disparada** | SOC165 - Possible SQL Injection Payload Detected |
| **Fecha de la alerta** | 2022-02-25 11:34 AM UTC |
| **Fecha del análisis** | 2026-03-19 |
| **Severidad** | High |
| **Veredicto final** | True Positive |
| **Escalado** | No |
| **Tiempo invertido** | ~30 min |

### Herramientas utilizadas

`LetsDefend Log Management` · `LetsDefend Endpoint Security` · `VirusTotal` · `CyberChef`

### MITRE ATT&CK

| ID | Técnica | Táctica |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial Access |

---

## Resumen Ejecutivo

Un atacante externo desde la IP `167.99.169[.]17` realizó un ataque de SQL Injection manual contra `WebServer1001` (`172.16.17[.]18`) apuntando al parámetro `q` del endpoint `/search/`. Se identificaron 6 requests secuenciales con payloads SQLi entre las 11:30 y 11:34 AM del 25 de febrero de 2022. Todos los intentos retornaron HTTP 500 con response size idéntico de 948 bytes, confirmando que el ataque no fue exitoso. Veredicto: True Positive. No requirió escalado a Tier 2.

---

## 1. Triage Inicial

### Información de la alerta

| Campo | Detalle |
|---|---|
| Dispositivo de origen | IP externa — no pertenece a la red interna |
| IP de origen | `167.99.169[.]17` |
| IP de destino | `172.16.17[.]18` |
| Hostname destino | WebServer1001 |
| Usuario involucrado | N/A |
| Proceso / Aplicación | Web Server (HTTPS / puerto 443) |
| Método HTTP | GET |
| URL solicitada | `https://172.16.17[.]18/search/?q=%22%20OR%201%20%3D%201%20--%20-` |
| URL decodificada | `https://172.16.17[.]18/search/?q=" OR 1 = 1 -- -` |
| User-Agent | `Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1` |
| Alert Trigger Reason | Requested URL Contains OR 1 = 1 |
| Device Action | Allowed |
| Timestamp | 2022-02-25 11:34 AM |

### Primera hipótesis

La regla fue disparada por la presencia del patrón `OR 1 = 1` en el parámetro `q` de la URL, codificado en URL encoding. La decodificación del payload confirma un intento clásico de SQL Injection boolean-based contra el endpoint `/search/` de `WebServer1001`. El tráfico proviene de una IP externa (Internet → Company Network), lo que descarta actividad interna.

---

## 2. Recolección de Evidencia

### Verificación de IP de origen

La IP `167.99.169[.]17` es una dirección pública externa. Se verificó que no pertenece a ningún activo interno de la empresa ni a herramientas de simulación de ataques (Verodin, AttackIQ, Picus). No se encontró ningún email o registro de trabajo planificado asociado a esta IP.

### Logs relevantes — Log Management

Búsqueda realizada por IP de origen `167.99.169.17`, ordenada cronológicamente:

```
[LOG 1] Feb 25, 2022 — 11:30 AM
Request URL  : https://172.16.17.18/
Method       : GET
Response     : 200 — 3547 bytes
Device Action: Permitted
Observación  : Reconocimiento inicial — el atacante verifica que el endpoint es accesible

[LOG 2] Feb 25, 2022 — 11:32 AM
Request URL  : https://172.16.17.18/search/?q=%27
URL decoded  : /search/?q='
Method       : GET
Response     : 500 — 948 bytes
Device Action: Permitted
Observación  : Prueba de comilla simple — sondeo de vulnerabilidad SQLi

[LOG 3] Feb 25, 2022 — 11:32 AM
Request URL  : https://172.16.17.18/search/?q=%27%20OR%20%271
URL decoded  : /search/?q=' OR '1
Method       : GET
Response     : 500 — 948 bytes
Device Action: Permitted
Observación  : Boolean-based SQLi — primer intento de condición verdadera

[LOG 4] Feb 25, 2022 — 11:33 AM
Request URL  : https://172.16.17.18/search/?q=%27%20OR%20%27x%27%3D%27x
URL decoded  : /search/?q=' OR 'x'='x
Method       : GET
Response     : 500 — 948 bytes
Device Action: Permitted
Observación  : Boolean-based SQLi alternativo — intento de bypass de filtros

[LOG 5] Feb 25, 2022 — 11:33 AM
Request URL  : https://172.16.17.18/search/?q=1%27%20ORDER%20BY%203--%2B
URL decoded  : /search/?q=1' ORDER BY 3--+
Method       : GET
Response     : 500 — 948 bytes
Device Action: Permitted
Observación  : Enumeración de columnas con ORDER BY — técnica de reconocimiento de estructura DB

[LOG 6] Feb 25, 2022 — 11:34 AM  ← LOG QUE DISPARÓ LA ALERTA
Request URL  : https://172.16.17.18/search/?q=%22%20OR%201%20%3D%201%20--%20-
URL decoded  : /search/?q=" OR 1 = 1 -- -
Method       : GET
Response     : 500 — 948 bytes
Device Action: Permitted
Observación  : Intento de bypass de autenticación con comentario SQL (-- -)
```

### Capturas de pantalla

![Detalles del evento en Monitoring](./screenshots-SOC165/01-event-details.png)
![Logs de IP origen en Log Management](./screenshots-SOC165/02-logs-source-ip.png)
![Raw del log que disparó la alerta](./screenshots-SOC165/03-trigger-log-raw.png)
![Playbook completado — Score 100%](./screenshots-SCO165/04-playbook-score.png)

---

## 3. Análisis

### 3.1 Análisis de red / tráfico

| Timestamp | URL decodificada | HTTP Status | Response Size | Observación |
|---|---|---|---|---|
| 11:30 AM | `https://172.16.17[.]18/` | 200 | 3547 bytes | Reconocimiento — endpoint accesible |
| 11:32 AM | `/search/?q='` | 500 | 948 bytes | Sondeo SQLi — comilla simple |
| 11:32 AM | `/search/?q=' OR '1` | 500 | 948 bytes | Boolean-based SQLi |
| 11:33 AM | `/search/?q=' OR 'x'='x` | 500 | 948 bytes | Boolean-based SQLi alternativo |
| 11:33 AM | `/search/?q=1' ORDER BY 3--+` | 500 | 948 bytes | Enumeración de columnas |
| 11:34 AM | `/search/?q=" OR 1 = 1 -- -` | 500 | 948 bytes | Bypass de autenticación ← **alerta** |

El response size constante de **948 bytes** en todos los intentos de SQLi indica que el servidor devuelve siempre la misma página de error genérica — no retorna datos de la base de datos. Esto confirma que el ataque no tuvo éxito.

### 3.2 Análisis del payload

El payload decodificado `" OR 1 = 1 -- -` tiene la siguiente estructura:

- `"` — cierra la cadena de texto en la consulta SQL
- `OR 1 = 1` — introduce una condición siempre verdadera para bypassear filtros
- `-- -` — comentario SQL que anula el resto de la query original

Técnica: **Boolean-based SQL Injection / Authentication Bypass**. El objetivo era manipular la query SQL del parámetro `q` para retornar todos los registros o evadir validaciones.

### 3.3 Verificación de actividad planificada

Se verificó que la IP `167.99.169[.]17` no corresponde a ninguna herramienta de simulación de ataques (Verodin, AttackIQ, Picus) ni existe registro de trabajo planificado. El tráfico no es resultado de un pentest autorizado.

---

## 4. Determinación del Veredicto

**Veredicto:** True Positive

**Justificación:** Se confirmó un ataque de SQL Injection manual y progresivo desde una IP externa contra el endpoint `/search/` de `WebServer1001`. El análisis de los 6 logs muestra una secuencia deliberada de reconocimiento y explotación. El ataque no fue exitoso — todos los payloads retornaron HTTP 500 con response size constante de 948 bytes, sin evidencia de exfiltración de datos ni compromiso del backend.

### Decisión de escalado

- No requiere escalado — caso cerrado

**Razón:** El ataque provino de Internet, no fue exitoso y no hubo compromiso de ningún dispositivo interno.

---

## 5. Indicadores de Compromiso (IOCs)

| Tipo | Valor | Contexto |
|---|---|---|
| IP | `167.99.169[.]17` | IP externa del atacante |
| IP | `172.16.17[.]18` | WebServer1001 — servidor objetivo |
| URL | `hxxps://172.16.17[.]18/search/?q=%22%20OR%201%20%3D%201%20--%20-` | Payload SQLi que disparó la alerta |
| Hostname | `WebServer1001` | Servidor web objetivo |

> Todos los IOCs están defangeados.

---

## 6. Hallazgos Clave

1. **Ataque manual y progresivo:** El atacante realizó un reconocimiento sistemático en 4 minutos — desde verificar accesibilidad del endpoint hasta intentar bypass de autenticación y enumeración de columnas, lo que indica conocimiento técnico de SQLi.

2. **Ataque no exitoso:** El response size constante de 948 bytes en todos los payloads SQLi confirma que el servidor retornó siempre la misma página de error, sin exponer datos de la base de datos.

3. **Gap en controles de red:** El firewall permitió todos los requests sin bloquear ninguno de los payloads SQLi (Device Action: Permitted), lo que indica ausencia de un WAF o reglas de filtrado de payloads en capa de aplicación.

---

## 7. Lecciones Aprendidas

### Lo que funcionó
- La correlación de logs por IP de origen permitió reconstruir la secuencia completa del ataque y confirmar que no fue exitoso.
- El análisis del HTTP Response Size (948 bytes constante) fue el indicador clave para determinar ausencia de exfiltración de datos.
- La decodificación URL del payload confirmó rápidamente el tipo de ataque y la técnica utilizada.

### Gaps identificados
- El firewall permitió todos los requests con payloads SQLi sin bloquearlos — oportunidad de mejora implementando un WAF con reglas de detección de SQLi en capa de aplicación.

### Para investigar después
- Verificar si `167.99.169[.]17` aparece en otros eventos del SIEM apuntando a otros activos de la red.
- Consultar reputación de la IP en AbuseIPDB y Cisco Talos para determinar si pertenece a un actor conocido.

---

## Referencias

- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [OWASP — SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [CyberChef — URL Decode](https://gchq.github.io/CyberChef/)
- [AbuseIPDB](https://www.abuseipdb.com/)
- [Cisco Talos Intelligence](https://talosintelligence.com/)
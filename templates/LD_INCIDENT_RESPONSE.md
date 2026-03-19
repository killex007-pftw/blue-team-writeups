# [Nombre del Incidente] — Incident Response Writeup

<!-- Archivo: LD-YYYYMMDD-IR-nombre-del-caso.md -->

---

## Metadata

| Campo | Valor |
|---|---|
| **Plataforma** | LetsDefend |
| **Categoría** | Incident Response |
| **Caso ID** | |
| **Fecha del incidente** | YYYY-MM-DD |
| **Fecha del análisis** | YYYY-MM-DD |
| **Severidad** | CRITICAL / HIGH / MEDIUM / LOW |
| **Tipo de incidente** | Ransomware / Data Breach / Lateral Movement / Insider Threat / Otro |
| **Estado** | Contenido / En progreso |
| **Tiempo invertido** | ~X horas |

### Activos afectados

| Host / IP | Rol | Sistema Operativo | Estado |
|---|---|---|---|
| | | | Comprometido / Sospechoso / Limpio |

### Herramientas utilizadas

`Herramienta 1` · `Herramienta 2` · `Herramienta 3`

### MITRE ATT&CK

| ID | Técnica | Táctica |
|---|---|---|
| TXXXX.XXX | Nombre de la técnica | Nombre de la táctica |

---

## Resumen Ejecutivo

> Descripción del incidente: qué ocurrió, cuándo fue detectado, qué sistemas se vieron afectados y cuál fue el impacto real o potencial. Máximo 4–5 oraciones.

---

## 1. Detección y Alcance Inicial

### ¿Cómo fue detectado?

> Describir el vector de detección: alerta SIEM, reporte de usuario, herramienta de EDR, etc.

### Scope inicial

> ¿Cuántos sistemas y usuarios se identificaron como potencialmente afectados al inicio?

---

## 2. Línea de Tiempo del Incidente

| Timestamp (UTC) | Evento | Fuente |
|---|---|---|
| YYYY-MM-DD HH:MM | | |
| YYYY-MM-DD HH:MM | | |
| YYYY-MM-DD HH:MM | | |
| YYYY-MM-DD HH:MM | Detección del incidente | |
| YYYY-MM-DD HH:MM | Inicio de respuesta | |
| YYYY-MM-DD HH:MM | Contención | |

---

## 3. Análisis del Incidente

### 3.1 Vector de acceso inicial

> ¿Cómo entró el atacante? Phishing, credenciales comprometidas, explotación de vulnerabilidad, acceso físico, etc.

```
[Evidencia — logs, comandos, artefactos relevantes]
```

### 3.2 Movimiento lateral (si aplica)

> ¿A qué otros sistemas se extendió el atacante? ¿Qué técnicas usó (Pass-the-Hash, RDP, SMB, etc.)?

| Sistema origen | Sistema destino | Técnica | Timestamp |
|---|---|---|---|
| | | | |

### 3.3 Escalada de privilegios (si aplica)

> ¿El atacante escaló privilegios? ¿Qué técnica utilizó?

### 3.4 Persistencia establecida

> ¿Qué mecanismos de persistencia dejó el atacante? (Scheduled tasks, registry keys, backdoors, cuentas creadas, etc.)

| Tipo | Detalle | Host |
|---|---|---|
| | | |

### 3.5 Objetivos del atacante / Impacto

> ¿Qué buscaba el atacante? ¿Qué datos o sistemas fueron comprometidos, cifrados o exfiltrados?

---

## 4. Contención

> Acciones tomadas para detener la propagación del incidente.

- [ ] Aislamiento de host(s) afectado(s)
- [ ] Bloqueo de IP(s) / dominio(s) maliciosos en firewall
- [ ] Deshabilitación de cuenta(s) comprometida(s)
- [ ] Revocación de tokens / sesiones activas
- [ ] Otro: 

**Evidencia de contención:**
```
[Logs o capturas que confirmen la contención]
```

---

## 5. Erradicación

> Pasos tomados para eliminar al atacante y los artefactos maliciosos del entorno.

- [ ] Eliminación de malware / backdoors
- [ ] Eliminación de cuentas creadas por el atacante
- [ ] Eliminación de mecanismos de persistencia
- [ ] Parcheo de vulnerabilidades explotadas
- [ ] Reset de credenciales comprometidas
- [ ] Otro: 

---

## 6. Recuperación

> Acciones para restaurar los sistemas al estado operativo seguro.

- [ ] Restauración desde backup limpio
- [ ] Validación de integridad de sistemas
- [ ] Re-habilitación de servicios afectados
- [ ] Monitoreo post-recuperación implementado

---

## 7. Causa Raíz (RCA)

### ¿Cuál fue la causa raíz del incidente?

> Descripción clara de la vulnerabilidad, error humano, gap de configuración o control fallido que permitió el incidente.

### Cadena de ataque resumida

```
[Vector inicial] → [Ejecución] → [Persistencia] → [Lateral Movement] → [Impacto]
```

---

## 8. Indicadores de Compromiso (IOCs)

| Tipo | Valor | Contexto |
|---|---|---|
| IP | | |
| Domain | | |
| File Hash (MD5) | | |
| File Hash (SHA256) | | |
| URL | | |
| Registry Key | | |
| Scheduled Task | | |

> Todos los IOCs están defangeados: `192.168.1[.]1` / `evil[.]com`

---

## 9. Hallazgos Clave

1. **[Hallazgo 1]:** 
2. **[Hallazgo 2]:** 
3. **[Hallazgo 3]:** 

---

## 10. Recomendaciones

| Prioridad | Recomendación | Tipo |
|---|---|---|
| Alta | | Técnico / Proceso / Formación |
| Media | | |
| Baja | | |

---

## 11. Lecciones Aprendidas

### Lo que funcionó
- 

### Gaps identificados
- 

### Para investigar después
- 

---

## Referencias

- [MITRE ATT&CK — Técnica](https://attack.mitre.org/techniques/TXXXX/)
- [Recurso adicional](URL)

# 167-LS Command Detected in Requested URL — de la Alerta] — SOC Alert Writeup

<!-- Archivo: LD-YYYYMMDD-SOC-nombre-del-caso.md -->

---

## Metadata

| Campo | Valor |
|---|---|
| **Plataforma** | LetsDefend |
| **Categoría** | SOC Alert |
| **Alert ID** | |
| **Regla disparada** | |
| **Fecha de la alerta** | 2026-03-24 HH:MM UTC |
| **Fecha del análisis** | 2026-03-24 |
| **Severidad** | CRITICAL / HIGH / MEDIUM / LOW |
| **Veredicto final** | True Positive / False Positive |
| **Escalado** | Sí / No |
| **Tiempo invertido** | ~X min |

### Herramientas utilizadas

`Herramienta 1` · `Herramienta 2` · `Herramienta 3`

### MITRE ATT&CK

| ID | Técnica | Táctica |
|---|---|---|
| TXXXX.XXX | Nombre de la técnica | Nombre de la táctica |

---

## Resumen Ejecutivo

> Descripción concisa: qué alerta se disparó, sobre qué activo, qué se encontró durante el análisis y cuál fue el veredicto final.

---

## 1. Triage Inicial

### Información de la alerta

| Campo | Detalle |
|---|---|
| Dispositivo de origen | |
| IP de origen | |
| IP de destino | |
| Usuario involucrado | |
| Proceso / Aplicación | |
| Timestamp | |

### Primera hipótesis

> ¿Qué sugiere la alerta a primera vista? Describir la hipótesis inicial antes de comenzar el análisis profundo.

---

## 2. Recolección de Evidencia

> Documentar todas las fuentes consultadas: logs, correos, archivos, capturas de tráfico, etc.

### Logs relevantes

```
[Pegar aquí los logs relevantes — timestamps, eventos, campos clave]
```

### Capturas de pantalla

<!-- ![Descripción](./screenshots/LD-YYYYMMDD-SOC-nombre-01.png) -->

---

## 3. Análisis

### 3.1 Análisis de red / tráfico

> ¿Hubo conexiones salientes sospechosas? ¿Puertos inusuales? ¿Volumen de datos anómalo?

### 3.2 Análisis de endpoint

> ¿Qué procesos se ejecutaron? ¿Hay artefactos de persistencia? ¿Comandos sospechosos?

### 3.3 Análisis de correo / phishing (si aplica)

| Campo | Detalle |
|---|---|
| Remitente | |
| Reply-To | |
| Asunto | |
| Adjunto / URL | |
| Resultado en VT / sandbox | |

### 3.4 Correlación de eventos

> ¿Qué otros eventos ocurrieron antes o después de la alerta? ¿Hay un patrón?

---

## 4. Determinación del Veredicto

### ¿True Positive o False Positive?

**Veredicto:** True Positive / False Positive

**Justificación:**
> Explicar con evidencia concreta por qué se llegó a este veredicto.

### Decisión de escalado

- [ ] No requiere escalado — caso cerrado
- [ ] Escalado al Tier 2 — motivo: 
- [ ] Escalado a IR — motivo: 

---

## 5. Indicadores de Compromiso (IOCs)

| Tipo | Valor | Contexto |
|---|---|---|
| IP | | |
| Domain | | |
| File Hash (MD5) | | |
| File Hash (SHA256) | | |
| URL | | |
| Email | | |

> Todos los IOCs están defangeados: `192.168.1[.]1` / `evil[.]com`

---

## 6. Hallazgos Clave

1. **[Hallazgo 1]:** 
2. **[Hallazgo 2]:** 
3. **[Hallazgo 3]:** 

---

## 7. Lecciones Aprendidas

### Lo que funcionó
- 

### Gaps identificados
- 

### Para investigar después
- 

---

## Referencias

- [MITRE ATT&CK — Técnica](https://attack.mitre.org/techniques/TXXXX/)
- [VirusTotal](https://www.virustotal.com)
- [Recurso adicional](URL)

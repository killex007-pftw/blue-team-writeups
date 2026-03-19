# [Nombre de la Hunt] — Threat Hunting Writeup

<!-- Archivo: LD-YYYYMMDD-TH-nombre-de-la-hunt.md -->

---

## Metadata

| Campo | Valor |
|---|---|
| **Plataforma** | LetsDefend |
| **Categoría** | Threat Hunting |
| **Fecha** | YYYY-MM-DD |
| **Resultado** | 🔴 Amenaza confirmada / 🟡 Actividad sospechosa / 🟢 Entorno limpio |
| **Tiempo invertido** | ~X horas |

### Fuentes de datos consultadas

| Fuente | Descripción |
|---|---|
| | Logs de endpoint / red / proxy / DNS / etc. |

### Herramientas utilizadas

`Herramienta 1` · `Herramienta 2` · `Herramienta 3`

### MITRE ATT&CK

| ID | Técnica | Táctica |
|---|---|---|
| TXXXX.XXX | Nombre de la técnica | Nombre de la táctica |

---

## Resumen Ejecutivo

> ¿Qué se buscó, cómo se buscó y qué se encontró? Incluir el resultado final de la hunt en 3–4 oraciones.

---

## 1. Hipótesis

> **Enunciado de la hipótesis:**
> *"Se sospecha que [actor / técnica] está utilizando [vector] para [objetivo] en [entorno]."*

### Base de la hipótesis

> ¿Por qué se formuló esta hipótesis? ¿Threat intel reciente? ¿Anomalía detectada? ¿Campaña conocida?

### Indicadores que motivaron la hunt

- 
- 

---

## 2. Metodología

### Framework aplicado

> Describir el enfoque de hunting: basado en IOC, en TTP, en anomalías de comportamiento, o en modelo de madurez (HMM Level).

```
Nivel de madurez de la hunt:
  0 — Inicial (basado en IOC)
  1 — Mínimo (basado en indicadores manuales)
  2 — Procedural (basado en TTP documentados)
  3 — Innovador (basado en análisis de comportamiento / ML)
```

**Nivel aplicado en esta hunt:** Nivel X

### Alcance

| Parámetro | Valor |
|---|---|
| Período de tiempo analizado | YYYY-MM-DD a YYYY-MM-DD |
| Sistemas incluidos | |
| Usuarios incluidos | Todos / Específicos |
| Fuentes de datos | |

---

## 3. Desarrollo de la Hunt

### 3.1 Consultas ejecutadas

#### Consulta 1: [Descripción del objetivo]

```sql
-- Descripción: qué busca esta consulta y por qué
[Query en SPL / KQL / SQL / EQL según la herramienta]
```

**Resultado:** X eventos retornados — [Normal / Sospechoso / Benigno confirmado]

#### Consulta 2: [Descripción del objetivo]

```sql
[Query]
```

**Resultado:** X eventos retornados — [Descripción]

#### Consulta 3: [Descripción del objetivo]

```sql
[Query]
```

**Resultado:** X eventos retornados — [Descripción]

---

### 3.2 Análisis de resultados

> Para cada hallazgo relevante, documentar:
> - Qué se encontró
> - Por qué es sospechoso o benigno
> - Cómo se validó

#### Hallazgo A

```
[Evidencia — log, salida de query, captura de pantalla referenciada]
```

**Análisis:**

**Veredicto:** 🔴 Malicioso / 🟡 Sospechoso / 🟢 Benigno

---

## 4. Resultado de la Hunt

### Resumen de hallazgos

| # | Descripción | Veredicto | Sistemas afectados |
|---|---|---|---|
| 1 | | 🔴/🟡/🟢 | |
| 2 | | | |

### Resultado general

**🔴 Amenaza confirmada** — Se encontró evidencia de actividad maliciosa activa.
**→ Acción:** Escalar a Incident Response.

_o_

**🟡 Actividad sospechosa** — Se identificaron anomalías que requieren monitoreo adicional.
**→ Acción:** Crear regla de detección y monitorear.

_o_

**🟢 Entorno limpio** — No se encontró evidencia de la amenaza hipotética.
**→ Acción:** Documentar consultas como base para detección futura.

---

## 5. Oportunidades de Detección

> Si la hunt reveló gaps de detección, proponer reglas nuevas.

### Regla SIGMA propuesta

```yaml
title: [Nombre de la regla]
id: [UUID generado]
status: experimental
description: [Descripción de la detección]
author: killex007
date: YYYY-MM-DD
logsource:
    category: [process_creation / network_connection / etc.]
    product: [windows / linux / etc.]
detection:
    selection:
        [Campo]: [Valor]
    condition: selection
falsepositives:
    - [Posible falso positivo]
level: [low / medium / high / critical]
tags:
    - attack.[táctica]
    - attack.[técnica_id]
```

---

## 6. Indicadores de Compromiso (IOCs)

*(Completar solo si la hunt confirmó amenaza)*

| Tipo | Valor | Contexto |
|---|---|---|
| IP | | |
| Domain | | |
| File Hash | | |

---

## 7. Hallazgos Clave

1. **[Hallazgo 1]:** 
2. **[Hallazgo 2]:** 
3. **[Hallazgo 3]:** 

---

## 8. Lecciones Aprendidas

### Lo que funcionó
- 

### Gaps identificados
- 

### Para investigar después
- 

---

## Referencias

- [MITRE ATT&CK — Técnica](https://attack.mitre.org/techniques/TXXXX/)
- [Sigma HQ](https://github.com/SigmaHQ/sigma)
- [Recurso adicional](URL)

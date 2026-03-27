# BLUE TEAM WRITEUPS

Repositorio que contiene documentación de casos tomados de SOC, Incident Response, Threat Hunting y Malware Analysis — resueltos en LetsDefend y Hack The Box.

**Autor:** Kilmer Bustos 

---

## Plataformas cubiertas

| Plataforma | Categorías | Carpeta |
|---|---|---|
| LetsDefend | SOC Alerts, Incident Response, Threat Hunting, Malware Analysis | `/letsdefend/` |
| Hack The Box | Sherlocks, Forensics Challenges, Blue Team Labs | `/htb-blueteam/` |

---

## Estructura del repositorio 
> Aún en desarrollo.

```
blue-team-writeups/
├── README.md
│
├── letsdefend/
│   ├── soc-alerts/
│   ├── incident-response/  # Por crearse
│   ├── threat-hunting/     # Por crearse
│   └── malware-analysis/   # Por crearse
│
├── htb-blueteam/           # Por crearse 
│   ├── sherlocks/          # Por crearse
│   └── forensics/          # Por crearse 
│
└── templates/
    ├── BASE_TEMPLATE.md
    ├── LD_SOC_ALERT.md
    ├── LD_INCIDENT_RESPONSE.md
    ├── LD_THREAT_HUNTING.md
    ├── LD_MALWARE_ANALYSIS.md
    └── HTB_BLUETEAM.md
```

---

## Índice de writeups 
> NOTA: Aún en progreso, según vaya subiendo mas documentación de casos se irán indexando para ambas plataformas.

### LetsDefend — SOC Alerts

| ID | Caso | Severidad | Veredicto | Fecha |
|---|---|---|---|---|
| 115 | [Possible SQL Injection Payload Detected](letsdefend/soc-alerts/LD-20260318-SOC-165-possible-sql-injection-payload-detected.md) | High | True Positive | 18/03/2026 |
| 116 | [Javascript Code Detected in Requested URL](letsdefend/soc-alerts/LD-20260319-SOC-166-javascript-code-detected-in-requested-url.md) | Medium | True Positive | 19/03/2026 |
| 117 | [LS Command Detected in Requested URL](letsdefend/soc-alerts/LD-20260324-SOC-167-ls-command-detected-in-requested-url.md) | High | False Positive | 24/03/2026 |
| 118 | [Whoami Command Detected in Request Body](letsdefend/soc-alerts/LD-20260325-SOC-168-whoami-command-detected-in-request-body.md) | High | True Positive | 25/03/2026 |
| 119 | [Possible IDOR Attack Detected](letsdefend/soc-alerts/LD-20260326-SOC-169-possible-idor-attack-detected.md) | Medium | True Positive | 26/03/2026 |
---

## Disclaimer

Los writeups de LetsDefend son publicados únicamente después de completar el caso y en conformidad con la política de divulgación de la plataforma. Los writeups de HTB son publicados únicamente para retos retirados o con divulgación autorizada.

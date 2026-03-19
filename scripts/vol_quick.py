"""
vol_quick.py — Volatility 3 Quick Analysis Wrapper
====================================================
Este script ejecuta automáticamente los plugins más importantes de Volatility 3
sobre un memory dump y guarda cada output en la carpeta exports/ del caso.

También genera un resumen consolidado con los hallazgos más relevantes.

Uso:
    python vol_quick.py <ruta_al_dump>
    python vol_quick.py <ruta_al_dump> --case <ruta_al_caso>
    python vol_quick.py <ruta_al_dump> --plugins pslist netscan malfind

Ejemplos:
    python vol_quick.py C:\\Cases\\LD-20260316-MA-emotet\\artifacts\\memory.dmp
    python vol_quick.py memory.dmp --case C:\\Cases\\LD-20260316-MA-emotet

Autor: killex007
"""

import os
import sys
import subprocess
import argparse
from datetime import datetime

# ─── CONFIGURACIÓN — RUTAS DE VOLATILITY EN FLARE VM ─────────────────────────
# Flare VM puede tener Volatility 3 en varias rutas posibles.
# El script las prueba en orden hasta encontrar la correcta.

VOLATILITY_PATHS = [
    r"C:\Tools\volatility3\vol.py",             # Fallback standalone
    r"C:\Tools\volatility3\volatility3\vol.py", # Fallback alternativo
]

# Volatility 3 v2.27.0 instalado como paquete Python (sin vol.exe) - Verificado en mi entorno local.
# Se invoca como: C:\python310\python.exe -m volatility3
# find_volatility() prueba esto primero antes de VOLATILITY_PATHS
PYTHON_CMD = r"C:\python310\python.exe"

# ─── PLUGINS A EJECUTAR ───────────────────────────────────────────────────────
# Cada plugin tiene: nombre, comando vol3, descripción, y si es prioritario
PLUGINS = [
    {
        "name": "imageinfo",
        "cmd": "windows.info",
        "desc": "Información del sistema operativo del dump",
        "priority": "HIGH",
    },
    {
        "name": "pslist",
        "cmd": "windows.pslist",
        "desc": "Lista de procesos activos",
        "priority": "HIGH",
    },
    {
        "name": "pstree",
        "cmd": "windows.pstree",
        "desc": "Árbol de procesos (relaciones padre-hijo)",
        "priority": "HIGH",
    },
    {
        "name": "cmdline",
        "cmd": "windows.cmdline",
        "desc": "Argumentos de línea de comandos de cada proceso",
        "priority": "HIGH",
    },
    {
        "name": "netscan",
        "cmd": "windows.netscan",
        "desc": "Conexiones de red y sockets",
        "priority": "HIGH",
    },
    {
        "name": "malfind",
        "cmd": "windows.malfind",
        "desc": "Regiones de memoria sospechosas (code injection)",
        "priority": "HIGH",
    },
    {
        "name": "dlllist",
        "cmd": "windows.dlllist",
        "desc": "DLLs cargadas por cada proceso",
        "priority": "MEDIUM",
    },
    {
        "name": "handles",
        "cmd": "windows.handles",
        "desc": "Handles abiertos (archivos, registry, mutexes)",
        "priority": "MEDIUM",
    },
    {
        "name": "filescan",
        "cmd": "windows.filescan",
        "desc": "Archivos en memoria (FILE_OBJECT structures)",
        "priority": "MEDIUM",
    },
    {
        "name": "registry_hivelist",
        "cmd": "windows.registry.hivelist",
        "desc": "Lista de colmenas del registro en memoria",
        "priority": "MEDIUM",
    },
    {
        "name": "svcscan",
        "cmd": "windows.svcscan",
        "desc": "Servicios de Windows registrados",
        "priority": "MEDIUM",
    },
    {
        "name": "hashdump",
        "cmd": "windows.hashdump",
        "desc": "Hashes NTLM de cuentas locales",
        "priority": "LOW",
    },
    {
        "name": "privs",
        "cmd": "windows.privileges",
        "desc": "Privilegios de procesos",
        "priority": "LOW",
    },
]

HIGH_PRIORITY_PLUGINS = [p["name"] for p in PLUGINS if p["priority"] == "HIGH"]
# ──────────────────────────────────────────────────────────────────────────────

# Banner personalizable, lo puedes modificar segun tus gustos
def banner():
    print("""
╔══════════════════════════════════════════════╗
║       Volatility 3 Quick Analysis            ║
║       killex007 — Flare VM                   ║
╚══════════════════════════════════════════════╝
""")


def find_volatility():
    """
    Detecta la instalacion de Volatility 3 disponible.

    En mi instancia Flare VM, Volatility esta instalado como paquete Python sin vol.exe.
    El entry point correcto es: from volatility3.cli import main
    Se crea un wrapper vol_runner.py en el mismo directorio del script.
    """
    # Primera opcion: paquete pip (volatility3.cli) — caso aplicado para mi entorno Flare VM, se recomienda evaluar en caso no cumpla para tu entorno.
    try:
        check = subprocess.run(
            [PYTHON_CMD, "-c", "from volatility3.cli import main; print('OK')"],
            capture_output=True, text=True, timeout=15
        )
        if "OK" in check.stdout:
            # Crear vol_runner.py junto al script si no existe
            runner_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vol_runner.py")
            if not os.path.isfile(runner_path):
                with open(runner_path, "w") as f:
                    f.write("# Auto-generado por vol_quick.py\n")
                    f.write("# Entry point para Volatility 3 instalado via pip\n")
                    f.write("from volatility3.cli import main\n")
                    f.write("if __name__ == '__main__':\n")
                    f.write("    main()\n")
            return [PYTHON_CMD, runner_path]
    except Exception:
        pass

    # Segunda opcion: vol.py standalone
    for path in VOLATILITY_PATHS:
        if os.path.isfile(path):
            return [PYTHON_CMD, path]

    # Tercera opcion: vol.py en el mismo directorio del script
    local_vol = os.path.join(os.path.dirname(__file__), "vol.py")
    if os.path.isfile(local_vol):
        return [PYTHON_CMD, local_vol]

    return None


def run_plugin(vol_cmd, dump_path, plugin, output_dir, timeout=120):
    """Ejecuta un plugin de Volatility y guarda el resultado."""
    output_file = os.path.join(output_dir, f"{plugin['name']}.txt")
    cmd = vol_cmd + ["-f", dump_path, plugin["cmd"]]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace"
        )
        output = result.stdout
        if result.stderr and not output:
            output = result.stderr

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(f"# Plugin: {plugin['cmd']}\n")
            f.write(f"# Desc  : {plugin['desc']}\n")
            f.write(f"# Dump  : {dump_path}\n")
            f.write(f"# Run   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(output)

        lines = [l for l in output.strip().splitlines() if l.strip()]
        return True, len(lines), output_file

    except subprocess.TimeoutExpired:
        with open(output_file, "w") as f:
            f.write(f"TIMEOUT: Plugin excedió {timeout}s\n")
        return False, 0, output_file
    except Exception as e:
        with open(output_file, "w") as f:
            f.write(f"ERROR: {e}\n")
        return False, 0, output_file


def extract_key_findings(output_dir):
    """
    Analiza los outputs de los plugins y extrae hallazgos clave
    para el resumen consolidado.
    """
    findings = []

    # ── Procesos sospechosos (pslist + pstree) ──
    pslist_path = os.path.join(output_dir, "pslist.txt")
    if os.path.exists(pslist_path):
        suspicious_procs = []
        with open(pslist_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                lower = line.lower()
                # Procesos comúnmente usados por malware
                indicators = [
                    "powershell", "wscript", "cscript", "mshta",
                    "regsvr32", "rundll32", "certutil", "bitsadmin",
                    "cmd.exe", "net.exe", "sc.exe", "schtasks"
                ]
                for ind in indicators:
                    if ind in lower and "system32" not in lower:
                        suspicious_procs.append(line.strip())
                        break
        if suspicious_procs:
            findings.append(("PROCESOS SOSPECHOSOS", suspicious_procs[:15]))

    # ── Conexiones de red (netscan) ──
    netscan_path = os.path.join(output_dir, "netscan.txt")
    if os.path.exists(netscan_path):
        connections = []
        with open(netscan_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if "ESTABLISHED" in line or "LISTEN" in line:
                    # Excluir localhost y conexiones locales obvias
                    if "127.0.0.1" not in line and "::1" not in line:
                        connections.append(line.strip())
        if connections:
            findings.append(("CONEXIONES DE RED ACTIVAS", connections[:20]))

    # ── Malfind ──
    malfind_path = os.path.join(output_dir, "malfind.txt")
    if os.path.exists(malfind_path):
        malfind_hits = []
        with open(malfind_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        # Contar entradas (cada proceso en malfind empieza con su nombre)
        hits = [l for l in content.splitlines() if l.startswith("Process:") or "MZ" in l]
        if hits:
            findings.append(("MALFIND — Posible Code Injection", hits[:10]))

    # ── Cmdline sospechosos ──
    cmdline_path = os.path.join(output_dir, "cmdline.txt")
    if os.path.exists(cmdline_path):
        suspicious_cmds = []
        with open(cmdline_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                lower = line.lower()
                sus_patterns = [
                    "encoded", "-enc", "bypass", "hidden", "downloadstring",
                    "invoke-expression", "iex", "wget", "curl", "base64",
                    "frombase64", "webclient", "-nop", "-noni"
                ]
                if any(p in lower for p in sus_patterns):
                    suspicious_cmds.append(line.strip())
        if suspicious_cmds:
            findings.append(("CMDLINE SOSPECHOSOS", suspicious_cmds[:10]))

    return findings


def generate_summary(dump_path, output_dir, results, vol_cmd):
    """Genera el resumen consolidado del análisis."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = []
    lines.append("=" * 60)
    lines.append("  VOLATILITY 3 — ANALYSIS SUMMARY")
    lines.append(f"  killex007 — {now}")
    lines.append("=" * 60)
    lines.append(f"\n  Dump     : {dump_path}")
    lines.append(f"  Exports  : {output_dir}")
    lines.append(f"  Vol cmd  : {' '.join(vol_cmd)}\n")

    # Tabla de resultados por plugin
    lines.append("[PLUGINS EJECUTADOS]")
    lines.append(f"  {'Plugin':<22} {'Estado':<10} {'Líneas':>8}  Archivo")
    lines.append(f"  {'-'*22} {'-'*10} {'-'*8}  {'-'*30}")
    for name, success, n_lines, out_file in results:
        status = "OK" if success else "ERROR"
        fname = os.path.basename(out_file)
        lines.append(f"  {name:<22} {status:<10} {n_lines:>8}  {fname}")

    # Hallazgos clave
    findings = extract_key_findings(output_dir)
    if findings:
        lines.append(f"\n{'=' * 60}")
        lines.append("[HALLAZGOS CLAVE — Revisar con prioridad]")
        for title, items in findings:
            lines.append(f"\n  {title}")
            for item in items:
                lines.append(f"    {item}")
    else:
        lines.append(f"\n[HALLAZGOS CLAVE]")
        lines.append("  No se detectaron indicadores automáticos obvios.")
        lines.append("  Revisar manualmente los outputs, especialmente malfind y netscan.")

    lines.append(f"\n[ARCHIVOS GENERADOS]")
    for f in sorted(os.listdir(output_dir)):
        if f.endswith(".txt"):
            fpath = os.path.join(output_dir, f)
            fsize = os.path.getsize(fpath)
            lines.append(f"  {f:<40} {fsize:>8,} bytes")

    lines.append(f"\n[PRÓXIMOS PASOS SUGERIDOS]")
    lines.append(f"  1. Revisar malfind.txt — buscar procesos con MZ header en memoria")
    lines.append(f"  2. Revisar netscan.txt — identificar IPs externas y puertos inusuales")
    lines.append(f"  3. Revisar cmdline.txt — buscar comandos ofuscados (base64, -enc, etc.)")
    lines.append(f"  4. Cruzar procesos sospechosos con dlllist.txt")
    lines.append(f"  5. Copiar IOCs al template de Malware Analysis")
    lines.append(f"\n{'=' * 60}\n")

    summary_path = os.path.join(output_dir, "vol_summary.txt")
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return summary_path, "\n".join(lines)


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    banner()

    parser = argparse.ArgumentParser(
        description="Volatility 3 Quick Analysis para Flare VM"
    )
    parser.add_argument("dump", help="Ruta al memory dump")
    parser.add_argument("--case", "-c", help="Ruta al directorio del caso", default=None)
    parser.add_argument(
        "--plugins", "-p",
        nargs="+",
        help=f"Plugins específicos a ejecutar. Disponibles: {', '.join(p['name'] for p in PLUGINS)}",
        default=None
    )
    parser.add_argument(
        "--priority",
        choices=["high", "all"],
        default="all",
        help="Ejecutar solo plugins HIGH priority (más rápido) o todos"
    )
    args = parser.parse_args()

    # Validar dump
    dump_path = os.path.abspath(args.dump)
    if not os.path.isfile(dump_path):
        print(f" Dump no encontrado: {dump_path}")
        sys.exit(1)

    # Detectar Volatility en tu entorno
    vol_cmd = find_volatility()
    if not vol_cmd:
        print("  Volatility 3 no encontrado.")
        print("     Opciones:")
        print("     1. Instalar con: pip install volatility3")
        print("     2. Descargar desde: https://github.com/volatilityfoundation/volatility3")
        print("     3. Ajustar VOLATILITY_PATHS en este script")
        sys.exit(1)

    print(f"  Volatility encontrado: {' '.join(vol_cmd)}")

    # Directorio de exports
    if args.case:
        output_dir = os.path.join(args.case, "exports", "volatility")
    else:
        output_dir = os.path.join(os.path.dirname(dump_path), "volatility_exports")
    os.makedirs(output_dir, exist_ok=True)

    # Seleccionar plugins
    if args.plugins:
        selected = [p for p in PLUGINS if p["name"] in args.plugins]
        not_found = [n for n in args.plugins if n not in [p["name"] for p in PLUGINS]]
        if not_found:
            print(f"Plugins no reconocidos: {', '.join(not_found)}")
    elif args.priority == "high":
        selected = [p for p in PLUGINS if p["priority"] == "HIGH"]
    else:
        selected = PLUGINS

    print(f"  Dump     : {os.path.basename(dump_path)}")
    print(f"  Exports  : {output_dir}")
    print(f"  Plugins  : {len(selected)} a ejecutar\n")

    # Ejecutar plugins
    results = []
    for i, plugin in enumerate(selected, 1):
        priority_tag = f"[{plugin['priority']}]" if plugin["priority"] == "HIGH" else "      "
        print(f"  [{i:02d}/{len(selected):02d}] {priority_tag} {plugin['name']:<22} — {plugin['desc']}")
        success, n_lines, out_file = run_plugin(vol_cmd, dump_path, plugin, output_dir)
        status = f" {n_lines} líneas" if success else "❌ error"
        print(f"           └─ {status}")
        results.append((plugin["name"], success, n_lines, out_file))

    # Generar resumen
    print(f"\n  Generando resumen consolidado...")
    summary_path, summary_content = generate_summary(dump_path, output_dir, results, vol_cmd)

    print()
    print(summary_content)
    print(f"   Resumen guardado en: {summary_path}")
    print(f"   Revisar vol_summary.txt y copiar hallazgos al template de análisis.\n")


if __name__ == "__main__":
    main()

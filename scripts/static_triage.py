"""
static_triage.py — Triage estático automatizado para análisis de malware
=========================================================================
Dado un archivo (sample), ejecuta automáticamente:
  - Hashes (MD5, SHA1, SHA256)
  - Tipo de archivo y magic bytes
  - Strings relevantes (filtrado)
  - Detect-It-Easy (DIE) si está disponible
  - CAPA si está disponible
  - Enlace directo a VirusTotal

Genera un reporte en la carpeta exports/ del caso activo.

Uso:
    python static_triage.py <ruta_al_sample>
    python static_triage.py <ruta_al_sample> --case <ruta_al_caso>

Ejemplos:
    python static_triage.py C:\\Users\\user\\Desktop\\Cases\\LD-20260316-MA-emotet\\artifacts\\sample.exe
    python static_triage.py sample.exe --case C:\\Users\\user\\Desktop\\Cases\\LD-20260316-MA-emotet

Autor: killex007
"""

import os
import sys
import hashlib
import struct
import string
import subprocess
import argparse
from datetime import datetime

# ─── CONFIGURACIÓN — RUTAS DE HERRAMIENTAS EN FLARE VM ───────────────────────
# Flare VM instala las herramientas en C:\Tools\ por defecto.
# Si alguna herramienta está en otra ruta, tratar de ajustar AQUÍ.

TOOL_PATHS = {
    "die": [
        r"C:\Tools\die\die.exe",                    # Confirmado en mi entorno Flare VM
        r"C:\Tools\die_win64_portable\die.exe",     # Fallback alternativo
    ],
    "capa": [
        r"C:\Tools\capa\capa.exe",                  # Confirmado en mi entorno Flare VM
        r"C:\Tools\capa-v7.0.0-windows\capa.exe",  # Fallback alternativo
    ],
}

MIN_STRING_LENGTH = 6       # Longitud mínima para filtrar strings
MAX_STRINGS_OUTPUT = 80     # Máximo de strings a incluir en el reporte
# ──────────────────────────────────────────────────────────────────────────────

# El banner es personalizable acorde a tu entorno y a tu actividad a realizar, en este caso el triage estático durante el Análisis de Malware.
def banner():
    print("""
╔══════════════════════════════════════════════╗
║       Static Triage — Malware Analysis       ║
║       killex007 — Flare VM                   ║
╚══════════════════════════════════════════════╝
""")


def find_tool(name):
    """Busca la herramienta en las rutas configuradas. Retorna la ruta o None."""
    for path in TOOL_PATHS.get(name, []):
        if os.path.isfile(path):
            return path
    return None


# ─── HASHES ───────────────────────────────────────────────────────────────────

def compute_hashes(filepath):
    """Calcula MD5, SHA1 y SHA256 del archivo."""
    hashes = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            for h in hashes.values():
                h.update(chunk)
    return {k: v.hexdigest() for k, v in hashes.items()}


# ─── MAGIC BYTES / TIPO DE ARCHIVO ────────────────────────────────────────────

MAGIC_SIGNATURES = {
    b"\x4D\x5A": "PE (MZ) — Windows Executable (.exe/.dll/.sys)",
    b"\x7FELF": "ELF — Linux Executable",
    b"\x25\x50\x44\x46": "PDF Document",
    b"\x50\x4B\x03\x04": "ZIP Archive (puede ser Office, JAR, APKG)",
    b"\xD0\xCF\x11\xE0": "OLE2 Compound File (Office 97-2003, .doc/.xls/.ppt)",
    b"\x4D\x53\x43\x46": "Microsoft Cabinet (.cab)",
    b"\x52\x61\x72\x21": "RAR Archive",
    b"\x1F\x8B": "GZIP Compressed",
    b"\x23\x21": "Script (shebang — #!)",
}

def detect_magic(filepath):
    """Detecta tipo de archivo por magic bytes."""
    with open(filepath, "rb") as f:
        header = f.read(16)
    for magic, description in MAGIC_SIGNATURES.items():
        if header.startswith(magic):
            return description
    return f"Desconocido — primeros bytes: {header[:8].hex()}"


# ─── PE INFORMATION ───────────────────────────────────────────────────────────

def get_pe_info(filepath):
    """Extrae información básica del header PE sin dependencias externas."""
    info = {}
    try:
        with open(filepath, "rb") as f:
            # Verificar MZ header
            if f.read(2) != b"MZ":
                return None
            # Offset al PE header
            f.seek(0x3C)
            pe_offset = struct.unpack("<I", f.read(4))[0]
            f.seek(pe_offset)
            if f.read(4) != b"PE\x00\x00":
                return None
            # COFF header
            machine = struct.unpack("<H", f.read(2))[0]
            num_sections = struct.unpack("<H", f.read(2))[0]
            timestamp = struct.unpack("<I", f.read(4))[0]
            f.read(4)  # skip PointerToSymbolTable
            f.read(4)  # skip NumberOfSymbols
            opt_header_size = struct.unpack("<H", f.read(2))[0]
            characteristics = struct.unpack("<H", f.read(2))[0]

            machine_map = {0x14C: "x86 (32-bit)", 0x8664: "x64 (64-bit)", 0x1C0: "ARM"}
            info["architecture"] = machine_map.get(machine, f"Unknown (0x{machine:04X})")
            info["num_sections"] = num_sections
            info["compile_timestamp"] = datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S UTC")

            is_dll = bool(characteristics & 0x2000)
            is_exe = bool(characteristics & 0x0002)
            info["type"] = "DLL" if is_dll else ("EXE" if is_exe else "Other")

    except Exception as e:
        info["error"] = str(e)
    return info


# ─── STRINGS ──────────────────────────────────────────────────────────────────

INTERESTING_PATTERNS = [
    "http", "https", "ftp", "tcp", "udp", "socket",
    "cmd", "powershell", "wscript", "cscript", "regsvr",
    "HKEY_", "SOFTWARE\\", "CurrentVersion\\Run",
    "CreateRemoteThread", "VirtualAlloc", "WriteProcessMemory",
    "LoadLibrary", "GetProcAddress", "ShellExecute", "WinExec",
    "CryptEncrypt", "CryptDecrypt", "BCryptEncrypt",
    "InternetOpen", "HttpSendRequest", "URLDownloadToFile",
    "taskkill", "net user", "net localgroup", "whoami",
    ".exe", ".dll", ".bat", ".ps1", ".vbs",
    "password", "passwd", "credentials", "token",
    "base64", "decode", "encode",
    "\\Temp\\", "\\AppData\\", "\\Startup\\",
    "svchost", "explorer", "lsass",
]

def extract_strings(filepath, min_length=MIN_STRING_LENGTH):
    """Extrae ASCII y Unicode strings del binario, priorizando los interesantes."""
    strings_found = []
    interesting = []

    with open(filepath, "rb") as f:
        data = f.read()

    # ASCII strings
    current = []
    for byte in data:
        if 0x20 <= byte <= 0x7E:
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                s = "".join(current)
                strings_found.append(s)
            current = []

    # Filtrar los interesantes
    for s in strings_found:
        s_lower = s.lower()
        if any(pat.lower() in s_lower for pat in INTERESTING_PATTERNS):
            interesting.append(s)

    return strings_found, interesting


# ─── HERRAMIENTAS EXTERNAS ────────────────────────────────────────────────────

def run_die(filepath):
    """Ejecuta DIE y retorna la salida."""
    die_path = find_tool("die")
    if not die_path:
        return None, "DIE no encontrado en rutas configuradas"
    try:
        result = subprocess.run(
            [die_path, "--resultasjson", filepath],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout.strip() or result.stderr.strip(), None
    except subprocess.TimeoutExpired:
        return None, "DIE timeout (>30s)"
    except Exception as e:
        return None, str(e)


def run_capa(filepath, exports_dir):
    """Ejecuta CAPA y guarda el output en exports/."""
    capa_path = find_tool("capa")
    if not capa_path:
        return None, "CAPA no encontrado en rutas configuradas"
    try:
        print("  Ejecutando CAPA (puede tomar 1-3 minutos)...")
        result = subprocess.run(
            [capa_path, filepath],
            capture_output=True, text=True, timeout=180
        )
        output = result.stdout + result.stderr
        # Guardar output completo de CAPA
        capa_out_path = os.path.join(exports_dir, "capa_output.txt")
        with open(capa_out_path, "w", encoding="utf-8") as f:
            f.write(output)
        return output[:3000], None  # Resumido en el reporte principal
    except subprocess.TimeoutExpired:
        return None, "CAPA timeout (>3min) — sample puede ser complejo"
    except Exception as e:
        return None, str(e)


# ─── GENERACIÓN DE REPORTE ────────────────────────────────────────────────────

def generate_report(filepath, exports_dir):
    """Genera el reporte de triage estático completo."""
    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    date_compact = datetime.now().strftime("%Y%m%d")

    lines = []
    lines.append("=" * 60)
    lines.append("  STATIC TRIAGE REPORT")
    lines.append(f"  killex007 — {now}")
    lines.append("=" * 60)

    # ── Hashes ──
    print("  [1/6] Calculando hashes...")
    hashes = compute_hashes(filepath)
    lines.append("\n[FILE INFO]")
    lines.append(f"  Nombre    : {filename}")
    lines.append(f"  Tamaño    : {filesize:,} bytes ({filesize / 1024:.1f} KB)")
    lines.append(f"  Ruta      : {filepath}")
    lines.append(f"\n[HASHES]")
    lines.append(f"  MD5       : {hashes['md5']}")
    lines.append(f"  SHA1      : {hashes['sha1']}")
    lines.append(f"  SHA256    : {hashes['sha256']}")
    lines.append(f"\n[VIRUSTOTAL]")
    lines.append(f"  https://www.virustotal.com/gui/file/{hashes['sha256']}")

    # ── Magic bytes ──
    print("  [2/6] Detectando tipo de archivo...")
    magic = detect_magic(filepath)
    lines.append(f"\n[TIPO DE ARCHIVO]")
    lines.append(f"  Magic bytes : {magic}")

    # ── PE Info ──
    pe_info = get_pe_info(filepath)
    if pe_info and "error" not in pe_info:
        lines.append(f"\n[PE HEADER]")
        lines.append(f"  Arquitectura      : {pe_info.get('architecture', 'N/A')}")
        lines.append(f"  Tipo              : {pe_info.get('type', 'N/A')}")
        lines.append(f"  Secciones         : {pe_info.get('num_sections', 'N/A')}")
        lines.append(f"  Compile Timestamp : {pe_info.get('compile_timestamp', 'N/A')}")

    # ── DIE ──
    print("  [3/6] Ejecutando Detect-It-Easy...")
    die_output, die_error = run_die(filepath)
    lines.append(f"\n[DETECT-IT-EASY (DIE)]")
    if die_output:
        lines.append(f"  {die_output}")
    else:
        lines.append(f"  Error de die  {die_error}")

    # ── Strings ──
    print("  [4/6] Extrayendo strings...")
    all_strings, interesting_strings = extract_strings(filepath)
    lines.append(f"\n[STRINGS]")
    lines.append(f"  Total strings extraídas : {len(all_strings)}")
    lines.append(f"  Strings interesantes    : {len(interesting_strings)}")

    lines.append(f"\n[STRINGS INTERESANTES]")
    if interesting_strings:
        for s in interesting_strings[:MAX_STRINGS_OUTPUT]:
            lines.append(f"  {s}")
        if len(interesting_strings) > MAX_STRINGS_OUTPUT:
            lines.append(f"  ... ({len(interesting_strings) - MAX_STRINGS_OUTPUT} más — ver strings_full.txt)")
    else:
        lines.append("  No se encontraron strings interesantes con los patrones configurados.")

    # Guardar strings completas
    strings_path = os.path.join(exports_dir, "strings_full.txt")
    with open(strings_path, "w", encoding="utf-8", errors="replace") as f:
        f.write(f"# Strings completas — {filename}\n")
        f.write(f"# Total: {len(all_strings)}\n\n")
        for s in all_strings:
            f.write(s + "\n")

    # ── CAPA ──
    print("  [5/6] Ejecutando CAPA...")
    capa_output, capa_error = run_capa(filepath, exports_dir)
    lines.append(f"\n[CAPA — Capabilities]")
    if capa_output:
        # Solo mostrar resumen en el reporte — el completo está en capa_output.txt
        lines.append(f"  (Output completo en exports/capa_output.txt)")
        lines.append(f"  --- PREVIEW (primeras 50 líneas) ---")
        preview = "\n".join(capa_output.split("\n")[:50])
        lines.append(preview)
    else:
        lines.append(f"  Error de capa  {capa_error}")

    # ── IOC Template ──
    lines.append(f"\n[IOCs INICIALES — completar manualmente]")
    lines.append(f"  MD5     : {hashes['md5']}")
    lines.append(f"  SHA1    : {hashes['sha1']}")
    lines.append(f"  SHA256  : {hashes['sha256']}")
    lines.append(f"  Tipo    : {magic}")
    lines.append(f"  VT URL  : https://www.virustotal.com/gui/file/{hashes['sha256']}")
    lines.append(f"\n  [Completar tras análisis dinámico]")
    lines.append(f"  IPs C2     :")
    lines.append(f"  Dominios   :")
    lines.append(f"  Mutex      :")
    lines.append(f"  Reg Keys   :")

    lines.append(f"\n{'=' * 60}")
    lines.append(f"  Reporte generado: {now}")
    lines.append(f"  Siguiente paso  : Análisis dinámico en sandbox aislado")
    lines.append(f"{'=' * 60}\n")

    # ── Guardar reporte ──
    print("  [6/6] Guardando reporte...")
    report_filename = f"static_triage_{date_compact}_{filename}.txt"
    report_path = os.path.join(exports_dir, report_filename)
    with open(report_path, "w", encoding="utf-8", errors="replace") as f:
        f.write("\n".join(lines))

    return report_path, "\n".join(lines)


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    banner()

    parser = argparse.ArgumentParser(
        description="Static triage automatizado para análisis de malware en Flare VM"
    )
    parser.add_argument("sample", help="Ruta al archivo a analizar")
    parser.add_argument(
        "--case", "-c",
        help="Ruta al directorio del caso (opcional). Si no se indica, exporta en la misma carpeta del sample.",
        default=None
    )
    args = parser.parse_args()

    # Validar que el sample existe
    sample_path = os.path.abspath(args.sample)
    if not os.path.isfile(sample_path):
        print(f" Archivo no encontrado: {sample_path}")
        sys.exit(1)

    # Determinar exports_dir
    if args.case:
        exports_dir = os.path.join(args.case, "exports")
    else:
        exports_dir = os.path.dirname(sample_path)

    os.makedirs(exports_dir, exist_ok=True)

    print(f"  Sample   : {os.path.basename(sample_path)}")
    print(f"  Exports  : {exports_dir}")
    print()

    # Ejecutar triage
    report_path, report_content = generate_report(sample_path, exports_dir)

    # Mostrar en consola
    print()
    print(report_content)
    print(f"  Reporte guardado en: {report_path}")
    print(f"  Copiar los hashes al template de Malware Analysis.\n")


if __name__ == "__main__":
    main()

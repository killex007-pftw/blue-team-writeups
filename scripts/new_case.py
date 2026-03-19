"""
new_case.py — Inicializador de casos Blue Team
===============================================
Este script crea la estructura de carpetas del caso, copia la plantilla
correcta con el metadata pre-rellenado, y abre el directorio. Uso principal
en la documentación de casos de Letsdefend, HackTheBox, etc.

Uso:
    python new_case.py

Autor: killex007
"""

import os
import sys
import shutil
import subprocess
from datetime import datetime

# ─── CONFIGURACIÓN ────────────────────────────────────────────────────────────
# Ajustar si cambias la ubicación base de tus casos
BASE_CASES_DIR = os.path.join(os.path.expanduser("~"), "Desktop", "Cases")

# Ruta al repositorio de templates del framework personalizado
# Ajustar a donde tengas clonado blue-team-writeups o como se llame tu carpeta donde almacenarás tu documentación
TEMPLATES_DIR = os.path.join(os.path.expanduser("~"), "Desktop", "blue-team-writeups", "templates")

TEMPLATES = {
    "1": ("SOC",  "LD_SOC_ALERT.md",         "letsdefend/soc-alerts"),
    "2": ("IR",   "LD_INCIDENT_RESPONSE.md",  "letsdefend/incident-response"),
    "3": ("TH",   "LD_THREAT_HUNTING.md",     "letsdefend/threat-hunting"),
    "4": ("MA",   "LD_MALWARE_ANALYSIS.md",   "letsdefend/malware-analysis"),
    "5": ("HTB",  "HTB_BLUETEAM.md",          "htb-blueteam"),
}
# ──────────────────────────────────────────────────────────────────────────────

# Lo del banner es personalizable acorde a tu entorno, en mi caso uso FLARE VM en Windows 10.
def banner():
    print("""
╔══════════════════════════════════════════════╗
║       Blue Team Case Initializer             ║
║       killex007 — Flare VM                   ║
╚══════════════════════════════════════════════╝
""")


def select_case_type():
    print("  Tipo de caso:")
    for key, (tipo, _, _) in TEMPLATES.items():
        print(f"    [{key}] {tipo}")
    print()
    while True:
        choice = input("  Selecciona el tipo [1-5]: ").strip()
        if choice in TEMPLATES:
            return choice
        print("  Opción inválida. Intenta de nuevo.")


def slugify(text):
    """Convierte texto a slug para nombre de carpeta."""
    import re
    text = text.lower().strip()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_]+", "-", text)
    return text


def create_case_structure(case_dir):
    """Crea la estructura de subcarpetas del caso."""
    subdirs = ["writeup", "artifacts", "screenshots", "exports"]
    for d in subdirs:
        os.makedirs(os.path.join(case_dir, d), exist_ok=True)


def prefill_template(template_path, dest_path, case_name, case_type, date_str):
    """Copia la plantilla y pre-rellena campos de metadata."""
    with open(template_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Pre-rellenar fecha y nombre en el metadata (luego lo puedes personalizar acorde al caso)
    content = content.replace("YYYY-MM-DD", date_str)
    content = content.replace("# [Nombre", f"# {case_name} —")
    content = content.replace("[Nombre del Caso]", case_name)
    content = content.replace("[Nombre de la Alerta]", case_name)
    content = content.replace("[Nombre del Incidente]", case_name)
    content = content.replace("[Nombre de la Hunt]", case_name)
    content = content.replace("[Nombre del Malware / Sample]", case_name)
    content = content.replace("[Nombre del Reto]", case_name)

    with open(dest_path, "w", encoding="utf-8") as f:
        f.write(content)


def main():
    banner()

    # 1. Seleccionar tipo
    choice = select_case_type()
    case_type, template_file, repo_subdir = TEMPLATES[choice]

    # 2. Nombre del caso
    print()
    case_name_raw = input(f"  Nombre del caso [{case_type}]: ").strip()
    if not case_name_raw:
        print("  El nombre no puede estar vacío.")
        sys.exit(1)

    # 3. Construir nombre de carpeta y archivo
    date_str = datetime.now().strftime("%Y-%m-%d")
    date_compact = datetime.now().strftime("%Y%m%d")
    slug = slugify(case_name_raw)
    folder_name = f"LD-{date_compact}-{case_type}-{slug}" if case_type != "HTB" else f"HTB-{date_compact}-{slug}"
    writeup_filename = f"{folder_name}.md"

    # 4. Crear directorio del caso
    case_dir = os.path.join(BASE_CASES_DIR, folder_name)
    if os.path.exists(case_dir):
        print(f"\n  Ya existe un caso con ese nombre: {case_dir}")
        sys.exit(1)

    os.makedirs(case_dir, exist_ok=True)
    create_case_structure(case_dir)
    print(f"\n  Estructura creada: {case_dir}")

    # 5. Copiar y pre-rellenar plantilla
    template_path = os.path.join(TEMPLATES_DIR, template_file)
    writeup_path = os.path.join(case_dir, "writeup", writeup_filename)

    if os.path.exists(template_path):
        prefill_template(template_path, writeup_path, case_name_raw, case_type, date_str)
        print(f"  Writeup creado:    writeup\\{writeup_filename}")
    else:
        print(f"  Template no encontrado en: {template_path}")
        print(f"     Ajusta la variable TEMPLATES_DIR en el script.")

    # 6. Crear README del caso con metadata básico
    readme_path = os.path.join(case_dir, "README.md")
    with open(readme_path, "w", encoding="utf-8") as f:
        f.write(f"# {case_name_raw}\n\n")
        f.write(f"| Campo | Valor |\n|---|---|\n")
        f.write(f"| **Tipo** | {case_type} |\n")
        f.write(f"| **Fecha** | {date_str} |\n")
        f.write(f"| **Estado** | En progreso |\n\n")
        f.write(f"## Estructura\n\n")
        f.write(f"```\n{folder_name}/\n")
        f.write(f"├── writeup/      ← Documentación Markdown\n")
        f.write(f"├── artifacts/    ← Samples, logs, archivos del caso\n")
        f.write(f"├── screenshots/  ← Capturas de pantalla\n")
        f.write(f"└── exports/      ← Salidas de herramientas de análisis\n```\n")
    print(f"  README del caso creado")

    # 7. Crear artifacts/.gitkeep
    open(os.path.join(case_dir, "artifacts", ".gitkeep"), "w").close()
    open(os.path.join(case_dir, "screenshots", ".gitkeep"), "w").close()
    open(os.path.join(case_dir, "exports", ".gitkeep"), "w").close()

    # 8. Abrir carpeta en Explorer (automaticamente)
    print(f"\n  Abriendo carpeta del caso...")
    subprocess.Popen(f'explorer "{case_dir}"')

    print(f"""
  ══════════════════════════════════════════════
  Caso inicializado exitosamente.

  Carpeta : {case_dir}
  Writeup : writeup\\{writeup_filename}
  
  Próximo paso: abrir el writeup y completar
  la sección de Metadata.
  ══════════════════════════════════════════════
""")


if __name__ == "__main__":
    main()

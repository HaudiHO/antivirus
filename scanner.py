import os
import re
import psutil
from pathlib import Path

SUSP_EXT = {".lnk", ".vbs", ".js", ".cmd", ".bat", ".scr", ".pif"}
DOUBLE_EXT_RE = re.compile(r".+\.(jpg|png|pdf|doc|docx|xls|xlsx|txt|mp4|mp3)\.(exe|scr|bat|cmd|vbs)$", re.I)

def list_removable_drives():
    drives = []
    for p in psutil.disk_partitions(all=False):
        device = p.device
        mount = p.mountpoint
        opts = p.opts.lower()
        if os.name == "nt":
            if "removable" in opts or ("cdrom" not in opts and mount[:1].isalpha()):
                drives.append(mount)
    return sorted(set(drives))

def inspect_drive(root):
    root_path = Path(root)
    suspicious = []
    hidden_candidates = []

    try:
        for item in root_path.iterdir():
            name = item.name.lower()

            if item.suffix.lower() in SUSP_EXT:
                suspicious.append({
                    "path": str(item),
                    "reason": f"Подозрительное расширение {item.suffix.lower()}"
                })

            if name == "autorun.inf":
                suspicious.append({
                    "path": str(item),
                    "reason": "Найден autorun.inf"
                })

            if DOUBLE_EXT_RE.match(item.name):
                suspicious.append({
                    "path": str(item),
                    "reason": "Подозрительное двойное расширение"
                })

            # Частая ситуация: настоящая папка скрыта, а рядом лежит .lnk
            if item.is_dir() and item.name.startswith("."):
                hidden_candidates.append(str(item))

    except PermissionError:
        pass

    return {
        "drive": root,
        "suspicious": suspicious,
        "hidden_candidates": hidden_candidates
    }

def scan_all_removable_drives():
    return [inspect_drive(d) for d in list_removable_drives()]
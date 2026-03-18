import os
import re
import ctypes
import psutil
from pathlib import Path
from signatures import SUSPICIOUS_EXTENSIONS, SUSPICIOUS_NAMES

FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4

DOUBLE_EXT_RE = re.compile(
    r"^.+(\.(jpg|jpeg|png|gif|pdf|doc|docx|xls|xlsx|txt|mp3|mp4|avi|zip|rar))\.(exe|scr|bat|cmd|vbs|js|pif|wsf)$",
    re.IGNORECASE
)

def is_windows_hidden_or_system(path: Path) -> bool:
    if os.name != "nt":
        return path.name.startswith(".")

    try:
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
        if attrs == -1:
            return False
        return bool(attrs & FILE_ATTRIBUTE_HIDDEN) or bool(attrs & FILE_ATTRIBUTE_SYSTEM)
    except Exception:
        return False

def list_targets():
    targets = []

    if os.name == "nt":
        for part in psutil.disk_partitions(all=False):
            mount = part.mountpoint
            opts = part.opts.lower()
            if "cdrom" in opts:
                continue
            if mount and mount[0].isalpha():
                targets.append(mount)
    else:
        volumes = Path("/Volumes")
        if volumes.exists():
            for item in volumes.iterdir():
                if item.is_dir():
                    targets.append(str(item))

    return sorted(set(targets))

def inspect_target(target: str):
    root = Path(target)
    suspicious = []
    hidden_candidates = []

    if not root.exists():
        return {
            "target": target,
            "exists": False,
            "suspicious": [],
            "hidden_candidates": []
        }

    try:
        for item in root.iterdir():
            low_name = item.stem.lower()
            low_full_name = item.name.lower()
            suffix = item.suffix.lower()

            if is_windows_hidden_or_system(item):
                hidden_candidates.append(str(item))

            if low_full_name == "autorun.inf":
                suspicious.append({
                    "path": str(item),
                    "reason": "Найден autorun.inf"
                })
                continue

            if DOUBLE_EXT_RE.match(item.name):
                suspicious.append({
                    "path": str(item),
                    "reason": "Подозрительное двойное расширение"
                })
                continue

            if suffix in SUSPICIOUS_EXTENSIONS:
                suspicious.append({
                    "path": str(item),
                    "reason": f"Подозрительное расширение {suffix}"
                })
                continue

            # Самый важный кейс: exe в корне флешки с маскировочным именем
            if suffix == ".exe":
                suspicious.append({
                    "path": str(item),
                    "reason": "Исполняемый файл в корне носителя"
                })
                continue

            if low_name in SUSPICIOUS_NAMES or low_full_name in SUSPICIOUS_NAMES:
                suspicious.append({
                    "path": str(item),
                    "reason": "Подозрительное имя файла"
                })
                continue

    except PermissionError:
        suspicious.append({
            "path": str(root),
            "reason": "Нет доступа к части файлов"
        })

    return {
        "target": target,
        "exists": True,
        "suspicious": suspicious,
        "hidden_candidates": hidden_candidates
    }

def scan_all_targets():
    targets = list_targets()
    return {
        "targets": [inspect_target(t) for t in targets]
    }
import os
import re
import psutil
from pathlib import Path
from signatures import SUSPICIOUS_EXTENSIONS, DOUBLE_EXTENSION_SAFE_BAIT

DOUBLE_EXT_RE = re.compile(
    r"^.+(\.(jpg|jpeg|png|gif|pdf|doc|docx|xls|xlsx|txt|mp3|mp4|avi|zip|rar))\.(exe|scr|bat|cmd|vbs|js|pif|wsf)$",
    re.IGNORECASE
)

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
            low_name = item.name.lower()
            suffix = item.suffix.lower()

            if low_name == "autorun.inf":
                suspicious.append({
                    "path": str(item),
                    "reason": "Найден autorun.inf"
                })

            if suffix in SUSPICIOUS_EXTENSIONS:
                suspicious.append({
                    "path": str(item),
                    "reason": f"Подозрительное расширение {suffix}"
                })

            if DOUBLE_EXT_RE.match(item.name):
                suspicious.append({
                    "path": str(item),
                    "reason": "Подозрительное двойное расширение"
                })

            if item.is_dir() and item.name.startswith("."):
                hidden_candidates.append(str(item))

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
import os
import shutil
import subprocess
from pathlib import Path
from datetime import datetime
from signatures import SUSPICIOUS_EXTENSIONS

BASE_DIR = Path(os.getenv("APPDATA") or Path.home())
QUARANTINE_DIR = BASE_DIR / "usb_fixer_quarantine"
LOG_DIR = BASE_DIR / "usb_fixer_logs"

QUARANTINE_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)

def quarantine_file(path_str: str):
    src = Path(path_str)
    if not src.exists():
        return None

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dst = QUARANTINE_DIR / f"{stamp}_{src.name}"
    shutil.move(str(src), str(dst))
    return str(dst)

def unhide_windows_files(target: str):
    cmd = ["attrib", "-h", "-s", "-r", f"{target}\\*.*", "/s", "/d"]
    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr
    }

def fix_target(target: str):
    if not target:
        return {"ok": False, "error": "Не передан target"}

    root = Path(target)
    if not root.exists():
        return {"ok": False, "error": "Путь не найден"}

    quarantined = []

    try:
        for item in root.iterdir():
            low_name = item.name.lower()
            suffix = item.suffix.lower()

            if low_name == "autorun.inf" or suffix in SUSPICIOUS_EXTENSIONS:
                moved = quarantine_file(str(item))
                if moved:
                    quarantined.append({"from": str(item), "to": moved})

        restore_info = None
        if os.name == "nt":
            restore_info = unhide_windows_files(target.rstrip("\\/"))

        return {
            "ok": True,
            "target": target,
            "quarantined": quarantined,
            "restore": restore_info
        }

    except Exception as e:
        return {"ok": False, "error": str(e)}
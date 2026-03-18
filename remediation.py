import os
import shutil
import subprocess
from pathlib import Path
from datetime import datetime

QUARANTINE_DIR = Path("quarantine")
QUARANTINE_DIR.mkdir(exist_ok=True)

def quarantine_path(path_str):
    src = Path(path_str)
    if not src.exists():
        return None
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dst = QUARANTINE_DIR / f"{stamp}_{src.name}"
    shutil.move(str(src), str(dst))
    return str(dst)

def unhide_windows_files(drive):
    # Снимаем hidden/system/read-only со всего содержимого диска
    cmd = ['attrib', '-h', '-s', '-r', f'{drive}\\*.*', '/s', '/d']
    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr
    }
def fix_target(path):
    try:
        # пример логики — пока просто заглушка
        print(f"[+] Fixing: {path}")
        return True
    except Exception as e:
        print(f"[-] Error fixing {path}: {e}")
        return False

def fix_drive(drive):
    drive_path = Path(drive)
    quarantined = []
    restored = None

    if os.name != "nt":
        return {"ok": False, "error": "Исправление доступно только на Windows"}

    try:
        for item in drive_path.iterdir():
            low = item.name.lower()

            if low == "autorun.inf" or item.suffix.lower() in {".lnk", ".vbs", ".js", ".cmd", ".bat", ".scr", ".pif"}:
                q = quarantine_path(str(item))
                if q:
                    quarantined.append({"from": str(item), "to": q})

        restored = unhide_windows_files(drive.rstrip("\\/"))

        return {
            "ok": True,
            "drive": drive,
            "quarantined": quarantined,
            "restore_result": restored
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}
    
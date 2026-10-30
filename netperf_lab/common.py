import csv
import json
import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n")


def write_csv(path, rows):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("")
        return
    keys = list(dict.fromkeys(k for row in rows for k in row))
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(rows)


def binary(name):
    local = ROOT / ".tools/root/usr/bin" / name
    path = str(local) if local.exists() else shutil.which(name)
    if not path:
        raise RuntimeError(f"Missing executable: {name}")
    return path


def tool_env():
    env = os.environ.copy()
    lib = ROOT / ".tools/root/usr/lib/x86_64-linux-gnu"
    if lib.exists():
        env["LD_LIBRARY_PATH"] = str(lib) + (":" + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else "")
    env["LC_ALL"] = "C"
    return env


def command_info(args, timeout=10):
    try:
        p = subprocess.run(args, capture_output=True, text=True, env=tool_env(), timeout=timeout)
        return {"command": args, "returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"command": args, "error": str(exc)}


def require_options(name, options):
    info = command_info([binary(name), "--help"])
    help_text = info.get("stdout", "") + info.get("stderr", "")
    missing = [x for x in options if x not in help_text]
    if missing:
        raise RuntimeError(f"Unsupported {name} options: {missing}")
    return help_text


def cpu_ticks(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")
    except (FileNotFoundError, ProcessLookupError):
        return None


def cpu_pair():
    cpus = sorted(os.sched_getaffinity(0))
    first = cpus[0]
    def physical(cpu):
        base = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology")
        return tuple((base / x).read_text().strip() for x in ["physical_package_id", "core_id"])
    other = next((c for c in cpus[1:] if physical(c) != physical(first)), None)
    if other is None:
        raise RuntimeError("Two distinct physical CPU cores are required for local isolation")
    return first, other

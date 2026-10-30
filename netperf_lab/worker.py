"""Run one sender inside its cgroup; account for all its threads with wait4."""
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from .common import tool_env, write_json


def cgroup_state():
    relative = Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]
    path = Path("/sys/fs/cgroup") / relative.lstrip("/")
    result = {"path": str(path), "ancestors": {}}
    for file in ["cpu.max", "cpu.stat", "cpuset.cpus.effective"]:
        try:
            result[file] = (path / file).read_text().strip()
        except OSError:
            result[file] = None
    current = path.parent
    while str(current).startswith("/sys/fs/cgroup"):
        if (current / "cpu.max").exists():
            result["ancestors"][str(current)] = (current / "cpu.max").read_text().strip()
        if current == Path("/sys/fs/cgroup"):
            break
        current = current.parent
    return result


def main():
    spec = json.loads(Path(sys.argv[1]).read_text())
    os.sched_setaffinity(0, {spec["cpu"]})
    initial = cgroup_state()
    quota = spec["quota_percent"]
    if quota is not None:
        value, period = map(int, initial["cpu.max"].split())
        if abs(value / period * 100 - quota) > .01:
            raise RuntimeError(f"CPU quota mismatch: {initial['cpu.max']} vs {quota}%")
    start = time.monotonic()
    with open(spec["stdout"], "wb") as out, open(spec["stderr"], "wb") as err:
        child = subprocess.Popen(spec["command"], stdout=out, stderr=err, env=tool_env())
        def forward(signum, frame):
            try:
                child.send_signal(signum)
            except ProcessLookupError:
                pass
        signal.signal(signal.SIGTERM, forward)
        signal.signal(signal.SIGINT, forward)
        write_json(spec["metadata"], {"pid": child.pid, "monotonic_start": start,
                   "wall_start": time.time(), "cgroup_before": initial, "affinity": sorted(os.sched_getaffinity(child.pid))})
        _, status, usage = os.wait4(child.pid, 0)
        child.returncode = os.waitstatus_to_exitcode(status)
    elapsed = time.monotonic() - start
    cpu = usage.ru_utime + usage.ru_stime
    write_json(spec["accounting"], {"returncode": child.returncode, "process_wall_s": elapsed,
               "monotonic_start": start, "monotonic_end": start + elapsed,
               "cpu_user_s": usage.ru_utime, "cpu_system_s": usage.ru_stime,
               "cpu_s": cpu, "cpu_percent_one_core": 100 * cpu / elapsed,
               "max_rss_kib": usage.ru_maxrss, "cgroup_before": initial, "cgroup_after": cgroup_state()})
    sys.exit(child.returncode if child.returncode >= 0 else 128 - child.returncode)


if __name__ == "__main__":
    main()

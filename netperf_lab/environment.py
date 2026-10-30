import hashlib
import importlib.metadata
import os
import platform
import shutil
from pathlib import Path
from .common import ROOT, binary, command_info, cpu_pair, write_json


def inspect(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    result = {"platform": platform.platform(), "python": platform.python_version(),
              "os_release": Path("/etc/os-release").read_text(),
              "affinity": sorted(os.sched_getaffinity(0)), "cpu_pair": cpu_pair(),
              "self_cgroup": Path("/proc/self/cgroup").read_text(), "tools": {}, "packages": {}}
    for name in ["iperf", "iperf3", "tcpdump", "systemd-run", "taskset", "ssh", "docker"]:
        try:
            path = binary(name)
        except RuntimeError:
            result["tools"][name] = {"available": False}
            continue
        flag = "-v" if name == "iperf" else "--version"
        result["tools"][name] = {"path": path, "version": command_info([path, flag]),
                                "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest()}
        if name in ("iperf", "iperf3", "tcpdump"):
            help_info = command_info([path, "--help"])
            (output / f"{name}-help.txt").write_text(help_info.get("stdout", "") + help_info.get("stderr", ""))
    for name in ["matplotlib", "numpy"]:
        try:
            result["packages"][name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            result["packages"][name] = None
    result["systemd_probe"] = command_info(["systemd-run", "--user", "--quiet", "--wait", "--pipe", "-p", "CPUQuota=50%", "/usr/bin/true"])
    result["network"] = {"links": command_info(["ip", "-details", "link"]),
                         "routes": command_info(["ip", "route"]),
                         "sysctl": command_info(["sysctl", "net.core.rmem_max", "net.core.wmem_max", "net.ipv4.udp_rmem_min"])}
    result["cpuinfo"] = Path("/proc/cpuinfo").read_text()
    result["cgroup_mount"] = command_info(["findmnt", "-no", "FSTYPE,OPTIONS", "/sys/fs/cgroup"])
    result["package_hashes"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT / ".tools/packages").glob("*.deb")}
    write_json(output / "environment.json", result)
    return result

import json
import os
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from .common import ROOT, cpu_ticks, tool_env, write_csv, write_json


def snapshot():
    result = {}
    for name, filename in [("snmp", "/proc/net/snmp"), ("softnet", "/proc/net/softnet_stat"),
                           ("host_cpu", "/proc/stat"), ("loadavg", "/proc/loadavg")]:
        result[name] = Path(filename).read_text()
    return result


def run_sender(command, directory, cpu, quota, receiver_pid=None, timeout=30, backend="systemd"):
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    spec = {"command": command, "cpu": cpu, "quota_percent": quota,
            **{k: str(directory / v) for k, v in {"stdout": "client.stdout", "stderr": "client.stderr",
               "metadata": "sender-metadata.json", "accounting": "sender-accounting.json"}.items()}}
    write_json(directory / "sender-spec.json", spec)
    worker = [sys.executable, "-m", "netperf_lab.worker", str(directory / "sender-spec.json")]
    unit = "iperf-lab-" + uuid.uuid4().hex
    if backend == "systemd":
        command_line = ["systemd-run", "--user", "--quiet", "--wait", "--collect", "--pipe", f"--unit={unit}",
                        "-p", f"WorkingDirectory={ROOT}"]
        if quota is not None:
            command_line += ["-p", f"CPUQuota={quota}%", "-p", "CPUQuotaPeriodSec=100ms"]
        command_line += worker
    elif backend == "none" and quota is None:
        command_line = worker
    else:
        raise RuntimeError("CPU quotas require systemd cgroup v2; no silent fallback")
    write_json(directory / "launcher.json", {"command": command_line, "backend": backend, "unit": unit})
    write_json(directory / "host-before.json", snapshot())
    samples = []
    start = time.monotonic()
    metadata = None
    with (directory / "launcher.stdout").open("wb") as out, (directory / "launcher.stderr").open("wb") as err:
        process = subprocess.Popen(command_line, cwd=ROOT, env=tool_env(), stdout=out, stderr=err)
        try:
            while process.poll() is None:
                if time.monotonic() - start > timeout:
                    raise TimeoutError(f"Sender exceeded {timeout}s")
                if metadata is None and Path(spec["metadata"]).exists():
                    try:
                        metadata = json.loads(Path(spec["metadata"]).read_text())
                    except json.JSONDecodeError:
                        pass
                if metadata:
                    samples.append({"monotonic_s": time.monotonic(), "wall_s": time.time(),
                                    "sender_cpu_s": cpu_ticks(metadata["pid"]),
                                    "receiver_cpu_s": cpu_ticks(receiver_pid) if receiver_pid else None})
                time.sleep(.05)
        finally:
            if process.poll() is None:
                if backend == "systemd":
                    subprocess.run(["systemctl", "--user", "stop", unit], capture_output=True, timeout=10)
                else:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
    write_csv(directory / "cpu-samples.csv", samples)
    write_json(directory / "host-after.json", snapshot())
    if process.returncode or not Path(spec["accounting"]).exists():
        raise RuntimeError(f"Sender failed ({process.returncode}); inspect {directory}")
    accounting = json.loads(Path(spec["accounting"]).read_text())
    if accounting["returncode"]:
        raise RuntimeError(f"iPerf failed ({accounting['returncode']}); inspect {directory}")
    observed = [s for s in samples if s["receiver_cpu_s"] is not None]
    accounting["receiver_cpu_percent_sampled"] = None
    if len(observed) > 1 and observed[-1]["monotonic_s"] > observed[0]["monotonic_s"]:
        accounting["receiver_cpu_percent_sampled"] = 100 * (observed[-1]["receiver_cpu_s"] - observed[0]["receiver_cpu_s"]) / (observed[-1]["monotonic_s"] - observed[0]["monotonic_s"])
    write_json(directory / "accounting.json", accounting)
    return accounting


class Capture:
    def __init__(self, command, interface, port, directory, protocol="udp"):
        self.directory = Path(directory)
        # Immediate delivery prevents losing the last libpcap buffer in sub-second sessions.
        self.command = command + ["--immediate-mode", "-i", interface, "-U", "-s", "160", "-w", "-", protocol, "port", str(port)]

    def __enter__(self):
        self.out = (self.directory / "capture.pcap").open("wb")
        self.err = (self.directory / "capture.log").open("wb")
        write_json(self.directory / "capture-command.json", self.command)
        self.process = subprocess.Popen(self.command, stdout=self.out, stderr=self.err)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.out.close(); self.err.close()
                raise RuntimeError(f"Capture failed: {self.directory / 'capture.log'}")
            if "listening on" in (self.directory / "capture.log").read_text(errors="replace"):
                return self
            time.sleep(.05)
        self.__exit__(None, None, None)
        raise RuntimeError("Capture did not become ready")

    def __exit__(self, *args):
        time.sleep(.1)
        self.process.send_signal(signal.SIGINT)
        try:
            self.process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            self.process.terminate(); self.process.wait(timeout=5)
        finally:
            self.out.close(); self.err.close()
        if self.process.returncode not in (0, -signal.SIGINT, 130):
            raise RuntimeError(f"Capture exited with {self.process.returncode}")


class Receiver:
    def __init__(self, command, directory, local=True):
        self.command = command
        self.directory = Path(directory)
        self.local = local

    def __enter__(self):
        self.out = (self.directory / "receiver.stdout").open("wb")
        self.err = (self.directory / "receiver.stderr").open("wb")
        write_json(self.directory / "receiver-command.json", self.command)
        self.process = subprocess.Popen(self.command, stdout=self.out, stderr=self.err, env=tool_env())
        time.sleep(.3 if self.local else 1)
        if self.process.poll() is not None:
            self.out.close(); self.err.close()
            raise RuntimeError(f"Receiver failed to start: {self.directory}")
        self.pid = self.process.pid if self.local else None
        return self

    def __exit__(self, *args):
        if not self.local and self.process.poll() is None:
            # Let a bounded remote server flush its report before closing SSH.
            try:
                self.process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                pass
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait()
        finally:
            self.out.close(); self.err.close()

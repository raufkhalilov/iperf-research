import contextlib
import hashlib
import itertools
import json
import math
import random
import shlex
import socket
import subprocess
import time
from pathlib import Path
from .common import ROOT, binary, command_info, cpu_pair, require_options, write_csv, write_json
from .control import Capture, Receiver, run_sender
from .environment import inspect
from .metrics import tcp_metrics, udp_metrics
from .pcap import analyze, analyze_tcp


def interval(spec, rng):
    if isinstance(spec, (int, float)):
        if spec < 0:
            raise ValueError("Negative interval")
        return float(spec)
    distribution = spec["distribution"]
    if distribution == "exponential" and spec["mean_s"] > 0:
        return rng.expovariate(1 / spec["mean_s"])
    if distribution == "uniform" and 0 <= spec["min_s"] <= spec["max_s"]:
        return rng.uniform(spec["min_s"], spec["max_s"])
    raise ValueError(f"Invalid interval distribution: {spec}")


def block_size(size):
    if not isinstance(size, int) or size < 1:
        raise ValueError("File size must be a positive integer")
    # Avoid iPerf3 -n overshoot by choosing a block that divides the requested size.
    return next(n for n in range(min(size, 65536), 0, -1) if size % n == 0)


def receiver_command(tool, protocol, port, config, receiver_cpu, packet_size):
    receiver = config.get("receiver", {"mode": "local", "host": "127.0.0.1"})
    mode = receiver.get("mode", "local")
    if mode == "external":
        return None
    executable = binary(tool) if mode == "local" else receiver.get("binaries", {}).get(tool, tool)
    args = [executable, "-s", "-p", str(port)]
    if mode == "local":
        args += ["-B", "127.0.0.1"]
    if tool == "iperf":
        args += ["-u", "-y", "C", "-l", str(packet_size), "-w", str(config.get("socket_buffer_bytes", 1048576))]
    else:
        args += ["-J", "-1"]
    if mode == "local":
        return ["taskset", "-c", str(receiver_cpu)] + args
    if mode == "ssh":
        if tool == "iperf":
            args += ["-t", str(config.get("duration_s", 3) + 5)]
        prefix = ["ssh", "-T", "-oBatchMode=yes", receiver["ssh_host"]]
        return prefix + [shlex.join(args)]
    raise ValueError(f"Unknown receiver mode {mode}")


def receiver_context(tool, protocol, port, config, receiver_cpu, packet_size, directory):
    command = receiver_command(tool, protocol, port, config, receiver_cpu, packet_size)
    if command is None:
        return contextlib.nullcontext(None)
    return Receiver(command, directory, config.get("receiver", {}).get("mode", "local") == "local")


def udp_command(tool, host, port, duration, rate, packet_size, config):
    args = [binary(tool), "-c", host, "-p", str(port), "-u", "-t", str(duration),
            "-b", str(rate), "-l", str(packet_size), "-w", str(config.get("socket_buffer_bytes", 1048576))]
    if tool == "iperf":
        args += ["-y", "C"]
    else:
        args += ["-J", "--pacing-timer", str(config.get("pacing_timer_us", 1000))]
    return args


def validate(config, directory):
    if config.get("cpu_backend", "systemd") not in ("systemd", "none"):
        raise ValueError("Invalid CPU backend")
    for tool in config.get("tools", ["iperf", "iperf3"]):
        required = ["--client", "--server", "--port", "--time", "--len" if tool == "iperf" else "--length", "--window"]
        required += ["--reportstyle", "--isochronous", "--ipg"] if tool == "iperf" else ["--json", "--bytes", "--pacing-timer", "--one-off"]
        require_options(tool, required)
    receiver = config.get("receiver", {})
    host = receiver.get("host", "127.0.0.1")
    address = socket.gethostbyname(host)
    if receiver.get("mode", "local") == "local" and not address.startswith("127."):
        raise ValueError("Local receiver requires IPv4 loopback target")
    if receiver.get("mode") == "ssh":
        probes = {}
        for tool in config.get("tools", ["iperf", "iperf3"]):
            remote = receiver.get("binaries", {}).get(tool, tool)
            probes[tool] = command_info(["ssh", "-T", "-oBatchMode=yes", receiver["ssh_host"], shlex.join([remote, "--help"])])
            text = probes[tool].get("stdout", "") + probes[tool].get("stderr", "")
            needed = ["--server", "--port", "--reportstyle"] if tool == "iperf" else ["--server", "--json", "--one-off"]
            if probes[tool].get("returncode") != 0 or any(x not in text for x in needed):
                write_json(directory / "remote-probes.json", probes)
                raise RuntimeError(f"Remote capability check failed for {tool}")
        write_json(directory / "remote-probes.json", probes)
    sizes = config.get("packet_sizes", [config.get("packet_size", 1200)])
    if any(not isinstance(n, int) or not 64 <= n <= 1400 for n in sizes):
        raise ValueError("Use IPv4 UDP payloads of 64..1400 bytes to avoid typical MTU fragmentation")
    for quota in config.get("cpu_quotas_percent", [config.get("cpu_quota_percent")]):
        if quota is not None and quota not in (25, 50, 100):
            raise ValueError("Supported quotas: null, 100, 50, 25 percent of one logical CPU")


def run_matrix(config, directory, sender_cpu, receiver_cpu):
    rng = random.Random(config.get("seed", 814))
    cases = list(itertools.product(config.get("tools", ["iperf", "iperf3"]),
        config["cpu_quotas_percent"], config["rates_bps"], config["packet_sizes"], range(config.get("repeats", 3))))
    rng.shuffle(cases)
    write_json(directory / "order.json", cases)
    rows = []
    for index, (tool, quota, rate, size, repeat) in enumerate(cases):
        trial = directory / f"trial-{index:03d}"
        trial.mkdir()
        port = config.get("receiver", {}).get("port", config.get("base_port", 16200) + index)
        duration = config.get("duration_s", 3)
        if rate <= 0 or duration < 1:
            raise ValueError("Positive bitrate and duration >= 1 s required")
        host = config.get("receiver", {}).get("host", "127.0.0.1")
        with receiver_context(tool, "udp", port, config, receiver_cpu, size, trial) as receiver:
            accounting = run_sender(udp_command(tool, host, port, duration, rate, size, config), trial,
                sender_cpu, quota, receiver.pid if receiver else None, duration + 20, config.get("cpu_backend", "systemd"))
        row = {"trial": str(trial.relative_to(directory)), "tool": tool, "quota_percent": quota,
               "packet_size": size, "repeat": repeat, "duration_s": duration,
               **udp_metrics(tool, trial, size, rate, accounting)}
        write_json(trial / "metrics.json", row)
        rows.append(row)
        write_json(directory / "results.json", rows)
        write_csv(directory / "results.csv", [{k: v for k, v in row.items() if k != "iperf_internal_cpu"} for row in rows])
        print(f"UDP {index + 1}/{len(cases)}: {tool}, quota={quota}, target={rate}, tx={row['tx_bps']:.0f}", flush=True)
        time.sleep(config.get("cooldown_s", .15))
    return rows


def ipg_unit():
    help_text = require_options("iperf", ["--isochronous", "--ipg"])
    lines = [line for line in help_text.splitlines() if "--ipg" in line]
    if any("milliseconds" in line for line in lines):
        return "milliseconds"
    if any("seconds" in line for line in lines):
        return "seconds"
    raise RuntimeError("Unknown --ipg unit: supply ipg_unit after a capture-based calibration")


def run_onoff(config, directory, sender_cpu, receiver_cpu):
    rng = random.Random(config.get("seed", 814))
    method = config["method"]
    if method not in ("isochronous", "sessions", "burst_probe"):
        raise ValueError("Unknown ON/OFF method")
    size, rate = config["packet_size"], config["on_rate_bps"]
    if rate <= 0 or config["cycles"] < 1:
        raise ValueError("Positive ON bitrate and cycle count required")
    port = config.get("base_port", 16400)
    host = config.get("receiver", {}).get("host", "127.0.0.1")
    command = config.get("capture_command", ["tcpdump"])
    if command and command[0].startswith("scripts/"):
        command = [str(ROOT / command[0])] + command[1:]
    capture_context = Capture(command, config.get("capture_interface", "lo"), port, directory) if command else contextlib.nullcontext()
    events = []
    with receiver_context("iperf", "udp", port, config, receiver_cpu, size, directory) as receiver, capture_context:
        if method in ("isochronous", "burst_probe"):
            if not isinstance(config["on_s"], (float, int)) or not isinstance(config["off_s"], (float, int)):
                raise ValueError("Native periodic modes require fixed ON and OFF durations")
            on, off = config["on_s"], config["off_s"]
            if on <= 0 or off <= 0:
                raise ValueError("ON and OFF must be positive")
            period = on + off
            average = rate * on / period
            gap_s = size * 8 / rate
            if on < 10 * gap_s:
                raise ValueError("At least 10 packets per ON interval required")
            duration = config["cycles"] * period - min(.001, gap_s / 2)
            args = udp_command("iperf", host, port, duration, round(average), size, config)
            if method == "isochronous":
                # iPerf2 2.1.9 rejects -b together with --isochronous or --ipg.
                bitrate_index = args.index("-b")
                del args[bitrate_index:bitrate_index + 2]
                unit = config.get("ipg_unit") or ipg_unit()
                if unit not in ("milliseconds", "seconds"):
                    raise ValueError("ipg_unit must be milliseconds or seconds")
                gap_argument = gap_s * (1000 if unit == "milliseconds" else 1)
                args += [f"--isochronous={1 / period:.12g}:{average:.12g},0", "--ipg", f"{gap_argument:.12g}"]
                write_json(directory / "native-plan.json", {"fps": 1 / period, "mean_bps": average,
                           "target_on_s": on, "target_off_s": off, "ipg_s": gap_s, "ipg_unit": unit,
                           "requested_burst_payload_bytes": rate * on / 8,
                           "approximation": "Packet-quantized native frames, final frame may be partial; verify capture."})
            else:
                # Probe native burst options only after verifying that the parser accepts them.
                probes = {}
                for option, value in [("--burst-period", str(period)), ("--burst-size", str(round(rate * on / 8)))]:
                    probes[option] = command_info([binary("iperf"), option, value, "--help"])
                    text = probes[option].get("stdout", "") + probes[option].get("stderr", "")
                    if any(word in text.lower() for word in ["unrecognized", "unknown option", "invalid option"]):
                        raise RuntimeError(f"Unsupported native option {option}")
                write_json(directory / "burst-option-probes.json", probes)
                # -b is the ON rate for this investigative mode; behavior must be inferred from capture.
                args = udp_command("iperf", host, port, duration, rate, size, config)
                args += ["--burst-period", str(period), "--burst-size", str(round(rate * on / 8))]
            trial = directory / "sender-000"
            accounting = run_sender(args, trial, sender_cpu, config.get("cpu_quota_percent"),
                 receiver.pid if receiver else None, duration + 20, config.get("cpu_backend", "systemd"))
            events.append({"cycle": 0, "requested_on_s": on, "requested_off_s": off, "native_cycles": config["cycles"],
                           "process_wall_s": accounting["process_wall_s"], "sender_cpu_percent": accounting["cpu_percent_one_core"]})
        else:
            for index in range(config["cycles"]):
                on, off = interval(config["on_s"], rng), interval(config["off_s"], rng)
                if on <= 0:
                    raise ValueError("ON duration must be positive")
                trial = directory / f"sender-{index:03d}"
                args = udp_command("iperf", host, port, on, rate, size, config)
                accounting = run_sender(args, trial, sender_cpu, config.get("cpu_quota_percent"),
                     receiver.pid if receiver else None, on + 20, config.get("cpu_backend", "systemd"))
                event = {"cycle": index, "requested_on_s": on, "requested_off_s": off,
                         "process_wall_s": accounting["process_wall_s"], "sender_cpu_percent": accounting["cpu_percent_one_core"],
                         "monotonic_start": accounting["monotonic_start"], "monotonic_end": accounting["monotonic_end"]}
                events.append(event)
                write_json(directory / "events.json", events)
                if index + 1 < config["cycles"]:
                    time.sleep(max(0, accounting["monotonic_end"] + off - time.monotonic()))
    write_json(directory / "events.json", events)
    write_csv(directory / "events.csv", events)
    if command:
        summary = analyze(directory / "capture.pcap", port, size, config.get("gap_threshold_s", .05), directory)
        log = (directory / "capture.log").read_text()
        import re
        match = re.search(r"(\d+) packets dropped by kernel", log)
        summary["capture_dropped_packets"] = int(match[1]) if match else None
        if summary["capture_dropped_packets"] != 0:
            raise RuntimeError("Capture completeness not verified; inspect capture.log")
        write_json(directory / "timing.json", summary)
        print(f"ON/OFF {method}: {summary['burst_count']} observed bursts, {summary['data_packets']} packets", flush=True)
    return events


def run_ftp(config, directory, sender_cpu, receiver_cpu):
    rng = random.Random(config.get("seed", 814))
    rows = []
    reading_times = [interval(config.get("reading_time", {"distribution": "exponential", "mean_s": 5}), rng)
                     for _ in range(max(0, config["transfers"] - 1))]
    write_json(directory / "sampled-reading-times.json", reading_times)
    previous_end = None
    previous_ack_wall = None
    previous_process_end = None
    for index in range(config["transfers"]):
        trial = directory / f"transfer-{index:03d}"
        trial.mkdir()
        size = config.get("file_sizes_bytes", [500000])[index % len(config.get("file_sizes_bytes", [500000]))]
        block = config.get("block_bytes") or block_size(size)
        if block <= 0 or size % block:
            raise ValueError("TCP block size must divide file size to prevent -n overshoot")
        port = config.get("receiver", {}).get("port", config.get("base_port", 16600) + index)
        host = config.get("receiver", {}).get("host", "127.0.0.1")
        # Prepare the receiver before the next transfer; startup time is included in measured launch gaps.
        capture_command = config.get("capture_command", []) if config.get("capture_tcp", False) else []
        if capture_command and capture_command[0].startswith("scripts/"):
            capture_command = [str(ROOT / capture_command[0])] + capture_command[1:]
        capture_context = Capture(capture_command, config.get("capture_interface", "lo"), port, trial, "tcp") if capture_command else contextlib.nullcontext()
        with receiver_context("iperf3", "tcp", port, config, receiver_cpu, 1200, trial) as receiver, capture_context:
            if previous_end is not None:
                time.sleep(max(0, previous_end + reading_times[index - 1] - time.monotonic()))
            args = [binary("iperf3"), "-c", host, "-p", str(port), "-n", str(size), "-l", str(block), "-J", "-i", str(config.get("report_interval_s", .1))]
            accounting = run_sender(args, trial, sender_cpu, config.get("cpu_quota_percent"),
                 receiver.pid if receiver else None, config.get("transfer_timeout_s", 60), config.get("cpu_backend", "systemd"))
        row = {"transfer": index, "block_bytes": block, "reading_time_requested_s": reading_times[index - 1] if index else None,
               "process_completion_to_launch_s": accounting["monotonic_start"] - previous_process_end if previous_process_end else None,
               "completion_reference_to_launch_s": accounting["monotonic_start"] - previous_end if previous_end else None,
               **tcp_metrics(trial, size, accounting)}
        if capture_command:
            timing = analyze_tcp(trial / "capture.pcap", port, size, trial)
            row.update({f"pcap_{key}": timing[key] for key in ["completion_ack_span_s", "emission_span_s", "unique_data_bytes", "acknowledged_goodput_bps"]})
            row["pcap_actual_reading_s"] = timing["request_syn_wall_s"] - previous_ack_wall if previous_ack_wall and timing["request_syn_wall_s"] else None
            previous_ack_wall = timing["completion_ack_wall_s"]
            import re
            match = re.search(r"(\d+) packets dropped by kernel", (trial / "capture.log").read_text())
            if not match or int(match[1]):
                raise RuntimeError(f"TCP capture completeness not verified: {trial}")
        if row["tx_bytes"] != size or row["rx_bytes"] != size:
            raise RuntimeError(f"Transfer size mismatch; inspect {trial}")
        previous_end = accounting["monotonic_end"]
        previous_process_end = accounting["monotonic_end"]
        if previous_ack_wall:
            previous_end = previous_ack_wall + time.monotonic() - time.time()
        row["reading_reference"] = "captured_previous_file_ack" if previous_ack_wall else "previous_iperf_process_exit"
        write_json(trial / "metrics.json", row)
        rows.append(row)
        write_json(directory / "results.json", rows)
        write_csv(directory / "results.csv", rows)
        print(f"TCP {index + 1}/{config['transfers']}: {size} bytes, {row['transfer_seconds']:.6f}s", flush=True)
    return rows


def run(config_path, output):
    config_path, output = Path(config_path), Path(output).resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError(f"Output is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    config = json.loads(config_path.read_text())
    write_json(output / "config.json", config)
    tracked = [p for folder in ["netperf_lab", "scripts", "tests", "configs"] for p in (ROOT / folder).rglob("*")
               if p.is_file() and "__pycache__" not in p.parts]
    write_json(output / "source-hashes.json", {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(tracked)})
    inspect(output / "environment")
    sender_cpu, receiver_cpu = cpu_pair()
    sender_cpu = config.get("sender_cpu", sender_cpu)
    receiver_cpu = config.get("receiver_cpu", receiver_cpu)
    if sender_cpu == receiver_cpu:
        raise ValueError("Sender and receiver must use different CPUs")
    write_json(output / "placement.json", {"sender_cpu": sender_cpu, "receiver_cpu": receiver_cpu,
               "unrestricted_definition": "No cgroup quota; sender affinity remains one logical CPU in all cases"})
    scenarios = config.get("scenarios", [config])
    dispatch = {"udp_matrix": run_matrix, "onoff": run_onoff, "ftp": run_ftp}
    for index, scenario in enumerate(scenarios):
        effective = {**config, **scenario}
        effective.pop("scenarios", None)
        directory = output / scenario.get("name", f"scenario-{index:02d}")
        directory.mkdir()
        write_json(directory / "config.json", effective)
        try:
            validate(effective, directory)
            dispatch[effective["kind"]](effective, directory, sender_cpu, receiver_cpu)
            write_json(directory / "status.json", {"status": "complete"})
        except Exception as exc:
            write_json(directory / "status.json", {"status": "failed", "error": str(exc)})
            raise
    write_json(output / "status.json", {"status": "complete"})

import csv
import json
import math
from pathlib import Path


def iperf2_rows(text):
    rows = []
    for line in text.splitlines():
        fields = next(csv.reader([line]))
        if len(fields) < 9:
            continue
        try:
            start, end = map(float, fields[6].split("-"))
            row = {"start": start, "end": end, "seconds": end - start,
                   "bytes": int(fields[7]), "bits_per_second": float(fields[8])}
            if len(fields) >= 13:
                row.update(lost_packets=int(fields[10]), packets=int(fields[11]), lost_percent=float(fields[12]))
            rows.append(row)
        except (ValueError, IndexError):
            continue
    return rows


def udp_metrics(tool, directory, packet_size, target, accounting):
    directory = Path(directory)
    if tool == "iperf3":
        data = json.loads((directory / "client.stdout").read_text())
        if "error" in data:
            raise RuntimeError(data["error"])
        tx = data["end"]["sum_sent"]
        rx = data["end"]["sum_received"]
        cpu_internal = data["end"].get("cpu_utilization_percent")
    else:
        send = iperf2_rows((directory / "client.stdout").read_text())
        receive = iperf2_rows((directory / "receiver.stdout").read_text()) if (directory / "receiver.stdout").exists() else []
        if not send:
            raise RuntimeError(f"No iPerf2 sender CSV in {directory}")
        tx = max(send, key=lambda x: x["seconds"])
        rx = max(receive, key=lambda x: x["seconds"]) if receive else None
        cpu_internal = None
    metrics = {"tx_bps": tx["bits_per_second"], "tx_bytes": tx["bytes"], "tx_seconds": tx["seconds"],
               "tx_pps": tx["bytes"] / packet_size / tx["seconds"],
               "rx_bps": rx["bits_per_second"] if rx else None,
               "loss_percent": rx.get("lost_percent") if rx else None,
               "lost_packets": rx.get("lost_packets") if rx else None,
               "rx_pps": (rx["packets"] - rx.get("lost_packets", 0)) / rx["seconds"] if rx else None,
               "target_bps": target, "deviation_percent": 100 * (tx["bits_per_second"] / target - 1),
               "sender_cpu_percent": accounting["cpu_percent_one_core"],
               "receiver_cpu_percent": accounting["receiver_cpu_percent_sampled"],
               "iperf_internal_cpu": cpu_internal}
    # iPerf2 CSV interval endpoints are rounded to 0.1 s; its bps field is more precise.
    if tool == "iperf":
        metrics["tx_pps"] = tx["bits_per_second"] / (packet_size * 8)
        if rx:
            metrics["rx_pps"] = rx["bits_per_second"] / (packet_size * 8)
    cpu_stat = accounting["cgroup_after"].get("cpu.stat") or ""
    before = accounting["cgroup_before"].get("cpu.stat") or ""
    baseline = {k: int(v) for k, v in (line.split() for line in before.splitlines())}
    values = {k: int(v) for k, v in (line.split() for line in cpu_stat.splitlines())}
    metrics.update({f"cgroup_{k}": values[k] - baseline.get(k, 0) if k in values else None
                    for k in ["nr_periods", "nr_throttled", "throttled_usec"]})
    return metrics


def tcp_metrics(directory, requested_bytes, accounting):
    data = json.loads((Path(directory) / "client.stdout").read_text())
    if "error" in data:
        raise RuntimeError(data["error"])
    tx, rx = data["end"]["sum_sent"], data["end"]["sum_received"]
    return {"requested_bytes": requested_bytes, "tx_bytes": tx["bytes"], "rx_bytes": rx["bytes"],
            "size_error_bytes": tx["bytes"] - requested_bytes,
            "transfer_seconds": tx["seconds"], "tx_bps": tx["bits_per_second"],
            "rx_bps": rx["bits_per_second"], "retransmits": tx.get("retransmits"),
            "process_wall_s": accounting["process_wall_s"], "sender_cpu_s": accounting["cpu_s"],
            "sender_cpu_percent": accounting["cpu_percent_one_core"],
            "receiver_cpu_percent": accounting["receiver_cpu_percent_sampled"]}

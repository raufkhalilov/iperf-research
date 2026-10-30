import collections
import csv
import json
import hashlib
import statistics
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from .common import ROOT, write_csv, write_json


def aggregate(rows):
    grouped = collections.defaultdict(list)
    for row in rows:
        grouped[(row["tool"], row["quota_percent"], row["target_bps"], row["packet_size"])].append(row)
    summary = []
    for (tool, quota, target, size), samples in grouped.items():
        row = {"tool": tool, "quota_percent": quota, "target_bps": target, "packet_size": size, "n": len(samples)}
        for field in ["tx_bps", "rx_bps", "tx_pps", "rx_pps", "sender_cpu_percent", "receiver_cpu_percent", "loss_percent", "deviation_percent", "cgroup_nr_throttled", "cgroup_throttled_usec"]:
            values = [s[field] for s in samples if s.get(field) is not None]
            if values:
                row[field + "_mean"] = statistics.mean(values)
                row[field + "_sd"] = statistics.stdev(values) if len(values) > 1 else 0
                row[field + "_min"] = min(values)
                row[field + "_max"] = max(values)
        summary.append(row)
    return sorted(summary, key=lambda x: (x["target_bps"], x["packet_size"], x["tool"], -1 if x["quota_percent"] is None else -x["quota_percent"]))


def save_figure(fig, base):
    fig.savefig(str(base) + ".png", dpi=170)
    fig.savefig(str(base) + ".svg")
    plt.close(fig)


def udp_figures(directory, summary):
    figures = directory / "figures"
    figures.mkdir(exist_ok=True)
    quotas = [None, 100, 50, 25]
    labels = ["Без квоты", "100%", "50%", "25%"]
    for target, size in sorted({(x["target_bps"], x["packet_size"]) for x in summary}):
        fig, axes = plt.subplots(1, 4, figsize=(15, 4.2), layout="constrained")
        for tool, color in [("iperf", "#2456a6"), ("iperf3", "#d07717")]:
            rows = [next((s for s in summary if s["target_bps"] == target and s["packet_size"] == size and s["tool"] == tool and s["quota_percent"] == q), None) for q in quotas]
            for ax, field, divisor, ylabel in zip(axes,
                 ["tx_bps", "sender_cpu_percent", "tx_pps", "loss_percent"],
                 [1e6, 1, 1000, 1], ["Отправлено, Мбит/с", "CPU отправителя, % ядра", "Отправлено, тыс. пакетов/с", "Потери на приёмнике, %"]):
                points = [(i, r) for i, r in enumerate(rows) if r and field + "_mean" in r]
                if points:
                    ax.errorbar([i for i, r in points], [r[field + "_mean"] / divisor for i, r in points],
                                yerr=[r[field + "_sd"] / divisor for i, r in points], marker="o", capsize=3, color=color,
                                label="iPerf2" if tool == "iperf" else "iPerf3")
                ax.set_xticks(range(4), labels, rotation=15)
                ax.set_ylabel(ylabel)
                ax.grid(alpha=.25)
        axes[0].axhline(target / 1e6, color="gray", linestyle="--", label="Цель")
        axes[0].legend(fontsize=8)
        axes[1].plot(range(1, 4), [100, 50, 25], "k:", alpha=.4)
        for ax in axes:
            ax.relim()
            ax.autoscale_view()
            ax.set_ylim(bottom=0)
        fig.suptitle(f"UDP payload {size} байт, цель {target / 1e6:g} Мбит/с; среднее ± SD, n={summary[0]['n']}")
        save_figure(fig, figures / f"udp-{int(target)}-{size}")
    # Receiver throughput and CPU are kept separate to expose bottleneck ambiguity.
    fig, axes = plt.subplots(1, 2, figsize=(10, 4), layout="constrained")
    for tool, color in [("iperf", "#2456a6"), ("iperf3", "#d07717")]:
        rows = [x for x in summary if x["tool"] == tool and "rx_bps_mean" in x]
        axes[0].scatter([x["tx_bps_mean"] / 1e6 for x in rows], [x["rx_bps_mean"] / 1e6 for x in rows], color=color, label=tool, alpha=.7)
        rows = [x for x in rows if "receiver_cpu_percent_mean" in x]
        axes[1].scatter([x["tx_pps_mean"] / 1000 for x in rows], [x["receiver_cpu_percent_mean"] for x in rows], color=color, alpha=.7)
    axes[0].set(xlabel="TX payload, Мбит/с", ylabel="RX payload, Мбит/с")
    axes[1].set(xlabel="TX, тыс. пакетов/с", ylabel="CPU приёмника, % ядра")
    axes[0].legend()
    for ax in axes:
        ax.grid(alpha=.25)
    save_figure(fig, figures / "receiver-diagnostics")


def timing_figure(directory):
    with (directory / "timeline.csv").open() as f:
        timeline = list(csv.DictReader(f))
    with (directory / "packets.csv").open() as f:
        packets = list(csv.DictReader(f))
    fig, axes = plt.subplots(2, 1, figsize=(10, 5), layout="constrained")
    axes[0].step([float(x["time_s"]) for x in timeline], [float(x["payload_bps"]) / 1e6 for x in timeline], where="post")
    axes[0].set(ylabel="UDP payload, Мбит/с", title=directory.name)
    points = [x for x in packets if x["gap_s"] and float(x["gap_s"]) > 0]
    axes[1].scatter([float(x["relative_s"]) for x in points], [float(x["gap_s"]) * 1000 for x in points], s=3)
    axes[1].set(yscale="log", xlabel="От первого data-пакета, с", ylabel="Межпакетный интервал, мс")
    for ax in axes:
        ax.grid(alpha=.25)
    save_figure(fig, directory / "timing")


def ftp_figure(directory, rows):
    fig, axes = plt.subplots(1, 3, figsize=(13, 4), layout="constrained")
    x = [r["transfer"] + 1 for r in rows]
    axes[0].plot(x, [r["transfer_seconds"] * 1000 for r in rows], "o-", label="Отчёт iPerf3")
    axes[0].plot(x, [r["process_wall_s"] * 1000 for r in rows], "o-", label="Процесс iPerf3")
    if all(r.get("pcap_completion_ack_span_s") is not None for r in rows):
        axes[0].plot(x, [r["pcap_completion_ack_span_s"] * 1000 for r in rows], "o-", label="PCAP: данные → ACK")
    axes[0].set(ylabel="Длительность, мс", xlabel="Передача", yscale="log")
    axes[0].legend(fontsize=8)
    axes[1].plot(x[1:], [r["reading_time_requested_s"] for r in rows[1:]], "o-", label="Выборка D")
    axes[1].plot(x[1:], [r["process_completion_to_launch_s"] for r in rows[1:]], "x--", label="Фактический промежуток процессов")
    if all(r.get("pcap_actual_reading_s") is not None for r in rows[1:]):
        axes[1].plot(x[1:], [r["pcap_actual_reading_s"] for r in rows[1:]], "s:", label="PCAP: ACK → запрос")
    axes[1].set(ylabel="Пауза, с", xlabel="Следующая передача")
    axes[1].legend(fontsize=8)
    axes[2].bar(x, [r["sender_cpu_s"] * 1000 for r in rows])
    axes[2].set(ylabel="CPU отправителя, мс", xlabel="Передача")
    for ax in axes:
        ax.grid(alpha=.25)
    fig.suptitle(directory.name)
    save_figure(fig, directory / "transfers")


def analyze_all(root):
    root = Path(root)
    write_json(root / "postprocessing-source-hashes.json", {
        str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in [ROOT / "netperf_lab/analysis.py", ROOT / "scripts/audit_results.py"] if p.exists()})
    for config_file in sorted(root.glob("*/config.json")):
        directory = config_file.parent
        config = json.loads(config_file.read_text())
        if config["kind"] == "udp_matrix" and (directory / "results.json").exists():
            rows = json.loads((directory / "results.json").read_text())
            summary = aggregate(rows)
            write_json(directory / "summary.json", summary)
            write_csv(directory / "summary.csv", summary)
            udp_figures(directory, summary)
        elif config["kind"] == "onoff" and (directory / "timeline.csv").exists():
            timing_figure(directory)
        elif config["kind"] == "ftp" and (directory / "results.json").exists():
            ftp_figure(directory, json.loads((directory / "results.json").read_text()))
    print(f"Processed results and figures saved: {root}")

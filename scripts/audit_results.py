#!/usr/bin/env python3
"""Audit measured artifacts without starting network traffic."""
import collections
import hashlib
import itertools
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from netperf_lab.common import ROOT, write_csv, write_json


def udp_counters(text):
    lines = [line.split() for line in text.splitlines() if line.startswith("Udp:")]
    return dict(zip(lines[0][1:], map(int, lines[1][1:]))) if len(lines) == 2 else {}


def audit(root):
    checks = []
    diagnostics = []
    def check(name, condition, detail=None):
        checks.append({"check": name, "passed": bool(condition), "detail": detail})
    check("root_complete", json.loads((root / "status.json").read_text())["status"] == "complete")
    hashes = json.loads((root / "source-hashes.json").read_text())
    changed = [name for name, expected in hashes.items() if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != expected]
    check("recorded_generation_sources_unchanged", not [p for p in changed if p != "netperf_lab/analysis.py"], changed)
    if (root / "postprocessing-source-hashes.json").exists():
        processing = json.loads((root / "postprocessing-source-hashes.json").read_text())
        check("postprocessing_sources_unchanged", all(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == value for name, value in processing.items()))
    for cfg_path in sorted(root.glob("*/config.json")):
        directory = cfg_path.parent
        config = json.loads(cfg_path.read_text())
        check(f"{directory.name}:complete", json.loads((directory / "status.json").read_text())["status"] == "complete")
        if config["kind"] == "udp_matrix":
            rows = json.loads((directory / "results.json").read_text())
            expected = len(config.get("tools", ["iperf", "iperf3"])) * len(config["cpu_quotas_percent"]) * len(config["rates_bps"]) * len(config["packet_sizes"]) * config["repeats"]
            check(f"{directory.name}:trial_count", len(rows) == expected, len(rows))
            cases = collections.Counter((r["tool"], r["quota_percent"], r["target_bps"], r["packet_size"], r["repeat"]) for r in rows)
            check(f"{directory.name}:unique_repeats", all(n == 1 for n in cases.values()) and len(cases) == expected)
            for row in rows:
                trial = directory / row["trial"]
                account = json.loads((trial / "sender-accounting.json").read_text())
                meta = json.loads((trial / "sender-metadata.json").read_text())
                quota = row["quota_percent"]
                if quota is not None:
                    value, period = map(int, meta["cgroup_before"]["cpu.max"].split())
                    check(f"{directory.name}/{row['trial']}:quota", abs(100 * value / period - quota) < .01)
                    check(f"{directory.name}/{row['trial']}:cpu_budget", row["sender_cpu_percent"] < quota + 5, row["sender_cpu_percent"])
                check(f"{directory.name}/{row['trial']}:affinity", len(meta["affinity"]) == 1)
                check(f"{directory.name}/{row['trial']}:successful_sender", account["returncode"] == 0)
                before = udp_counters(json.loads((trial / "host-before.json").read_text())["snmp"])
                after = udp_counters(json.loads((trial / "host-after.json").read_text())["snmp"])
                diag = {k: row[k] for k in ["trial", "tool", "quota_percent", "target_bps", "packet_size", "loss_percent", "sender_cpu_percent", "receiver_cpu_percent"]}
                diag.update({"host_udp_" + key + "_delta": after[key] - value for key, value in before.items() if key in after})
                diagnostics.append(diag)
        elif config["kind"] == "ftp":
            rows = json.loads((directory / "results.json").read_text())
            check(f"{directory.name}:transfer_count", len(rows) == config["transfers"])
            check(f"{directory.name}:exact_sizes", all(r["requested_bytes"] == r["tx_bytes"] == r["rx_bytes"] for r in rows))
            if config.get("capture_tcp"):
                check(f"{directory.name}:complete_capture", all(r.get("pcap_unique_data_bytes") == r["requested_bytes"] for r in rows))
                check(f"{directory.name}:final_ack", all(r.get("pcap_completion_ack_span_s") is not None for r in rows))
                check(f"{directory.name}:reading_schedule", all(r.get("pcap_actual_reading_s", -1) + .001 >= r["reading_time_requested_s"] for r in rows[1:]))
        elif config["kind"] == "onoff" and (directory / "timing.json").exists():
            timing = json.loads((directory / "timing.json").read_text())
            check(f"{directory.name}:capture_no_drops", timing["capture_dropped_packets"] == 0)
            if config["method"] == "sessions":
                check(f"{directory.name}:session_bursts", timing["burst_count"] == config["cycles"], timing["burst_count"])
    write_csv(root / "host-udp-diagnostics.csv", diagnostics)
    write_json(root / "verification.json", {"checks": checks, "passed": all(x["passed"] for x in checks),
               "audit_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               "host_counter_note": "Host-wide counters include unrelated traffic; deltas alone do not identify the experiment socket."})
    failed = [x for x in checks if not x["passed"]]
    print(f"Audit: {len(checks) - len(failed)}/{len(checks)} passed; details: {root / 'verification.json'}")
    return bool(failed)


if __name__ == "__main__":
    sys.exit(audit(Path(sys.argv[1])))

"""Small classic-PCAP IPv4/UDP decoder; no Scapy dependency."""
import collections
import math
import statistics
import struct
from pathlib import Path
from .common import write_csv, write_json


def packets(path, protocol="udp"):
    with Path(path).open("rb") as f:
        header = f.read(24)
        formats = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
                   b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}
        if len(header) != 24 or header[:4] not in formats:
            raise ValueError("Expected classic PCAP with complete global header")
        endian, resolution = formats[header[:4]]
        linktype = struct.unpack(endian + "I", header[20:24])[0]
        if linktype not in (1, 113, 276, 101, 0):
            raise ValueError(f"Unsupported PCAP linktype {linktype}")
        while record := f.read(16):
            if len(record) != 16:
                raise ValueError("Truncated PCAP record header")
            sec, fraction, incl, original = struct.unpack(endian + "IIII", record)
            data = f.read(incl)
            if len(data) != incl:
                raise ValueError("Truncated PCAP packet")
            if linktype == 1:
                if len(data) < 14:
                    continue
                kind = struct.unpack("!H", data[12:14])[0]
                offset = 14
                while kind in (0x8100, 0x88a8):
                    kind = struct.unpack("!H", data[offset + 2:offset + 4])[0]
                    offset += 4
                if kind != 0x0800:
                    continue
            elif linktype == 113:
                if len(data) < 16 or data[14:16] != b"\x08\x00":
                    continue
                offset = 16
            elif linktype == 276:
                if len(data) < 20 or data[:2] != b"\x08\x00":
                    continue
                offset = 20
            else:
                offset = 0 if linktype == 101 else 4
            ip = data[offset:]
            if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != (17 if protocol == "udp" else 6):
                continue
            fragment = struct.unpack("!H", ip[6:8])[0]
            if fragment & 0x3fff:
                raise ValueError("Fragmented IPv4 datagram; reduce UDP payload size")
            ip_header_bytes = (ip[0] & 15) * 4
            udp = ip[ip_header_bytes:]
            if protocol == "tcp":
                if len(udp) < 20:
                    continue
                sport, dport, seq, ack = struct.unpack("!HHII", udp[:12])
                payload = struct.unpack("!H", ip[2:4])[0] - ip_header_bytes - (udp[12] >> 4) * 4
                yield {"timestamp": sec + fraction * resolution, "source_port": sport, "destination_port": dport,
                       "sequence": seq, "ack": ack, "flags": udp[13], "tcp_payload_bytes": payload}
                continue
            if len(udp) < 12:
                continue
            sport, dport, length, _ = struct.unpack("!HHHH", udp[:8])
            yield {"timestamp": sec + fraction * resolution, "source_port": sport,
                   "destination_port": dport, "udp_payload_bytes": length - 8,
                   "sequence": struct.unpack("!i", udp[8:12])[0]}


def quantiles(values):
    if not values:
        return {"count": 0}
    values = sorted(values)
    def percentile(p):
        pos = p * (len(values) - 1)
        lo = math.floor(pos)
        hi = math.ceil(pos)
        return values[lo] + (values[hi] - values[lo]) * (pos - lo)
    return {"count": len(values), "min": values[0], "p50": percentile(.5),
            "p95": percentile(.95), "p99": percentile(.99), "max": values[-1]}


def analyze(path, port, packet_size, gap_threshold_s, output, bin_s=.01):
    output = Path(output)
    data = [p for p in packets(path) if p["destination_port"] == port
            and p["udp_payload_bytes"] == packet_size and p["sequence"] > 0]
    if not data:
        raise RuntimeError("Capture contains no matching iPerf2 data packets")
    data.sort(key=lambda p: p["timestamp"])
    origin = data[0]["timestamp"]
    previous = None
    groups = [[]]
    for p in data:
        p["relative_s"] = p["timestamp"] - origin
        p["gap_s"] = p["timestamp"] - previous["timestamp"] if previous else None
        if previous and (p["gap_s"] > gap_threshold_s or p["source_port"] != previous["source_port"]):
            groups.append([])
        p["burst"] = len(groups) - 1
        groups[-1].append(p)
        previous = p
    bursts = []
    for index, group in enumerate(groups):
        span = group[-1]["timestamp"] - group[0]["timestamp"]
        bursts.append({"burst": index, "first_s": group[0]["relative_s"], "last_s": group[-1]["relative_s"],
                       "span_s": span, "packets": len(group), "payload_bytes": len(group) * packet_size,
                       "next_gap_s": groups[index + 1][0]["timestamp"] - group[-1]["timestamp"] if index + 1 < len(groups) else None})
    within = [p["gap_s"] for g in groups for p in g[1:]]
    between = [g["next_gap_s"] for g in bursts if g["next_gap_s"] is not None]
    bins = collections.Counter(int(p["relative_s"] / bin_s) for p in data)
    timeline = [{"time_s": i * bin_s, "payload_bps": bins[i] * packet_size * 8 / bin_s, "packets": bins[i]}
                for i in range(max(bins) + 1)]
    summary = {"data_packets": len(data), "burst_count": len(bursts), "gap_threshold_s": gap_threshold_s,
               "within_gap_s": quantiles(within), "between_gap_s": quantiles(between),
               "burst_span_s": quantiles([x["span_s"] for x in bursts]),
               "burst_start_period_s": quantiles([b["first_s"] - a["first_s"] for a, b in zip(bursts, bursts[1:])]),
               "interpretation": "Sender-side loopback timestamps; positive sequence and exact payload-size filter. No wire or receiver timing claim."}
    write_csv(output / "packets.csv", data)
    write_csv(output / "bursts.csv", bursts)
    write_csv(output / "timeline.csv", timeline)
    write_json(output / "timing.json", summary)
    return summary


def analyze_tcp(path, port, requested_bytes, output):
    records = list(packets(path, "tcp"))
    flows = collections.defaultdict(list)
    for p in records:
        if p["destination_port"] == port and p["tcp_payload_bytes"] > 0:
            flows[p["source_port"]].append(p)
    if not flows:
        raise RuntimeError("No TCP payload captured")
    source, flow = max(flows.items(), key=lambda kv: sum(x["tcp_payload_bytes"] for x in kv[1]))
    # iPerf3 sends a 37-byte cookie on the data connection before the test payload.
    base = flow[0]["sequence"]
    data = []
    intervals = []
    for p in flow:
        start = (p["sequence"] - base) % (2**32)
        end = start + p["tcp_payload_bytes"]
        left, right = max(37, start), min(37 + requested_bytes, end)
        if left < right:
            data.append(p)
            intervals.append((left, right))
    merged = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(end, merged[-1][1])
        else:
            merged.append([start, end])
    unique_bytes = sum(b - a for a, b in merged)
    if unique_bytes != requested_bytes or not data:
        raise RuntimeError(f"Incomplete TCP capture: {unique_bytes}/{requested_bytes} payload bytes")
    first, last = min(x["timestamp"] for x in data), max(x["timestamp"] for x in data)
    acks = [x["timestamp"] for x in records if x["source_port"] == port and x["destination_port"] == source
            and x["flags"] & 16 and 37 + requested_bytes <= (x["ack"] - base) % (2**32) < 2**31
            and x["timestamp"] >= first]
    ack_span = min(acks) - first if acks else None
    result = {"unique_data_bytes": unique_bytes, "data_packets": len(data), "emission_span_s": last - first,
              "completion_ack_span_s": ack_span,
              "completion_ack_wall_s": min(acks) if acks else None,
              "request_syn_wall_s": min((x["timestamp"] for x in records if x["destination_port"] == port and x["flags"] & 2), default=None),
              "acknowledged_goodput_bps": requested_bytes * 8 / ack_span if ack_span and ack_span > 0 else None,
              "first_data_wall_s": first, "last_data_wall_s": last,
              "interpretation": "Sender capture: first file-data packet to first cumulative ACK covering the file; includes retransmission time. Excludes TCP setup and iPerf3 control teardown. Loopback offloads remain enabled."}
    write_csv(Path(output) / "tcp-packets.csv", records)
    write_json(Path(output) / "tcp-timing.json", result)
    return result

import struct
import tempfile
import unittest
from pathlib import Path
from netperf_lab.pcap import analyze_tcp


def tcp_packet(seq, ack, flags, length, source=1234, destination=5001):
    tcp = struct.pack("!HHIIBBHHH", source, destination, seq % 2**32, ack % 2**32, 5 << 4, flags, 65535, 0, 0) + bytes(length)
    ip = struct.pack("!BBHHHBBHII", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0, 0x7f000001, 0x7f000001)
    return bytes(12) + b"\x08\x00" + ip + tcp


class TcpCaptureTests(unittest.TestCase):
    def test_retransmission_wraparound_and_cumulative_ack(self):
        base = 0xffffffd0
        frames = [
            tcp_packet(base - 1, 0, 2, 0),
            tcp_packet(base, 0, 24, 37),
            tcp_packet(base + 37, 0, 24, 500),
            tcp_packet(base + 37, 0, 24, 500),
            tcp_packet(base + 537, 0, 24, 500),
            tcp_packet(42, base + 1037, 16, 0, source=5001, destination=1234),
        ]
        header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        content = header + b"".join(struct.pack("<IIII", 100, i * 1000, len(frame), len(frame)) + frame for i, frame in enumerate(frames))
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            path = directory / "capture.pcap"
            path.write_bytes(content)
            result = analyze_tcp(path, 5001, 1000, directory)
            self.assertEqual(result["unique_data_bytes"], 1000)
            self.assertEqual(result["data_packets"], 3)
            self.assertAlmostEqual(result["completion_ack_span_s"], .003)
            self.assertAlmostEqual(result["request_syn_wall_s"], 100)
            with self.assertRaises(RuntimeError):
                analyze_tcp(path, 5001, 1001, directory)


if __name__ == "__main__":
    unittest.main()

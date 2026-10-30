import io
import random
import struct
import tempfile
import unittest
from pathlib import Path
from netperf_lab.experiments import block_size, interval
from netperf_lab.metrics import iperf2_rows
from netperf_lab.pcap import packets


class ResearchTests(unittest.TestCase):
    def test_iperf2_sender_sentinel_and_receiver(self):
        text = "noise\n20261028,127.0.0.1,1,127.0.0.1,2,1,0.0-2.0,120000,480000,-nan,0,-1,-0.000,0\n"
        row = iperf2_rows(text)[0]
        self.assertEqual(row["packets"], -1)
        self.assertEqual(row["bits_per_second"], 480000)
        receiver = iperf2_rows(text.replace("-nan,0,-1,-0.000", "0.001,2,102,1.961"))[0]
        self.assertEqual(receiver["lost_packets"], 2)

    def test_pcap_nanosecond_and_control_filter_inputs(self):
        ethernet = b"\x00" * 12 + b"\x08\x00"
        ip = b"\x45\x00" + struct.pack("!H", 44) + b"\x00" * 5 + b"\x11" + b"\x00" * 10
        udp = struct.pack("!HHHH", 1234, 5001, 24, 0) + struct.pack("!i", 7) + b"\x00" * 12
        body = ethernet + ip + udp
        header = struct.pack("<IHHIIII", 0xa1b23c4d, 2, 4, 0, 0, 160, 1)
        record = struct.pack("<IIII", 100, 123456789, len(body), len(body))
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "test.pcap"
            path.write_bytes(header + record + body)
            row = list(packets(path))[0]
            self.assertAlmostEqual(row["timestamp"], 100.123456789)
            self.assertEqual(row["sequence"], 7)
            self.assertEqual(row["udp_payload_bytes"], 16)
            path.write_bytes(header + record + body[:-1])
            with self.assertRaises(ValueError):
                list(packets(path))

    def test_exponential_reading_times_and_seed(self):
        spec = {"distribution": "exponential", "mean_s": 5}
        rng = random.Random(814)
        values = [interval(spec, rng) for _ in range(20000)]
        self.assertTrue(all(x >= 0 for x in values))
        self.assertAlmostEqual(sum(values) / len(values), 5, delta=.15)
        self.assertEqual(values[0], interval(spec, random.Random(814)))

    def test_exact_byte_blocks(self):
        for n in [1, 17, 500000, 5000000, 50000000]:
            b = block_size(n)
            self.assertEqual(n % b, 0)
            self.assertLessEqual(b, 65536)
        with self.assertRaises(ValueError):
            block_size(0)


if __name__ == "__main__":
    unittest.main()

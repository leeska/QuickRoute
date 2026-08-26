import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import quickroute_lib as qr


def trace(*asns):
    lines = [f"traceroute to example (1.1.1.1), 30 hops max"]
    for index, asn in enumerate(asns, 1):
        lines.append(f"{index}  192.0.2.{index}  AS{asn}  1.{index} ms")
    return "\n".join(lines)


class ParseTests(unittest.TestCase):
    def test_parse_text_and_preserve_ecmp_ttl(self):
        text = """
traceroute to x (1.1.1.1), 30 hops max
 1  10.0.0.1  AS64512  0.30 ms
 2  * * *
 3  59.43.1.1 (59.43.1.1) AS4809  22.5 ms
 3  59.43.1.2 AS4809 23.0 ms
"""
        hops = qr.parse_nexttrace(text)
        self.assertEqual([h.number for h in hops], [1, 2, 3, 3])
        self.assertEqual(hops[0].asn, 64512)
        self.assertIsNone(hops[1].ip)
        self.assertEqual(hops[2].asn, 4809)
        self.assertEqual(hops[2].latency_ms, 22.5)
        self.assertEqual(hops[3].ip, "59.43.1.2")

    def test_ignores_header_address(self):
        hops = qr.parse_nexttrace("66.187.6.8 -> 1.1.1.1, 24 hops max\n1 203.0.113.1 AS4134 5 ms")
        self.assertEqual(len(hops), 1)

    def test_latency_on_following_line(self):
        hops = qr.parse_nexttrace("1   203.0.113.1 AS4134 provider\n    12.34 ms")
        self.assertEqual(hops[0].latency_ms, 12.34)


class ClassificationTests(unittest.TestCase):
    def classify(self, *asns):
        return qr.classify_route(qr.parse_nexttrace(trace(*asns)))

    def test_163(self):
        self.assertEqual(self.classify(3356, 4134)[:2], ("163", "AS3356"))

    def test_cn2_gia(self):
        self.assertEqual(self.classify(1299, 4809, 4809)[0], "CN2 GIA")

    def test_cn2_gt(self):
        self.assertEqual(self.classify(1299, 4809, 4134)[0], "CN2 GT")

    def test_ctg_gia(self):
        self.assertEqual(self.classify(1299, 23764, 4809)[0], "CTG GIA")

    def test_unicom(self):
        self.assertEqual(self.classify(174, 4837)[0], "4837")
        self.assertEqual(self.classify(174, 9929)[0], "9929")
        self.assertEqual(self.classify(174, 10099, 9929)[0], "10099→9929")

    def test_mobile(self):
        self.assertEqual(self.classify(1299, 9808)[0], "CMI")
        self.assertEqual(self.classify(1299, 58807)[0], "CMIN2")
        self.assertEqual(self.classify(1299, 58807, 9808)[0], "CMIN2→CMI")

    def test_education(self):
        self.assertEqual(self.classify(6939, 4538)[0], "CERNET")
        self.assertEqual(self.classify(6939, 23910)[0], "CERNET2")
        self.assertEqual(self.classify(6939, 7497)[0], "CSTNET")

    def test_hidden_and_empty(self):
        self.assertEqual(self.classify(3356)[0], "Hidden")
        self.assertEqual(qr.classify_route([]), ("Unknown", "-", "error"))


class DownloadTests(unittest.TestCase):
    def test_asset_selection(self):
        digest = "sha256:" + "a" * 64
        release = {"assets": [{"name": "nexttrace-tiny_linux_amd64", "digest": digest, "browser_download_url": "https://example.test/x"}]}
        self.assertEqual(qr.select_release_asset(release, "x86_64")["digest"], digest)

    def test_asset_requires_digest(self):
        release = {"assets": [{"name": "nexttrace-tiny_linux_amd64", "browser_download_url": "x"}]}
        with self.assertRaises(RuntimeError):
            qr.select_release_asset(release, "amd64")

    def test_unknown_arch(self):
        with self.assertRaises(RuntimeError):
            qr.select_release_asset({"assets": []}, "mystery")

    def test_digest(self):
        data = b"quickroute"
        qr.verify_digest(data, "sha256:" + hashlib.sha256(data).hexdigest())
        with self.assertRaises(RuntimeError):
            qr.verify_digest(data, "sha256:" + "0" * 64)

    @mock.patch("quickroute_lib.platform.machine", return_value="x86_64")
    @mock.patch("quickroute_lib._bytes_url")
    @mock.patch("quickroute_lib._json_url")
    @mock.patch("quickroute_lib.shutil.which", return_value=None)
    def test_download_to_cache(self, _which, json_url, bytes_url, _machine):
        data = b"binary"
        json_url.return_value = {
            "tag_name": "v-test",
            "assets": [{
                "name": "nexttrace-tiny_linux_amd64",
                "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
                "browser_download_url": "https://example.test/bin",
            }],
        }
        bytes_url.return_value = data
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict("os.environ", {"XDG_CACHE_HOME": directory}, clear=False):
            path = Path(qr.ensure_nexttrace())
            self.assertEqual(path.read_bytes(), data)
            self.assertTrue(path.stat().st_mode & 0o100)
            path.write_bytes(b"tampered")
            path.chmod(0o700)
            bytes_url.reset_mock()
            repaired = Path(qr.ensure_nexttrace())
            self.assertEqual(repaired.read_bytes(), data)
            bytes_url.assert_called_once()


class CliTests(unittest.TestCase):
    def test_invalid_utf8_from_nexttrace_does_not_crash(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "nexttrace"
            binary.write_bytes(b"#!/usr/bin/env python3\nimport os\nos.write(1, b'\\xff\\xfe')\n")
            binary.chmod(0o700)
            result = qr.trace_one(str(binary), "gd", "ct", 4, "tcp", 2, 10, 1, True)
            self.assertEqual(result.status, "error")
            self.assertIn("�", result.output or "")

    def test_classify_file_json_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.txt"
            path.write_text(trace(3356, 4809), encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, str(ROOT / "quickroute"), "--classify-file", str(path), "--json"],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            data = json.loads(completed.stdout)
            self.assertEqual(data["schema_version"], "1.0")
            self.assertEqual(data["tool_version"], qr.VERSION)
            self.assertEqual(data["results"][0]["route"], "CN2 GIA")
            self.assertIn("timestamp", data)
            self.assertIn("options", data)

    def test_command_shape(self):
        cmd = qr.build_command("nexttrace", "example.com", "tcp", 4, 20, 1)
        self.assertIn("-T", cmd)
        self.assertEqual(cmd[-1], "example.com")


if __name__ == "__main__":
    unittest.main()

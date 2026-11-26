"""sandbox_manager.py - Quản lý Trình duyệt Sandbox cô lập (Docker CDP hoặc Local Chrome Process).

Hỗ trợ 2 chế độ:
1. Docker Sandbox (kết nối qua CDP ws://localhost:9222).
2. Local Chromium/Chrome Process (tự động spawn process độc lập với user-data-dir tạm thời).
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from threading import Semaphore
from typing import Optional
import requests


@dataclass
class SandboxConfig:
    port: int = 9222
    host: str = "127.0.0.1"
    headless: bool = True
    max_browsers: int = 3
    startup_timeout_s: float = 15.0


def is_port_open(host: str, port: int) -> bool:
    """Kiểm tra xem cổng đã có tiến trình nào lắng nghe chưa."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex((host, port)) == 0


def find_system_chrome() -> Optional[str]:
    """Dò tìm file thực thi Google Chrome hoặc Edge trên hệ thống Windows/Linux/macOS."""
    possible_paths = [
        # Windows
        os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
        # Linux
        "/usr/bin/google-chrome",
        "/usr/bin/chromium-browser",
        "/usr/bin/chromium",
        # macOS
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    ]
    for p in possible_paths:
        if p and Path(p).is_file():
            return str(p)
    return shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("chrome")


class SandboxManager:
    """Điều phối vòng đời sandbox và khống chế trần phiên đồng thời."""

    def __init__(self, config: Optional[SandboxConfig] = None):
        self.config = config or SandboxConfig()
        self._semaphore = Semaphore(self.config.max_browsers)
        self._process: Optional[subprocess.Popen] = None
        self._temp_dir: Optional[str] = None

    @property
    def cdp_endpoint(self) -> str:
        return f"http://{self.config.host}:{self.config.port}"

    def start_sandbox(self) -> str:
        """Khởi động hoặc kết nối tới sandbox hiện có."""
        if is_port_open(self.config.host, self.config.port):
            try:
                resp = requests.get(f"{self.cdp_endpoint}/json/version", timeout=1.0)
                if resp.status_code == 200:
                    print(f"[Sandbox] Đã kết nối với Sandbox đang chạy sẵn tại {self.cdp_endpoint}")
                    return self.cdp_endpoint
            except Exception:
                pass

        # Nếu chưa có sandbox, tự khởi động local Chrome cô lập
        chrome_bin = find_system_chrome()
        if not chrome_bin:
            raise RuntimeError(
                "Không tìm thấy Google Chrome hoặc Microsoft Edge trên máy. "
                "Hãy cài đặt Chrome hoặc khởi chạy container Docker: 'docker compose -f docker-compose.sandbox.yml up -d'"
            )

        self._temp_dir = tempfile.mkdtemp(prefix="agent_sandbox_")
        cmd = [
            chrome_bin,
            f"--remote-debugging-port={self.config.port}",
            f"--user-data-dir={self._temp_dir}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-sync",
            "--disable-translate",
            "--disable-features=Translate,OptimizationHints",
            "--metrics-recording-only",
            "--safebrowsing-disable-auto-update",
            "--disable-blink-features=AutomationControlled",
        ]
        if self.config.headless:
            cmd.append("--headless=new")

        print(f"[Sandbox] Khởi chạy Local Browser Sandbox (PID mới) tại port {self.config.port}...")
        self._process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        # Chờ port mở
        start_time = time.monotonic()
        while time.monotonic() - start_time < self.config.startup_timeout_s:
            if is_port_open(self.config.host, self.config.port):
                time.sleep(0.5)
                print(f"[Sandbox] Trình duyệt Sandbox đã sẵn sàng tại {self.cdp_endpoint}")
                return self.cdp_endpoint
            time.sleep(0.2)

        raise TimeoutError(f"Sandbox không phản hồi trên port {self.config.port} sau {self.config.startup_timeout_s}s.")

    @contextmanager
    def lease(self, timeout_s: float = 10.0):
        """Khống chế trần phiên đồng thời trong Sandbox."""
        acquired = self._semaphore.acquire(blocking=True, timeout=timeout_s)
        if not acquired:
            raise RuntimeError(f"Hết slot Sandbox (vượt trần {self.config.max_browsers} browser đồng thời)!")
        try:
            yield
        finally:
            self._semaphore.release()

    def stop_sandbox(self):
        """Dừng tiến trình local nếu do SandboxManager tạo ra."""
        if self._process:
            print("[Sandbox] Đang đóng tiến trình Sandbox...")
            try:
                self._process.terminate()
                self._process.wait(timeout=3)
            except Exception:
                self._process.kill()
            self._process = None

        if self._temp_dir and Path(self._temp_dir).exists():
            try:
                shutil.rmtree(self._temp_dir, ignore_errors=True)
            except Exception:
                pass
            self._temp_dir = None

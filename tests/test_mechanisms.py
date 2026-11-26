"""test_mechanisms.py - Bộ kiểm thử tự động xác minh cơ chế chống ban IP hoạt động đúng.

Chạy lệnh:
    py -3 -m unittest tests/test_mechanisms.py -v
"""
import sys
import unittest
from pathlib import Path

CURRENT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(CURRENT_DIR))

from ip_block_detector import IPBlockDetector, detector
from sandbox_manager import SandboxManager, SandboxConfig


class TestIPBlockMechanisms(unittest.TestCase):

    def setUp(self):
        self.detector = IPBlockDetector(breaker_threshold=2, breaker_cooldown_s=5.0)

    def test_01_classify_normal_success(self):
        """Xác minh: Trang bình thường trả về HTTP 200 không bị coi là chặn IP."""
        res = self.detector.classify(status_code=200, title="Nhà hàng", body_text="Chào mừng quý khách")
        self.assertFalse(res.is_blocked)
        self.assertEqual(res.signal_type, "NONE")
        self.assertEqual(res.suggested_action, "CONTINUE")

    def test_02_distinguish_ratelimit_from_ip_ban(self):
        """Xác minh: HTTP 429 là Rate Limit (CHỜ ĐỢI), KHÔNG ĐƯỢC coi là Chặn IP (DỪNG BỎ)."""
        res = self.detector.classify(status_code=429, title="Too Many Requests", body_text="Rate limit exceeded")
        self.assertFalse(res.is_blocked, "429 phải được xử lý như Rate Limit, không phải IP Ban!")
        self.assertEqual(res.signal_type, "RATELIMIT_429")
        self.assertEqual(res.suggested_action, "WAIT_AND_RETRY")

    def test_03_detect_http_403_forbidden(self):
        """Xác minh: HTTP 403 kích hoạt ngay cờ chặn IP."""
        res = self.detector.classify(status_code=403, title="Forbidden", body_text="Access is forbidden")
        self.assertTrue(res.is_blocked)
        self.assertEqual(res.suggested_action, "STOP_AND_ESCALATE")

    def test_04_detect_cloudflare_signatures(self):
        """Xác minh: Bắt chính xác chữ ký WAF Cloudflare (Error 1020, Ray ID)."""
        res = self.detector.classify(
            status_code=403,
            title="Attention Required! | Cloudflare",
            body_text="Error 1020 Ray ID: 8b12f45c990a-hcm Access Denied"
        )
        self.assertTrue(res.is_blocked)
        self.assertEqual(res.signal_type, "CLOUDFLARE_1020")
        self.assertEqual(res.suggested_action, "STOP_AND_ESCALATE")

    def test_05_detect_geoblock_451(self):
        """Xác minh: HTTP 451 kích hoạt cờ Geoblocking."""
        res = self.detector.classify(status_code=451, title="Legal Block", body_text="Unavailable")
        self.assertTrue(res.is_blocked)
        self.assertEqual(res.signal_type, "GEO_BLOCK_451")

    def test_06_circuit_breaker_triggers(self):
        """Xác minh: Khi gặp chặn IP quá ngưỡng (threshold=2), Cầu dao tự động ngắt."""
        domain = "mock-restaurant.vn"
        is_open, _ = self.detector.is_domain_circuit_open(domain)
        self.assertFalse(is_open, "Ban đầu cầu dao phải đóng")

        # Lần chặn 1
        res1 = self.detector.classify(status_code=403, title="403", body_text="Access denied")
        self.detector.record_event(domain, res1)
        is_open, _ = self.detector.is_domain_circuit_open(domain)
        self.assertFalse(is_open, "Chưa vượt threshold (2) thì cầu dao vẫn chưa ngắt")

        # Lần chặn 2 -> Kích hoạt Circuit Breaker
        res2 = self.detector.classify(status_code=403, title="403", body_text="Access denied")
        self.detector.record_event(domain, res2)
        is_open, remain = self.detector.is_domain_circuit_open(domain)
        self.assertTrue(is_open, "Vượt threshold=2 thì cầu dao PHẢI ngắt")
        self.assertGreater(remain, 0)

    def test_07_sandbox_concurrency_lease_limit(self):
        """Xác minh: Sandbox manager khống chế đúng trần tối đa số browser đồng thời."""
        cfg = SandboxConfig(max_browsers=2)
        mgr = SandboxManager(cfg)

        with mgr.lease():
            with mgr.lease():
                # Đã chiếm đủ 2/2 slot, lần lease thứ 3 phải ném ngoại lệ hết slot ngay
                mgr._semaphore._value = 0
                with self.assertRaises(RuntimeError):
                    with mgr.lease(timeout_s=0.2):
                        pass


if __name__ == "__main__":
    unittest.main()

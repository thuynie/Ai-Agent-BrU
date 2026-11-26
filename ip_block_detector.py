"""ip_block_detector.py - Phân loại tín hiệu Chặn IP & Bộ ngắt mạch Circuit Breaker.

Phân biệt dứt khoát:
- Ratelimit (429): Tạm thời quá tải hạn ngạch -> Có Retry-After -> Đợi và thử lại.
- Chặn IP (403, WAF 1020, Access Denied): Cấm vĩnh viễn hoặc theo phiên -> Không Retry-After -> DỪNG NGAY!
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from threading import Lock
from typing import Dict, List, Optional, Tuple


@dataclass
class BlockClassification:
    is_blocked: bool
    signal_type: str  # 'HTTP_403', 'CLOUDFLARE_1020', 'WAF_ACCESS_DENIED', 'GEO_BLOCK', 'NONE'
    reason: str
    suggested_action: str  # 'STOP_AND_ESCALATE', 'HANDOFF_USER', 'DEEPLINK', 'CONTINUE'
    details: Dict[str, str] = field(default_factory=dict)


# Chữ ký WAF nhận diện chặn IP từ các nhà cung cấp phổ biến
WAF_SIGNATURES = [
    # Cloudflare
    (r"error\s+1020", "CLOUDFLARE_1020", "Cloudflare Error 1020: Access Denied"),
    (r"ray\s+id[:\s]+[a-f0-9]+", "CLOUDFLARE_WAF", "Cloudflare WAF Block (Phát hiện Ray ID)"),
    (r"attention\s+required!.*cloudflare", "CLOUDFLARE_CHALLENGE", "Cloudflare Challenge/Block Interstitial"),
    (r"blocked\s+by\s+cloudflare", "CLOUDFLARE_BLOCKED", "Bị chặn trực tiếp bởi Cloudflare WAF"),
    
    # Imperva / Incapsula / Akamai
    (r"incapsula\s+incident\s+id", "IMPERVA_BLOCKED", "Imperva/Incapsula IP Block"),
    (r"you\s+don't\s+have\s+permission\s+to\s+access.*on\s+this\s+server", "AKAMAI_BLOCKED", "Akamai IP Policy Denied"),
    
    # Generic WAF & Geoblocking
    (r"access\s+denied", "WAF_ACCESS_DENIED", "WAF Firewall: Access Denied"),
    (r"your\s+ip\s+has\s+been\s+blocked", "IP_BLACKLIST", "IP bị đưa vào danh sách đen"),
    (r"địa\s+chỉ\s+ip\s+của\s+bạn\s+bị\s+chặn", "IP_BLACKLIST_VN", "Thông báo IP bị chặn (Tiếng Việt)"),
    (r"not\s+available\s+in\s+your\s+(country|region)", "GEO_BLOCK", "Chặn vùng địa lý (Geoblock)"),
]


class IPBlockDetector:
    """Bộ phát hiện tín hiệu chặn IP và điều phối Circuit Breaker."""

    def __init__(self, breaker_threshold: int = 2, breaker_cooldown_s: float = 60.0):
        self._lock = Lock()
        self.breaker_threshold = breaker_threshold
        self.breaker_cooldown_s = breaker_cooldown_s
        self.domain_failures: Dict[str, List[float]] = {}
        self.circuit_open_domains: Dict[str, float] = {}

    def is_domain_circuit_open(self, domain: str) -> Tuple[bool, float]:
        """Kiểm tra xem domain mục tiêu có đang bị ngắt cầu dao (Circuit Breaker) hay không."""
        with self._lock:
            if domain in self.circuit_open_domains:
                elapsed = time.monotonic() - self.circuit_open_domains[domain]
                if elapsed < self.breaker_cooldown_s:
                    return True, round(self.breaker_cooldown_s - elapsed, 1)
                else:
                    # Hết thời gian cooldown -> chuyển sang trạng thái half-open
                    del self.circuit_open_domains[domain]
                    self.domain_failures[domain] = []
            return False, 0.0

    def record_event(self, domain: str, classification: BlockClassification):
        """Ghi nhận sự cố chặn IP vào domain và kích hoạt Circuit Breaker nếu vượt ngưỡng."""
        if not classification.is_blocked:
            return

        with self._lock:
            now = time.monotonic()
            history = self.domain_failures.setdefault(domain, [])
            # Giữ lại các lỗi trong vòng 3 phút
            self.domain_failures[domain] = [t for t in history if now - t < 180.0]
            self.domain_failures[domain].append(now)

            if len(self.domain_failures[domain]) >= self.breaker_threshold:
                self.circuit_open_domains[domain] = now
                print(f"\n[CIRCUIT BREAKER] Kích hoạt Cầu dao cho domain '{domain}' trong {self.breaker_cooldown_s}s!")

    def classify(
        self,
        status_code: Optional[int],
        title: str = "",
        body_text: str = "",
        headers: Optional[Dict[str, str]] = None,
        domain: str = ""
    ) -> BlockClassification:
        """Phân tích các phản hồi mạng và DOM để kết luận có bị ban IP hay không."""
        combined_text = f"{title}\n{body_text}".lower()

        # 1. Trường hợp HTTP 429: Đây là Ratelimit, KHÔNG PHẢI Chặn IP
        if status_code == 429:
            return BlockClassification(
                is_blocked=False,
                signal_type="RATELIMIT_429",
                reason="Server phản hồi HTTP 429 (Quá tải tạm thời/Rate Limit). Đây KHÔNG phải là Chặn IP.",
                suggested_action="WAIT_AND_RETRY",
                details={"status": "429"}
            )

        # 2. Trường hợp HTTP 403: Chặn IP / Cấm truy cập do Policy
        if status_code == 403:
            for pattern, sig, desc in WAF_SIGNATURES:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    return BlockClassification(
                        is_blocked=True,
                        signal_type=sig,
                        reason=f"HTTP 403 Forbidden + {desc}",
                        suggested_action="STOP_AND_ESCALATE",
                        details={"status": "403", "title": title}
                    )
            return BlockClassification(
                is_blocked=True,
                signal_type="HTTP_403_FORBIDDEN",
                reason="HTTP 403 Forbidden: Server từ chối truy cập do chính sách IP / WAF",
                suggested_action="STOP_AND_ESCALATE",
                details={"status": "403"}
            )

        # 3. Trường hợp HTTP 451: Geoblocking
        if status_code == 451:
            return BlockClassification(
                is_blocked=True,
                signal_type="GEO_BLOCK_451",
                reason="HTTP 451 Unavailable For Legal Reasons: Chặn IP theo vùng địa lý",
                suggested_action="STOP_AND_ESCALATE",
                details={"status": "451"}
            )

        # 4. Kiểm tra trang tùy biến (Custom Block Page) kể cả khi status code trả 200
        for pattern, sig, desc in WAF_SIGNATURES:
            if re.search(pattern, combined_text, re.IGNORECASE):
                return BlockClassification(
                    is_blocked=True,
                    signal_type=sig,
                    reason=f"Phát hiện chữ ký WAF trong nội dung trang: {desc}",
                    suggested_action="STOP_AND_ESCALATE",
                    details={"matched_signature": sig}
                )

        return BlockClassification(
            is_blocked=False,
            signal_type="NONE",
            reason="Truy cập hợp lệ, không có dấu hiệu bị chặn IP.",
            suggested_action="CONTINUE"
        )


# Khởi tạo thể hiện dùng chung
detector = IPBlockDetector()

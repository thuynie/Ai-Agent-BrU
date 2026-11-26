"""agent_booking.py - Agent Đặt Bàn Điều Khiển Trình Duyệt Trong Sandbox Qua CDP.

Tính năng:
1. Kết nối với Sandbox Trình duyệt độc lập qua Chrome DevTools Protocol (CDP).
2. Tích hợp cơ chế ngắt mạch Circuit Breaker trước khi điều hướng.
3. Nhận diện phản hồi Chặn IP (HTTP 403, WAF 1020, Geoblock) qua IPBlockDetector.
4. Kích hoạt cơ chế Stop & Escalate + Deeplink Handoff khi bị chặn IP.
"""
from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

# Nạp module nội bộ
CURRENT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(CURRENT_DIR))

from ip_block_detector import detector, BlockClassification
from sandbox_manager import SandboxManager, SandboxConfig
from playwright.async_api import async_playwright


async def run_booking_task(
    target_url: str,
    sandbox_endpoint: str,
    customer_name: str = "Nguyễn Văn A",
    guests: str = "4",
    booking_time: str = "19:00 Hôm nay"
) -> dict:
    """Agent điều khiển trình duyệt đặt bàn với cơ chế kiểm soát IP Ban."""
    domain = urlparse(target_url).netloc or "localhost"

    # [BƯỚC 1]: Kiểm tra Cầu dao (Circuit Breaker) trước khi gửi bất kỳ request nào
    is_open, remain_s = detector.is_domain_circuit_open(domain)
    if is_open:
        print(f"\n[⚠️ CẦU DAO KÍCH HOẠT] Domain '{domain}' đang bị ngắt mạch (còn {remain_s}s) do sự cố Chặn IP trước đó!")
        print("[HÀNH ĐỘNG] DỪNG NGAY TỨC THÌ. Không gửi request -> Tránh làm hỏng toàn bộ dải IP.")
        return {
            "status": "CIRCUIT_BREAKER_BLOCKED",
            "reason": f"Cầu dao bảo vệ đang mở cho domain {domain}",
            "fallback_deeplink": target_url
        }

    print(f"\n[1] Kết nối Playwright tới Sandbox qua CDP: {sandbox_endpoint}...")
    async with async_playwright() as p:
        browser = await p.chromium.connect_over_cdp(sandbox_endpoint)
        
        # Cấu hình Context giả lập người dùng thật (Anti-bot fingerprinting cơ bản)
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            locale="vi-VN",
            timezone_id="Asia/Ho_Chi_Minh",
            viewport={"width": 1280, "height": 800}
        )
        page = await context.new_page()

        last_status_code = None
        def on_response(resp):
            nonlocal last_status_code
            if resp.request.resource_type == "document":
                last_status_code = resp.status

        page.on("response", on_response)

        # [BƯỚC 2]: Truy cập trang mục tiêu
        print(f"[2] Điều hướng tới trang đặt bàn: {target_url}")
        t0 = time.monotonic()
        try:
            resp = await page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
            if resp:
                last_status_code = resp.status
        except Exception as e:
            print(f"[!] Ngoại lệ khi tải trang: {e}")

        elapsed = round(time.monotonic() - t0, 2)
        title = await page.title()
        
        try:
            body_text = await page.inner_text("body")
        except Exception:
            body_text = ""

        print(f"[3] Phản hồi mạng: HTTP {last_status_code} | Thời gian: {elapsed}s | Tiêu đề: '{title[:60]}'")

        # [BƯỚC 3]: Đánh giá tình trạng Chặn IP
        classification = detector.classify(
            status_code=last_status_code,
            title=title,
            body_text=body_text[:2000],
            domain=domain
        )

        if classification.is_blocked:
            print(f"\n[🚨 PHÁT HIỆN CHẶN IP - {classification.signal_type}]")
            print(f"  - Lý do: {classification.reason}")
            print(f"  - Hành động khuyến nghị: {classification.suggested_action}")
            
            # Ghi nhận vào Circuit Breaker của domain
            detector.record_event(domain, classification)

            print("\n[CƠ CHẾ PHÒNG VỆ KÍCH HOẠT]:")
            print("  1. Dừng hoàn toàn tác vụ (Stop & Escalate).")
            print("  2. TUYỆT ĐỐI KHÔNG spam reload hoặc lạm dụng xoay proxy.")
            print(f"  3. Chuyển giao Deep Link đặt bàn cho người dùng: {target_url}")
            
            await context.close()
            return {
                "status": "BLOCKED_IP",
                "classification": classification,
                "fallback_deeplink": target_url
            }

        # [BƯỚC 4]: Nếu không bị chặn, Agent thực hiện thao tác nghiệp vụ đặt bàn
        print("[4] Không có dấu hiệu bị chặn IP. Tiến hành đặt bàn tự động...")
        try:
            if await page.query_selector("#name"):
                await page.fill("#name", customer_name)
                await page.select_option("#guests", guests)
                await page.fill("#time", booking_time)
                await page.click("#btn-book")
                await page.wait_for_timeout(2000)
                msg = await page.inner_text("#msg")
                print(f"[THÀNH CÔNG] Kết quả: {msg}")
                await context.close()
                return {"status": "SUCCESS", "message": msg}
            else:
                print("[!] Trang không có form đặt bàn mock (có thể là trang ngoài). Kết thúc phiên an toàn.")
                await context.close()
                return {"status": "SUCCESS", "message": "Đã tải trang thành công"}
        except Exception as ex:
            print(f"[!] Lỗi khi điền form đặt bàn: {ex}")
            await context.close()
            return {"status": "FAILED", "error": str(ex)}


def execute_agent(url: str, headless: bool = True):
    """Bọc quy trình cấp phát Sandbox và thực thi Agent."""
    sandbox_mgr = SandboxManager(SandboxConfig(port=9222, headless=headless, max_browsers=3))
    endpoint = sandbox_mgr.start_sandbox()

    try:
        with sandbox_mgr.lease():
            result = asyncio.run(run_booking_task(target_url=url, sandbox_endpoint=endpoint))
            return result
    finally:
        sandbox_mgr.stop_sandbox()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Chạy Agent Đặt Bàn với Sandbox và cơ chế chống ban IP")
    parser.add_argument("--url", default="http://127.0.0.1:8000/", help="URL trang đặt bàn hoặc trang kiểm thử")
    parser.add_argument("--no-headless", action="store_true", help="Mở cửa sổ trình duyệt để quan sát")
    args = parser.parse_args()

    execute_agent(url=args.url, headless=not args.no_headless)

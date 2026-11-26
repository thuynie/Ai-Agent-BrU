"""run_demo.py - Trực Quan Hóa 3 Kịch Bản Thực Nghiệm Chống & Xử Lý Ban IP.

Kịch bản 1: Đặt bàn bình thường trên Mock Server (Thành công).
Kịch bản 2: Truy cập trang có WAF Chặn IP (HTTP 403 + Cloudflare Ray ID) -> Agent dừng ngay.
Kịch bản 3: Thử truy cập lại -> Cầu dao (Circuit Breaker) chặn ngay lập tức.
Kịch bản 4: Kiểm thử trên endpoint testbed chuẩn quốc tế (httpbin.org/status/403).
"""
from __future__ import annotations

import multiprocessing
import os
import sys
import time
from pathlib import Path

CURRENT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(CURRENT_DIR))

from agent_booking import execute_agent
from ip_block_detector import detector


def start_mock_server_background():
    """Khởi chạy Mock Server trong tiến trình nền."""
    import uvicorn
    from mock_server import app
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")


def main():
    print("=" * 70)
    print("      DEMO: CƠ CHẾ BẢO VỆ CHỐNG & XỬ LÝ CHẶN IP CHO BROWSER AGENT")
    print("=" * 70)

    # 1. Khởi động Mock Server
    print("\n[*] Đang khởi chạy Mock Restaurant Server tại http://127.0.0.1:8000...")
    server_process = multiprocessing.Process(target=start_mock_server_background, daemon=True)
    server_process.start()
    time.sleep(2)  # Chờ server sẵn sàng

    try:
        # KỊCH BẢN 1: Đặt bàn thông thường (Happy path)
        print("\n" + "#" * 60)
        print("KỊCH BẢN 1: Đặt bàn bình thường trên Web Nhà hàng (Không bị chặn)")
        print("#" * 60)
        res1 = execute_agent(url="http://127.0.0.1:8000/", headless=True)
        print(f"-> Kết quả Kịch bản 1: {res1.get('status')}")

        time.sleep(1)

        # KỊCH BẢN 2: Gặp WAF Chặn IP (HTTP 403 + Ray ID)
        print("\n" + "#" * 60)
        print("KỊCH BẢN 2: Truy cập trang bị WAF Chặn IP (Cloudflare Error 1020)")
        print("#" * 60)
        res2 = execute_agent(url="http://127.0.0.1:8000/waf/blocked-403", headless=True)
        print(f"-> Kết quả Kịch bản 2: {res2.get('status')}")

        # Giả lập ghi nhận thêm sự cố để kích hoạt Circuit Breaker
        from ip_block_detector import BlockClassification
        detector.record_event("127.0.0.1:8000", BlockClassification(
            is_blocked=True,
            signal_type="CLOUDFLARE_1020",
            reason="Mô phỏng lần chặn thứ 2",
            suggested_action="STOP_AND_ESCALATE"
        ))

        time.sleep(1)

        # KỊCH BẢN 3: Cầu dao ngắt mạch (Circuit Breaker) bảo vệ hệ thống
        print("\n" + "#" * 60)
        print("KỊCH BẢN 3: Kiểm thử Cầu dao ngắt mạch (Circuit Breaker)")
        print("#" * 60)
        res3 = execute_agent(url="http://127.0.0.1:8000/", headless=True)
        print(f"-> Kết quả Kịch bản 3: {res3.get('status')} - Lý do: {res3.get('reason')}")

        time.sleep(1)

        # KỊCH BẢN 4: Testbed HTTP 403 chuẩn quốc tế (httpbin.org)
        print("\n" + "#" * 60)
        print("KỊCH BẢN 4: Kiểm thử với endpoint chuẩn quốc tế https://httpbin.org/status/403")
        print("#" * 60)
        res4 = execute_agent(url="https://httpbin.org/status/403", headless=True)
        print(f"-> Kết quả Kịch bản 4: {res4.get('status')}")

    finally:
        print("\n[*] Đang dừng Mock Server...")
        server_process.terminate()
        server_process.join()

    print("\n" + "=" * 70)
    print("                      HOÀN TẤT BẢN THỬ NGHIỆM")
    print("=" * 70)


if __name__ == "__main__":
    main()

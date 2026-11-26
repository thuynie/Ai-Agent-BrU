# Hệ Thống Agent Đặt Bàn: Sandbox & Cơ Chế Chống/Xử Lý Ban IP Thực Tế

Thư mục này cung cấp giải pháp hoàn chỉnh cho bài toán: **Dựng AI Agent điều khiển trình duyệt (sử dụng browser-use / Playwright qua CDP) trong Sandbox cô lập để đặt bàn tự động, đồng thời kiểm thử và kích hoạt cơ chế phòng vệ khi gặp sự cố Chặn IP (IP Ban / WAF Block)**.

---

## 1. Phân biệt then chốt: Chặn IP (IP Ban) vs Rate Limit

Rất nhiều người nhầm lẫn giữa hai khái niệm này, dẫn đến thiết kế cơ chế xử lý sai lầm:

| Tiêu chí | Rate Limit (Giới hạn tần suất) | Chặn IP (IP Ban / WAF Block / Policy Deny) |
| :--- | :--- | :--- |
| **Bản chất** | Bạn gửi quá nhiều request trong 1 đơn vị thời gian (giây/phút) vượt quota tạm thời. | Server / WAF (Cloudflare, Akamai, Imperva) cấm hẳn IP của bạn (do IP nằm trong blacklist, dải datacenter bot, hoặc bị gắn cờ độc hại). |
| **HTTP Status** | Thường là **HTTP 429 Too Many Requests**. | **HTTP 403 Forbidden**, **HTTP 451 Unavailable For Legal Reasons**, hoặc trang HTML 200/403 chứa chữ ký WAF (Cloudflare 1020, Ray ID, Access Denied). |
| **Header** | Thường có `Retry-After: 30` (cho biết sau bao lâu được gọi lại). | Không có `Retry-After`. Thường có `cf-ray`, `x-amz-cf-id`,... |
| **Chiến lược xử lý đúng** | Chờ hết thời gian `Retry-After` (Exponential Backoff with Jitter) rồi gửi lại. | **DỪNG NGAY LẬP TỨC (Stop & Escalate)**. Tuyệt đối **KHÔNG** spam reload vì sẽ làm IP bị cấm vĩnh viễn; kích hoạt **Cầu dao (Circuit Breaker)** và bàn giao cho người dùng (Human Handoff / Deeplink). |

---

## 2. Các trang kiểm thử thực tế & an toàn (Không cần spam trang thương mại)

> [!WARNING]
> **Quy tắc đạo đức & an toàn kỹ thuật**: Tuyệt đối **không** dùng script/bot để spam liên tục vào các website đặt bàn thương mại đang hoạt động ngoài internet để "cố tình ăn ban". Điều này vi phạm Điều khoản Dịch vụ (ToS), có thể gây ảnh hưởng dịch vụ của họ và dẫn đến việc IP công ty/nhà mạng của bạn bị đưa vào Blacklist an ninh mạng toàn cầu (Spamhaus, AbuseIPDB).

Thay vào đó, cơ chế được kiểm thử thực tế qua các môi trường sau:

### A. Mock Server Đặt Bàn Cục Bộ (Được tích hợp sẵn trong folder này)
- File `mock_server.py`: Giả lập đầy đủ quy trình đặt bàn của nhà hàng và có sẵn bộ lọc WAF:
  - Chặn IP nằm trong Blacklist (trả về 403 Forbidden + Cloudflare Ray ID mô phỏng).
  - Tự động cấm IP sau số lần request bất thường.
  - Chặn Geoblocking (HTTP 451).

### B. Các Website Testbed Chuyên Dụng Quốc Tế
1. **HTTP Status Testbed (`https://httpbin.org/status/403`)**: Kiểm thử phản ứng chuẩn khi gặp HTTP 403.
2. **Geoblocking Testbed (`https://httpbin.org/status/451`)**: Kiểm thử chặn vùng địa lý.
3. **Bot Fingerprinting Testbed (`https://bot.sannysoft.com/`)**: Kiểm tra xem trình duyệt Sandbox của bạn có bị lộ cờ `navigator.webdriver`, thiếu WebGL, sai lệch canvas/timezone hay không.
4. **Cloudflare WAF Testbed (`https://nowsecure.nl/`)**: Trang kiểm tra khả năng vượt qua hoặc nhận diện màn hình chờ của Cloudflare Bot Management.

---

## 3. Cấu trúc thư mục

```text
browser_use_sandbox_antiban/
├── README.md                      # Tài liệu tổng quan này
├── requirements.txt              # Thư viện: browser-use, playwright, fastapi, uvicorn
├── docker-compose.sandbox.yml    # Khởi chạy Sandbox Chromium cô lập (port 9222 CDP)
├── sandbox_manager.py            # Quản lý vòng đời Sandbox (Docker hoặc Local Chrome process)
├── mock_server.py                # Server web đặt bàn giả lập tích hợp cơ chế WAF / IP Ban
├── ip_block_detector.py          # Bộ phân loại tín hiệu Chặn IP + Cầu dao Circuit Breaker
├── agent_booking.py              # Agent đặt bàn điều khiển trình duyệt qua CDP với cơ chế bảo vệ
└── run_demo.py                   # Script demo tự động 3 kịch bản thực tế
```

---

## 4. Bốn Tầng Cơ Chế Bảo Vệ / Chống Ban IP

1. **Tầng 1 - Sandbox Cô Lập (CDP Isolation)**:
   Trình duyệt chạy trong môi trường sandbox riêng, không dùng chung cookies hay storage với máy thật, giới hạn trần số lượng session đồng thời để tránh làm bùng nổ traffic.
2. **Tầng 2 - Nhận diện sớm dấu hiệu Chặn IP (`IPBlockDetector`)**:
   Phân tích HTTP Status, tiêu đề trang và DOM để bắt nhanh các mẫu: Cloudflare 1020, Imperva Incident, Akamai Access Denied, Geoblock.
3. **Tầng 3 - Cầu dao ngắt mạch (Circuit Breaker)**:
   Khi phát hiện 1 IP bị chặn ở một domain, hệ thống lập tức mở cầu dao domain đó, chặn mọi request tiếp theo từ các agent khác để bảo vệ toàn bộ dải IP.
4. **Tầng 4 - Fallback & Human Handoff (Bàn giao người dùng)**:
   Agent không cố tình bypass hay xoay IP bừa bãi khi gặp chặn cấp chính sách; thay vào đó, agent trích xuất deep link đặt bàn và gửi lại cho khách hàng tự hoàn tất trên điện thoại/máy tính cá nhân.

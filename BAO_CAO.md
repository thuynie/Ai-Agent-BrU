# Báo Cáo Kỹ Thuật: Cơ Chế Xử Lý & Chống Ban IP Cho Browser Agent Đặt Bàn

> **Đề án:** Nghiên cứu và thử nghiệm cơ chế kiểm soát rủi ro Chặn IP khi điều khiển trình duyệt tự động (browser-use / Playwright qua CDP).  
> **Trạng thái:** Đã hoàn thành thử nghiệm cơ chế • 7/7 Unit Tests Passed (0.2s).  
> **Thư mục nghiệm thu:** `d:\browser_use_sandbox_antiban`  
> **Repository:** [https://github.com/thuynie/Ai-Agent-BrU](https://github.com/thuynie/Ai-Agent-BrU)

---

## 1. Phân Biệt Chặn IP (IP Ban) vs Giới Hạn Tần Suất (Rate Limit)

Điểm cốt lõi nhằm tránh bẫy thiết kế nghiêm trọng: Khi gặp sự cố mạng, việc đánh đồng giữa **hết hạn ngạch tạm thời** và **bị cấm IP ở cấp chính sách** sẽ dẫn đến việc liên tục xoay proxy hoặc spam reload, làm đốt cháy toàn bộ dải IP phụ và đưa hệ thống vào Blacklist an ninh mạng toàn cầu.

| Tiêu chí | Giới Hạn Tần Suất (Rate Limit) | Chặn IP (IP Ban / WAF Block / Policy Deny) |
| :--- | :--- | :--- |
| **Mã phản hồi HTTP** | `HTTP 429 Too Many Requests` | `HTTP 403 Forbidden` / `HTTP 451` / WAF HTML |
| **Bản chất sự cố** | Hết hạn ngạch (quota) tạm thời trong 1 phút hoặc 1 giờ. | Server hoặc WAF cấm hẳn IP do nằm trong blacklist hoặc bị phát hiện bot. |
| **Dữ liệu kèm theo** | Thường có header chuẩn `Retry-After: 30`. | Kèm chữ ký WAF: `Ray ID`, `Error 1020`, `Access Denied`. |
| **Hành vi sai lầm cần tránh** | Bỏ cuộc ngay lập tức khi chưa chờ hết quota. | **Cố chấp reload hoặc liên tục xoay proxy spam tiếp**. |
| **Cơ chế xử lý chuẩn** | Chờ theo `Retry-After` (Exponential Backoff) rồi gọi lại. | **DỪNG NGAY TỨC THÌ (Stop & Escalate)**, kích hoạt Cầu dao (Circuit Breaker) và trả Deeplink cho người dùng. |

---

## 2. Kiến Trúc 4 Tầng Phòng Vệ & Chống Ban IP

Hệ thống được thiết kế theo 4 tầng bảo vệ độc lập, kiểm soát từ khâu cấp phát trình duyệt đến khi hoàn tất tác vụ:

### 2.1. Chi tiết 4 tầng phòng vệ

* **Tầng 1 - Sandbox Cô Lập (CDP Isolation):**
  * Trình duyệt chạy trong môi trường riêng biệt (Docker Chrome hoặc tiến trình Chromium độc lập với user-data-dir tạm thời qua port `9222`).
  * Cô lập hoàn toàn cookies, storage, cấu hình User-Agent và Timezone chuẩn người dùng Việt Nam.
  * Khống chế trần tối đa số session đồng thời (`MAX_CONCURRENT_SESSIONS = 3`) theo chuẩn MVP-76 để tránh bùng nổ lưu lượng.
* **Tầng 2 - Nhận Diện WAF Sớm (`IPBlockDetector`):**
  * Tự động phân tích mã HTTP Status Code và quét biểu thức chính quy (Regex) trên DOM/Title.
  * Nhận diện nhanh các chữ ký WAF phổ biến: Cloudflare `Error 1020: Access Denied`, Cloudflare `Ray ID`, Imperva Incapsula, Akamai Access Denied, Geoblock `HTTP 451`.
* **Tầng 3 - Cầu Dao Ngắt Mạch (`Circuit Breaker` theo Domain):**
  * Máy trạng thái hữu hạn theo dõi tỷ lệ lỗi theo từng domain đích.
  * Khi phát hiện IP bị chặn liên tiếp vượt ngưỡng (`threshold = 2`), cầu dao tự động chuyển sang trạng thái **OPEN** trong khoảng thời gian `cooldown = 60s`.
  * Toàn bộ các request tiếp theo gửi đến domain này sẽ bị **ngắn mạch ngay tại ứng dụng (Short-circuit)**, không phát sinh gói tin ra mạng ngoài để bảo toàn dải IP.
* **Tầng 4 - Bàn Giao & Fallback (`Human Handoff`):**
  * Tuyệt đối không cưỡng chế bypass WAF khi đã bị cấm ở cấp chính sách.
  * Agent tự động trích xuất Deep Link của trang đặt bàn và trả về cho người dùng tự thao tác thủ công trên thiết bị cá nhân.

### 2.2. Chu trình điều phối tác vụ (Workflow Diagram)

```text
[Tác vụ Đặt Bàn] ──► [Kiểm tra Circuit Breaker]
                            │
              ┌─────────────┴─────────────┐
        (Cầu dao MỞ?)                (Cầu dao ĐÓNG)
              │                             │
              ▼                             ▼
       [DỪNG NGAY TỨC THÌ]           [Cấp phát Sandbox CDP]
       [Trả link Deeplink]                  │
                                            ▼
                                     [Điều hướng tới Web]
                                            │
                                            ▼
                                   [IPBlockDetector Phân Tích]
                                   ┌────────┴────────┐
                             (Phát hiện 403/WAF)   (HTTP 200 OK)
                                   │                 │
                                   ▼                 ▼
                          [Kích hoạt Cầu dao]    [Điền Form & Đặt Bàn]
                          [Stop & Escalate]      [Hoàn tất thành công]
```

---

## 3. Phương Pháp Thực Nghiệm An Toàn (Compliance & Safety)

> **Quy tắc bảo vệ hạ tầng mạng:** Tuyệt đối không dùng script spam trực tiếp vào các trang thương mại thật ngoài internet (như hệ thống đặt bàn lớn, app giao đồ ăn). Hành vi này vi phạm Điều khoản dịch vụ (ToS) và có nguy cơ khiến dải IP công ty bị đưa vào Blacklist an ninh mạng toàn cầu (Spamhaus, AbuseIPDB).

Toàn bộ quá trình thực nghiệm được triển khai an toàn trên 2 nhóm môi trường:

### 3.1. Môi trường Mock Server Cục Bộ (`mock_server.py`)
Chạy trực tiếp tại `http://127.0.0.1:8000/`, cung cấp:
* `GET /`: Trang đặt bàn nhà hàng chuẩn (Happy path), kiểm tra luồng điền form và API `/api/book`.
* `GET /waf/blocked-403`: Giả lập trang chặn WAF Cloudflare chuẩn (HTTP 403 + `Error 1020: Access Denied` + Ray ID).
* `GET /waf/geoblock-451`: Giả lập trang từ chối truy cập ngoài lãnh thổ (HTTP 451).
* `GET /waf/spam-test`: Mô phỏng cơ chế Fail2ban động — nếu gửi quá 3 request/5 giây, server tự động khóa vĩnh viễn IP vào Blacklist.

### 3.2. Testbed Tiêu Chuẩn Quốc Tế
* `https://httpbin.org/status/403`: Kiểm thử phản ứng trước mã lỗi HTTP 403 chuẩn quốc tế.
* `https://httpbin.org/status/451`: Kiểm thử phản ứng trước mã lỗi Geoblock 451.
* `https://bot.sannysoft.com/`: Kiểm toán dấu vân tay trình duyệt (`navigator.webdriver`, canvas, WebGL,...).
* `https://nowsecure.nl/`: Kiểm tra phản ứng trước màn hình chờ của Cloudflare Bot Management.

---

## 4. Kết Quả Kiểm Thử Độc Lập (Unit Test Verification)

Bộ kiểm thử tự động gồm 7 bài test tại `tests/test_mechanisms.py` xác thực tính toàn vẹn của logic cốt lõi:

| Mã Test Case | Mục Tiêu Kiểm Thử | Kết Quả |
| :--- | :--- | :--- |
| `test_01` | Trang bình thường HTTP 200 không bị nhận nhầm là chặn IP | **PASS** |
| `test_02` | **Phân biệt đúng:** HTTP 429 là Rate Limit (`WAIT_AND_RETRY`), không phải Chặn IP | **PASS** |
| `test_03` | HTTP 403 Forbidden kích hoạt cờ dừng khẩn cấp `STOP_AND_ESCALATE` | **PASS** |
| `test_04` | Bắt chính xác chữ ký WAF Cloudflare (`Error 1020` + `Ray ID`) | **PASS** |
| `test_05` | HTTP 451 kích hoạt cờ Geoblocking vùng địa lý | **PASS** |
| `test_06` | Cầu dao (`Circuit Breaker`) tự động ngắt mạch khi gặp chặn IP liên tiếp | **PASS** |
| `test_07` | Khống chế đúng trần tối đa số browser đồng thời trong Sandbox | **PASS** |

### Output Console thực tế:
```text
test_01_classify_normal_success ... ok
test_02_distinguish_ratelimit_from_ip_ban ... ok
test_03_detect_http_403_forbidden ... ok
test_04_detect_cloudflare_signatures ... ok
test_05_detect_geoblock_451 ... ok
test_06_circuit_breaker_triggers ... ok
test_07_sandbox_concurrency_lease_limit ... ok

----------------------------------------------------------------------
Ran 7 tests in 0.214s

OK
[CIRCUIT BREAKER] Kích hoạt Cầu dao cho domain 'mock-restaurant.vn' trong 5.0s!
```

---

## 5. Hướng Dẫn Các Lệnh Thao Tác & Demo

Mở terminal tại thư mục `d:\browser_use_sandbox_antiban`:

1. **Chạy 7 bài kiểm thử đơn vị tự động:**
   ```powershell
   py -3 -m unittest tests/test_mechanisms.py -v
   ```
2. **Chạy kịch bản demo tự động (Happy path + WAF block + Circuit breaker):**
   ```powershell
   py -3 run_demo.py
   ```
3. **Mở Agent với cửa sổ Chrome thật để quan sát:**
   ```powershell
   py -3 agent_booking.py --url "http://127.0.0.1:8000/" --no-headless
   ```
4. **Xem bản báo cáo HTML tương tác xanh pastel:**
   Mở trình duyệt truy cập: [http://127.0.0.1:8000/report](http://127.0.0.1:8000/report)

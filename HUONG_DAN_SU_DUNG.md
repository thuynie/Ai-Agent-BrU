# Hướng Dẫn Chi Tiết: Dựng Agent Đặt Bàn, Sandbox & Kiểm Thử Cơ Chế Chống Ban IP

Tài liệu này giải đáp toàn diện các vấn đề bạn và team đang gặp phải:
1. **Tìm các trang bị chặn IP do spam / WAF để thử nghiệm an toàn.**
2. **Phân biệt rạch ròi giữa Chặn IP (IP Ban/Block) và Giới hạn tần suất (Rate Limit).**
3. **Cách dựng Trình duyệt Sandbox cô lập điều khiển qua CDP / browser-use.**
4. **Cơ chế xử lý chuẩn ở mức kiến trúc (Stop & Escalate, Circuit Breaker, Human Handoff).**

---

## 1. Tìm các trang bị chặn IP do spam / WAF (Thử nghiệm thực tế như thế nào?)

### ⚠️ Lưu ý an toàn & đạo đức kỹ thuật
Tuyệt đối **không nên** viết bot để spam liên tục vào các website thương mại thật (như Shopee, Baemin, Grab, các hệ thống nhà hàng lớn) chỉ để "bị ban IP thử xem sao". Vì:
- Vi phạm Điều khoản sử dụng (ToS).
- Có nguy cơ khiến toàn bộ IP mạng công ty/nhà riêng của bạn bị đưa vào Blacklist toàn cầu (như Spamhaus, AbuseIPDB), ảnh hưởng đến toàn bộ công việc khác.

### ✅ Các phương án thử nghiệm thực tế & an toàn nhất:

#### Phương án 1: Dùng Mock Server tích hợp sẵn (Khuyên dùng cho giai đoạn phát triển cơ chế)
Trong thư mục này đã có sẵn file `mock_server.py`. Server này mô phỏng chính xác:
- **Trang đặt bàn thật**: Có form điền họ tên, số khách, giờ đặt.
- **Kịch bản WAF Cloudflare**: URL `/waf/blocked-403` trả về HTTP 403 + `Error 1020: Access Denied` kèm Ray ID.
- **Kịch bản Geoblock**: URL `/waf/geoblock-451` trả về HTTP 451 chặn theo quốc gia.
- **Kịch bản Spam dẫn đến Ban IP**: URL `/waf/spam-test`. Nếu agent gửi quá 3 request trong 5 giây, server sẽ tự động đưa IP của bạn vào Blacklist và khóa vĩnh viễn mọi lượt truy cập sau đó.

#### Phương án 2: Các Testbed Chuẩn Quốc Tế dành cho Bot & WAF
Bạn có thể trỏ Agent vào các trang sau:
1. **`https://httpbin.org/status/403`**: Trả về mã phản hồi HTTP 403 Forbidden chuẩn của WAF/Server.
2. **`https://httpbin.org/status/451`**: Trả về mã HTTP 451 (Chặn theo chính sách địa lý).
3. **`https://bot.sannysoft.com/`**: Trang kiểm tra chi tiết xem Sandbox/Browser của bạn có bị lộ dấu vết bot hay không (`navigator.webdriver`, thiếu WebGL, canvas fingerprint,...).
4. **`https://nowsecure.nl/`**: Trang được bảo vệ bởi Cloudflare Bot Management để kiểm tra phản ứng của trình duyệt khi gặp Cloudflare Turnstile/Interstitial.
5. **Các website nhà hàng có WAF Cloudflare thực tế** (Ví dụ: `https://datban.ggg.com.vn/`): Nếu truy cập bằng IP hosting/datacenter lạ, Cloudflare sẽ ngay lập tức kích hoạt màn hình chặn WAF.

---

## 2. Phân biệt: Chặn IP (IP Ban) vs Ratelimit (HTTP 429)

Hiểu đúng bản chất này sẽ giúp bạn thiết kế code ở mức cơ chế cực kỳ chuẩn xác:

| Đặc điểm | Giới hạn tần suất (Rate Limit) | Chặn IP (IP Ban / WAF Block) |
| :--- | :--- | :--- |
| **Mã HTTP** | **429 Too Many Requests** | **403 Forbidden**, **451 Unavailable**, hoặc trang **200/403** kèm chữ ký WAF |
| **Bản chất** | Tạm thời hết quota trong 1 phút/1 giờ. | Server cấm cửa IP (do blacklist, IP datacenter, hoặc hành vi bị coi là tấn công). |
| **Thông tin đi kèm** | Header `Retry-After: 30` (sau 30 giây được gọi lại). | Kèm Ray ID, Incident ID, chữ ký "Access Denied", "Error 1020". |
| **Hành vi xử lý sai** | Bỏ cuộc ngay lập tức. | **Cố tình spam reload hoặc liên tục xoay proxy để vượt WAF** (khiến toàn bộ dải IP phụ bị cháy đen). |
| **Hành vi xử lý ĐÚNG** | Ngủ (sleep) theo `Retry-After` rồi thử lại. | **DỪNG NGAY TỨC THÌ (Stop & Escalate)**, ngắt cầu dao domain đó (Circuit Breaker) và trả Deep Link cho người dùng tự đặt (Human Handoff). |

---

## 3. Kiến trúc Cơ Chế Chống & Xử Lý Ban IP

Trong thư mục `browser_use_sandbox_antiban`, cơ chế được tổ chức thành 4 tầng:

```
[User Request: Đặt bàn]
         │
         ▼
[Tầng 1: Circuit Breaker] ──(Cầu dao đang mở?)──► [Có] ──► [Dừng ngay, trả Deeplink]
         │ [Không]
         ▼
[Tầng 2: Sandbox Manager] (Khởi tạo trình duyệt cô lập port 9222, trần 3 session)
         │
         ▼
[Tầng 3: Browser Agent] (Playwright / browser-use điều khiển qua CDP)
         │
         ▼
[Tầng 4: IP Block Detector]
   ├── HTTP 403 / 451 / WAF 1020? ──► DỪNG NGAY, kích hoạt Cầu dao, Deeplink
   ├── HTTP 429?                 ──► Exponential Backoff theo Retry-After
   └── HTTP 200 OK               ──► Tiếp tục điền form và xác nhận đặt bàn
```

---

## 4. Cách chạy và thử nghiệm

### Bước 1: Cài đặt thư viện
```powershell
cd d:\browser_use_sandbox_antiban
py -3 -m pip install -r requirements.txt
```

### Bước 2: Chạy demo tổng thể 4 kịch bản tự động
Chỉ cần chạy lệnh:
```powershell
py -3 run_demo.py
```
Script sẽ tự động:
1. Chạy Mock Server ngầm.
2. Thử nghiệm **Kịch bản 1**: Đặt bàn bình thường trên form nhà hàng (Thành công).
3. Thử nghiệm **Kịch bản 2**: Truy cập trang WAF Cloudflare mô phỏng -> Agent phát hiện và dừng ngay lập tức.
4. Thử nghiệm **Kịch bản 3**: Thử gọi lại khi Cầu dao (Circuit Breaker) đang mở -> Agent chặn ngay từ đầu, không gửi request.
5. Thử nghiệm **Kịch bản 4**: Truy cập trang testbed quốc tế `https://httpbin.org/status/403`.

### Bước 3: Thử nghiệm riêng lẻ với cửa sổ trình duyệt hiển thị (Non-headless)
Nếu bạn muốn nhìn thấy tận mắt trình duyệt Sandbox mở lên và thao tác:
```powershell
py -3 agent_booking.py --url "http://127.0.0.1:8000/" --no-headless
```
Hoặc thử với trang bị chặn WAF:
```powershell
py -3 agent_booking.py --url "http://127.0.0.1:8000/waf/blocked-403" --no-headless
```

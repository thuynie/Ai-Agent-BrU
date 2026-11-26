"""mock_server.py - Server Đặt Bàn Giả Lập tích hợp WAF & Cơ Chế Chặn IP Thực Tế.

Cung cấp:
1. Trang đặt bàn nhà hàng bình thường (Happy path).
2. Trang WAF Cloudflare giả lập (HTTP 403 + Ray ID / Error 1020).
3. Trang Geoblocking (HTTP 451).
4. Cơ chế tự động ban IP theo ngưỡng spam (Fail2ban/WAF Dynamic Rule).
"""
from __future__ import annotations

import time
from collections import defaultdict
from pathlib import Path
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(title="Mock Restaurant Booking & WAF Server")

REPORT_HTML_PATH = Path(__file__).resolve().parent / "report_bao_cao.html"


@app.get("/report", response_class=HTMLResponse)
async def view_report_html():
    if REPORT_HTML_PATH.exists():
        return HTMLResponse(content=REPORT_HTML_PATH.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>Không tìm thấy file report_bao_cao.html</h1>", status_code=404)

# Bộ nhớ giả lập lưu trữ các IP bị cấm
BANNED_IPS = set(["192.168.1.100", "10.0.0.99"])
# Đếm tần suất request theo IP (mô phỏng spam detection)
REQUEST_HISTORY = defaultdict(list)
SPAM_THRESHOLD = 3  # Quá 3 request trong 5 giây => BAN IP


@app.get("/", response_class=HTMLResponse)
async def home_booking_page(request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    
    # Kiểm tra xem IP có nằm trong danh sách cấm hay không
    if client_ip in BANNED_IPS:
        return HTMLResponse(
            status_code=403,
            content="""
            <html>
            <head><title>403 Forbidden - Access Denied</title></head>
            <body style="font-family: sans-serif; text-align: center; padding-top: 50px;">
                <h1 style="color: red;">Error 1020: Access Denied</h1>
                <p>Your IP address has been blocked by Cloudflare WAF Security Policy.</p>
                <p>Ray ID: <code>8b12f45c990a-hcm</code></p>
                <p>Contact the site owner if you believe this is an error.</p>
            </body>
            </html>
            """
        )

    return HTMLResponse(
        content="""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Nhà Hàng Gourmet - Đặt Bàn Trực Tuyến</title>
            <style>
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f4f6f9; padding: 40px; }
                .card { max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
                h2 { color: #2c3e50; }
                .form-group { margin-bottom: 15px; }
                label { display: block; margin-bottom: 5px; font-weight: bold; }
                input, select, button { width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 6px; box-sizing: border-box; }
                button { background: #27ae60; color: white; font-size: 16px; border: none; cursor: pointer; margin-top: 10px; }
                button:hover { background: #219150; }
                #msg { margin-top: 15px; font-weight: bold; }
            </style>
        </head>
        <body>
            <div class="card">
                <h2>Đặt Bàn Nhà Hàng Gourmet</h2>
                <div class="form-group">
                    <label>Họ và tên:</label>
                    <input id="name" type="text" value="Nguyễn Văn A" placeholder="Nhập tên của bạn">
                </div>
                <div class="form-group">
                    <label>Số lượng khách:</label>
                    <select id="guests">
                        <option value="2">2 người</option>
                        <option value="4" selected>4 người</option>
                        <option value="8">8 người</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Giờ đặt:</label>
                    <input id="time" type="text" value="19:00 Hôm nay">
                </div>
                <button id="btn-book" onclick="submitBooking()">Xác Nhận Đặt Bàn</button>
                <div id="msg"></div>
            </div>
            <script>
                async function submitBooking() {
                    const btn = document.getElementById('btn-book');
                    btn.disabled = true;
                    btn.innerText = 'Đang xử lý...';
                    const res = await fetch('/api/book', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            name: document.getElementById('name').value,
                            guests: document.getElementById('guests').value,
                            time: document.getElementById('time').value
                        })
                    });
                    const data = await res.json();
                    const msgDiv = document.getElementById('msg');
                    if (res.ok) {
                        msgDiv.style.color = 'green';
                        msgDiv.innerText = '✅ ' + data.message + ' (Mã bàn: ' + data.booking_id + ')';
                    } else {
                        msgDiv.style.color = 'red';
                        msgDiv.innerText = '❌ Lỗi: ' + (data.detail || 'Không thể đặt bàn');
                    }
                    btn.disabled = false;
                    btn.innerText = 'Xác Nhận Đặt Bàn';
                }
            </script>
        </body>
        </html>
        """
    )


@app.post("/api/book")
async def api_book_table(request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    if client_ip in BANNED_IPS:
        return JSONResponse(status_code=403, content={"detail": "IP của bạn đã bị chặn bởi hệ thống bảo mật WAF."})
    return {"status": "success", "booking_id": "BK-8899", "message": "Đặt bàn thành công!"}


@app.get("/waf/blocked-403", response_class=HTMLResponse)
async def waf_blocked_scenario():
    """Giả lập trang chặn WAF Cloudflare HTTP 403 chuẩn."""
    return HTMLResponse(
        status_code=403,
        content="""
        <!DOCTYPE html>
        <html>
        <head><title>Attention Required! | Cloudflare</title></head>
        <body style="font-family: sans-serif; text-align: center; margin-top: 50px;">
            <h1>Error 1020: Access Denied</h1>
            <p>You do not have permission to access this resource on this server.</p>
            <p>Cloudflare Ray ID: <strong>9ab4021fe3a17c</strong></p>
            <p>Your IP has been blocked due to suspicious activity.</p>
        </body>
        </html>
        """
    )


@app.get("/waf/geoblock-451", response_class=HTMLResponse)
async def waf_geoblock_scenario():
    """Giả lập trang Geoblock HTTP 451."""
    return HTMLResponse(
        status_code=451,
        content="""
        <html>
        <head><title>451 Unavailable For Legal Reasons</title></head>
        <body>
            <h1>Access Denied: Not available in your country/region</h1>
            <p>This reservation service is restricted to domestic IP ranges only.</p>
        </body>
        </html>
        """
    )


@app.get("/waf/spam-test")
async def spam_trigger_ban(request: Request):
    """Mô phỏng: Cố tình gửi request dồn dập (spam) -> Bị ban vĩnh viễn IP."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    now = time.monotonic()
    
    # Dọn dẹp request cũ hơn 5s
    REQUEST_HISTORY[client_ip] = [t for t in REQUEST_HISTORY[client_ip] if now - t < 5.0]
    REQUEST_HISTORY[client_ip].append(now)

    if len(REQUEST_HISTORY[client_ip]) >= SPAM_THRESHOLD or client_ip in BANNED_IPS:
        BANNED_IPS.add(client_ip)
        return HTMLResponse(
            status_code=403,
            content="""
            <html>
            <head><title>403 Forbidden - IP Blacklisted</title></head>
            <body>
                <h1>WAF Security Alert: IP Blacklisted!</h1>
                <p>Hệ thống phát hiện tần suất gửi request bất thường giống bot/spam.</p>
                <p>Địa chỉ IP của bạn đã bị chặn vĩnh viễn (Policy Ban).</p>
            </body>
            </html>
            """
        )

    return {"status": "ok", "remaining_quota_before_ban": SPAM_THRESHOLD - len(REQUEST_HISTORY[client_ip])}


@app.get("/admin/reset-bans")
async def reset_bans():
    BANNED_IPS.clear()
    REQUEST_HISTORY.clear()
    return {"message": "Đã gỡ toàn bộ IP khỏi blacklist"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)

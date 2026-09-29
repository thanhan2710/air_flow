"""
scanner_api.py
Dịch vụ REST API kiểm định mã độc (Malware Scanner API Service).
Lắng nghe trên cổng 5050, tiếp nhận tệp tin tải lên từ Web Dashboard
và trả về kết quả phân tích chi tiết của 3 mô hình học máy.
"""

import os
import sys
import json
import cgi
import io
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

# Import engine
try:
    from scanner_engine import get_scanner_engine
except ImportError:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, base_dir)
    from scanner_engine import get_scanner_engine


PORT = int(os.environ.get("SCANNER_PORT", 5050))
HOST = "0.0.0.0"


class MalwareScannerHTTPHandler(BaseHTTPRequestHandler):

    def _set_cors_headers(self):
        """Thiết lập CORS để cho phép trình duyệt từ MinIO (localhost:9000) hoặc máy local gọi API"""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')

    def do_OPTIONS(self):
        """Xử lý preflight CORS request"""
        self.send_response(200)
        self._set_cors_headers()
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_GET(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        # 1. Health check endpoint
        if path == "/api/health":
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self._set_cors_headers()
            self.end_headers()

            engine = get_scanner_engine()
            res = {
                "status": "online",
                "service": "Shield-AI Malware Scanner API",
                "models_loaded": engine.models_loaded,
                "supported_algorithms": ["Random Forest", "XGBoost", "Deep Learning (MLP)"],
                "version": "2.0.0"
            }
            self.wfile.write(json.dumps(res, ensure_ascii=False).encode('utf-8'))
            return

        # 2. Demo sample scan endpoint
        if path.startswith("/api/sample/"):
            sample_name = path.replace("/api/sample/", "")
            base_dir = os.path.dirname(os.path.abspath(__file__))
            sample_dir = os.path.join(base_dir, "malware_samples")
            sample_path = os.path.join(sample_dir, sample_name)

            if not os.path.exists(sample_path):
                self.send_response(404)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self._set_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({"error": f"Không tìm thấy mẫu {sample_name}"}).encode('utf-8'))
                return

            with open(sample_path, 'rb') as f:
                content = f.read()

            engine = get_scanner_engine()
            analysis = engine.analyze_file(content, file_name=sample_name)

            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(analysis, ensure_ascii=False).encode('utf-8'))
            return

        # 3. Phục vụ dashboard.html trực tiếp nếu truy cập http://localhost:5050
        if path in ["/", "/dashboard", "/dashboard.html", "/index.html"]:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            html_path = os.path.join(base_dir, "reports", "dashboard.html")
            if not os.path.exists(html_path):
                html_path = os.path.join(base_dir, "reports", "index.html")

            if os.path.exists(html_path):
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self._set_cors_headers()
                self.end_headers()
                with open(html_path, 'rb') as f:
                    self.wfile.write(f.read())
                return

        # 404 Fallback
        self.send_response(404)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps({"error": "Endpoint không tồn tại"}).encode('utf-8'))

    def do_POST(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        if path == "/api/scan":
            try:
                content_type = self.headers.get('Content-Type', '')
                content_length = int(self.headers.get('Content-Length', 0))

                file_content = None
                file_name = "uploaded_file.bin"

                # Xử lý multipart/form-data
                if 'multipart/form-data' in content_type:
                    boundary = content_type.split("boundary=")[1].encode()
                    raw_body = self.rfile.read(content_length)

                    parts = raw_body.split(b'--' + boundary)
                    for part in parts:
                        if b'Content-Disposition' in part and b'filename="' in part:
                            # Tách header và body của part
                            header_body_split = part.split(b'\r\n\r\n', 1)
                            if len(header_body_split) == 2:
                                headers_part, body_part = header_body_split
                                # Tách tên file
                                for line in headers_part.split(b'\r\n'):
                                    if b'filename="' in line:
                                        try:
                                            fn_start = line.find(b'filename="') + 10
                                            fn_end = line.find(b'"', fn_start)
                                            file_name = line[fn_start:fn_end].decode('utf-8', errors='ignore')
                                        except Exception:
                                            file_name = "uploaded_sample.exe"

                                # Loại bỏ phần kết thúc \r\n
                                if body_part.endswith(b'\r\n'):
                                    body_part = body_part[:-2]
                                file_content = body_part
                                break

                # Hoặc raw binary stream
                elif 'application/octet-stream' in content_type or content_length > 0:
                    file_content = self.rfile.read(content_length)
                    # Lấy tên file từ header tùy chọn X-File-Name nếu có
                    custom_name = self.headers.get('X-File-Name')
                    if custom_name:
                        file_name = custom_name

                if not file_content:
                    self.send_response(400)
                    self.send_header('Content-Type', 'application/json; charset=utf-8')
                    self._set_cors_headers()
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "Không tìm thấy dữ liệu tệp tin được tải lên."}).encode('utf-8'))
                    return

                # Thực hiện phân tích qua Scanner Engine
                engine = get_scanner_engine()
                result = engine.analyze_file(file_content, file_name=file_name)

                self.send_response(200)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self._set_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps(result, ensure_ascii=False).encode('utf-8'))

            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self._set_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({"error": f"Lỗi trong quá trình quét tệp: {str(e)}"}).encode('utf-8'))
            return

        # Not found
        self.send_response(404)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps({"error": "Endpoint không hợp lệ"}).encode('utf-8'))

    def log_message(self, format, *args):
        # Tùy chỉnh log ngắn gọn
        print(f"[SCANNER API] {self.address_string()} - {args[0]}")


def run_server():
    server_address = (HOST, PORT)
    httpd = ThreadingHTTPServer(server_address, MalwareScannerHTTPHandler)
    print("=" * 70)
    print(f"🛡️  SHIELD-AI MALWARE SCANNER API SERVER ĐANG CHẠY...")
    print(f"📡  Lắng nghe trên: http://localhost:{PORT}")
    print(f"🔍  Endpoint Quét File: POST http://localhost:{PORT}/api/scan")
    print(f"💚  Endpoint Kiểm Tra:  GET  http://localhost:{PORT}/api/health")
    print(f"🌐  Giao diện Dashboard: http://localhost:{PORT}/")
    print("=" * 70)

    # Nạp trước mô hình khi khởi động
    engine = get_scanner_engine()
    if engine.models_loaded:
        print(">> [SẴN SÀNG] Đã nạp 3 mô hình học máy: Random Forest, XGBoost, MLP.")
    else:
        print(">> [CHÚ Ý] Đang chờ khởi tạo mô hình...")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n>> Dừng máy chủ Scanner API.")
        httpd.server_close()


if __name__ == "__main__":
    run_server()

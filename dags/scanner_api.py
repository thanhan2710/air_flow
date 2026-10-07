"""
scanner_api.py
Dịch vụ REST API kiểm định mã độc (Malware Scanner API Service).
Lắng nghe trên cổng 5050, tiếp nhận tệp tin tải lên từ Web Dashboard,
lưu trữ tệp tin và toàn bộ lịch sử phân tích, trả về kết quả phân tích
chi tiết của 3 mô hình học máy.
"""

import os
import sys
import json
import uuid
import threading
from datetime import datetime
from urllib.parse import urlparse, unquote
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

# Import engine
try:
    from scanner_engine import get_scanner_engine
except ImportError:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, base_dir)
    from scanner_engine import get_scanner_engine


PORT = int(os.environ.get("SCANNER_PORT", 5050))
HOST = "0.0.0.0"

# Đường dẫn lưu trữ tệp tải lên và lịch sử kiểm định
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploaded_scans")
FILES_DIR = os.path.join(UPLOAD_DIR, "files")
HISTORY_FILE = os.path.join(UPLOAD_DIR, "scan_history.json")


class ScanHistoryManager:
    """Quản lý lưu trữ tệp tin đã tải lên và toàn bộ dữ liệu lịch sử phân tích"""

    def __init__(self):
        self.lock = threading.Lock()
        os.makedirs(FILES_DIR, exist_ok=True)
        if not os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                json.dump([], f, ensure_ascii=False, indent=2)

    def _read_history(self):
        try:
            if os.path.exists(HISTORY_FILE):
                with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception as e:
            print(f"[HISTORY LỖI ĐỌC] {e}")
        return []

    def _write_history(self, history):
        try:
            with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                json.dump(history, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[HISTORY LỖI GHI] {e}")

    def save_scan(self, file_content_bytes, original_filename, analysis_result):
        """Lưu file vật lý và lưu metadata/kết quả phân tích vào lịch sử"""
        with self.lock:
            now = datetime.now()
            scan_id = "scan_" + now.strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6]

            # Xử lý tên file an toàn tránh directory traversal
            clean_name = os.path.basename(original_filename or "uploaded_sample.bin")
            safe_name = "".join(c for c in clean_name if c.isalnum() or c in "._- ")
            if not safe_name:
                safe_name = "sample.bin"

            saved_filename = f"{scan_id}_{safe_name}"
            saved_filepath = os.path.join(FILES_DIR, saved_filename)

            # Lưu file nhị phân vào thư mục files
            try:
                with open(saved_filepath, "wb") as f:
                    f.write(file_content_bytes)
            except Exception as e:
                print(f"[HISTORY LỖI LƯU FILE]: {e}")

            # Tạo bản ghi tóm tắt & chi tiết
            download_url = f"/api/download/{scan_id}"
            record = {
                "id": scan_id,
                "file_name": clean_name,
                "saved_filename": saved_filename,
                "file_size": len(file_content_bytes),
                "file_size_formatted": analysis_result.get("file_size_formatted", f"{len(file_content_bytes)/1024:.2f} KB"),
                "timestamp": now.strftime("%d/%m/%Y %H:%M:%S"),
                "iso_time": now.isoformat(),
                "hashes": analysis_result.get("hashes", {}),
                "entropy": analysis_result.get("entropy", 0.0),
                "is_pe": analysis_result.get("is_pe", False),
                "file_type_detected": analysis_result.get("file_type_detected", "Không xác định"),
                "models_loaded": analysis_result.get("models_loaded", True),
                "algorithms": analysis_result.get("algorithms", {}),
                "consensus": analysis_result.get("consensus", {}),
                "threat_indicators": analysis_result.get("threat_indicators", []),
                "forensics": analysis_result.get("forensics", {}),
                "download_url": download_url
            }

            history = self._read_history()
            history.insert(0, record)
            # Giữ tối đa 200 bản ghi lịch sử gần nhất
            if len(history) > 200:
                history = history[:200]
            self._write_history(history)

            return scan_id, download_url

    def get_all_scans(self):
        with self.lock:
            return self._read_history()

    def get_scan(self, scan_id):
        with self.lock:
            history = self._read_history()
            for item in history:
                if item.get("id") == scan_id:
                    return item
        return None

    def get_file_info(self, scan_id):
        with self.lock:
            history = self._read_history()
            for item in history:
                if item.get("id") == scan_id:
                    saved_fn = item.get("saved_filename")
                    orig_fn = item.get("file_name", "downloaded_file.bin")
                    if saved_fn:
                        full_path = os.path.join(FILES_DIR, saved_fn)
                        return full_path, orig_fn
        return None, None

    def delete_scan(self, scan_id):
        with self.lock:
            history = self._read_history()
            new_history = []
            found = False
            for item in history:
                if item.get("id") == scan_id:
                    found = True
                    saved_fn = item.get("saved_filename")
                    if saved_fn:
                        p = os.path.join(FILES_DIR, saved_fn)
                        if os.path.exists(p):
                            try:
                                os.remove(p)
                            except Exception as e:
                                print(f"[HISTORY LỖI XÓA FILE]: {e}")
                else:
                    new_history.append(item)
            if found:
                self._write_history(new_history)
            return found

    def clear_all(self):
        with self.lock:
            history = self._read_history()
            for item in history:
                saved_fn = item.get("saved_filename")
                if saved_fn:
                    p = os.path.join(FILES_DIR, saved_fn)
                    if os.path.exists(p):
                        try:
                            os.remove(p)
                        except Exception:
                            pass
            self._write_history([])
            return True


history_manager = ScanHistoryManager()


class MalwareScannerHTTPHandler(BaseHTTPRequestHandler):

    def _set_cors_headers(self):
        """Thiết lập CORS để cho phép trình duyệt từ MinIO, Web, hoặc local gọi API"""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, X-File-Name')

    def do_OPTIONS(self):
        """Xử lý preflight CORS request"""
        self.send_response(200)
        self._set_cors_headers()
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_HEAD(self):
        """Hỗ trợ kiểm tra Header tệp tin"""
        self.do_GET()

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
                "version": "2.1.0",
                "total_scans_stored": len(history_manager.get_all_scans())
            }
            self.wfile.write(json.dumps(res, ensure_ascii=False).encode('utf-8'))
            return

        # 2. Lấy danh sách toàn bộ file đã quét / lịch sử
        if path in ["/api/scans", "/api/history"]:
            scans = history_manager.get_all_scans()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self._set_cors_headers()
            self.end_headers()
            res = {
                "status": "success",
                "total": len(scans),
                "scans": scans
            }
            self.wfile.write(json.dumps(res, ensure_ascii=False).encode('utf-8'))
            return

        # 3. Lấy chi tiết một bản ghi quét theo scan_id
        if path.startswith("/api/scan/"):
            scan_id = path.replace("/api/scan/", "").strip("/")
            record = history_manager.get_scan(scan_id)
            if record:
                self.send_response(200)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self._set_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps(record, ensure_ascii=False).encode('utf-8'))
            else:
                self.send_response(404)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self._set_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({"error": f"Không tìm thấy bản ghi quét '{scan_id}'"}).encode('utf-8'))
            return

        # 4. Tải xuống tệp tin gốc đã lưu theo scan_id
        if path.startswith("/api/download/"):
            scan_id = path.replace("/api/download/", "").strip("/")
            file_path, orig_name = history_manager.get_file_info(scan_id)
            if file_path and os.path.exists(file_path):
                try:
                    with open(file_path, 'rb') as f:
                        file_data = f.read()

                    self.send_response(200)
                    self.send_header('Content-Type', 'application/octet-stream')
                    safe_dl_name = orig_name.replace('"', '').replace('\r', '').replace('\n', '')
                    self.send_header('Content-Disposition', f'attachment; filename="{safe_dl_name}"')
                    self.send_header('Content-Length', str(len(file_data)))
                    self._set_cors_headers()
                    self.end_headers()
                    self.wfile.write(file_data)
                    return
                except Exception as e:
                    self.send_response(500)
                    self.send_header('Content-Type', 'application/json; charset=utf-8')
                    self._set_cors_headers()
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": f"Lỗi đọc file: {str(e)}"}).encode('utf-8'))
                    return
            else:
                self.send_response(404)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self._set_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Tệp tin không tồn tại hoặc đã bị xóa."}).encode('utf-8'))
                return

        # 5. Demo sample scan endpoint
        if path.startswith("/api/sample/"):
            sample_name = path.replace("/api/sample/", "")
            sample_dir = os.path.join(BASE_DIR, "malware_samples")
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
            # Lưu mẫu vào lịch sử luôn
            scan_id, dl_url = history_manager.save_scan(content, sample_name, analysis)
            analysis["scan_id"] = scan_id
            analysis["download_url"] = dl_url

            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(analysis, ensure_ascii=False).encode('utf-8'))
            return

        # 6. Phục vụ dashboard.html trực tiếp nếu truy cập http://localhost:5050
        if path in ["/", "/dashboard", "/dashboard.html", "/index.html"]:
            html_path = os.path.join(BASE_DIR, "reports", "dashboard.html")
            if not os.path.exists(html_path):
                html_path = os.path.join(BASE_DIR, "reports", "index.html")

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

        # 1. Endpoint Quét & Lưu trữ tệp tin
        if path == "/api/scan":
            try:
                content_type = self.headers.get('Content-Type', '')
                content_length = int(self.headers.get('Content-Length', 0))

                file_content = None
                file_name = "uploaded_file.bin"

                # Lấy tên file gửi kèm header nếu có
                header_filename = self.headers.get('X-File-Name')
                if header_filename:
                    try:
                        file_name = unquote(header_filename)
                    except Exception:
                        file_name = header_filename

                # Xử lý multipart/form-data
                if 'multipart/form-data' in content_type:
                    boundary_marker = "boundary="
                    if boundary_marker in content_type:
                        boundary = content_type.split(boundary_marker)[1].split(";")[0].strip().strip('"').strip("'").encode()
                    else:
                        boundary = b''

                    raw_body = self.rfile.read(content_length)

                    parts = raw_body.split(b'--' + boundary)
                    for part in parts:
                        if b'Content-Disposition' in part and b'filename="' in part:
                            header_body_split = part.split(b'\r\n\r\n', 1)
                            if len(header_body_split) == 2:
                                headers_part, body_part = header_body_split
                                for line in headers_part.split(b'\r\n'):
                                    if b'filename="' in line:
                                        try:
                                            fn_start = line.find(b'filename="') + 10
                                            fn_end = line.find(b'"', fn_start)
                                            parsed_fn = line[fn_start:fn_end].decode('utf-8', errors='ignore')
                                            if parsed_fn:
                                                file_name = parsed_fn
                                        except Exception:
                                            pass

                                if body_part.endswith(b'\r\n'):
                                    body_part = body_part[:-2]
                                file_content = body_part
                                break

                # Hoặc raw binary stream
                elif 'application/octet-stream' in content_type or content_length > 0:
                    file_content = self.rfile.read(content_length)

                if not file_content:
                    self.send_response(400)
                    self.send_header('Content-Type', 'application/json; charset=utf-8')
                    self._set_cors_headers()
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "Không tìm thấy dữ liệu tệp tin được tải lên."}).encode('utf-8'))
                    return

                # Phân tích file qua Scanner Engine
                engine = get_scanner_engine()
                result = engine.analyze_file(file_content, file_name=file_name)

                # Lưu trữ file vật lý và lưu vào lịch sử
                scan_id, dl_url = history_manager.save_scan(file_content, file_name, result)
                result["scan_id"] = scan_id
                result["download_url"] = dl_url

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

        # 2. Xóa 1 bản ghi qua POST (cho proxy/client không hỗ trợ DELETE)
        if path.startswith("/api/scan/") and path.endswith("/delete"):
            scan_id = path.replace("/api/scan/", "").replace("/delete", "").strip("/")
            success = history_manager.delete_scan(scan_id)
            self.send_response(200 if success else 404)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"status": "success" if success else "not_found", "deleted_id": scan_id}).encode('utf-8'))
            return

        # 3. Xóa toàn bộ lịch sử qua POST
        if path in ["/api/history/clear", "/api/scans/clear"]:
            history_manager.clear_all()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"status": "success", "message": "Đã xóa toàn bộ lịch sử tệp tin."}).encode('utf-8'))
            return

        # 404 Fallback
        self.send_response(404)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps({"error": "Endpoint không hợp lệ"}).encode('utf-8'))

    def do_DELETE(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        # 1. Xóa 1 bản ghi quét
        if path.startswith("/api/scan/"):
            scan_id = path.replace("/api/scan/", "").strip("/")
            success = history_manager.delete_scan(scan_id)
            self.send_response(200 if success else 404)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"status": "success" if success else "not_found", "deleted_id": scan_id}).encode('utf-8'))
            return

        # 2. Xóa toàn bộ lịch sử
        if path in ["/api/history", "/api/scans", "/api/history/clear"]:
            history_manager.clear_all()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"status": "success", "message": "Đã xóa toàn bộ lịch sử tệp tin."}).encode('utf-8'))
            return

        self.send_response(404)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps({"error": "Endpoint không hợp lệ"}).encode('utf-8'))

    def log_message(self, format, *args):
        # Log ngắn gọn
        print(f"[SCANNER API] {self.address_string()} - {args[0]}")


def run_server():
    server_address = (HOST, PORT)
    httpd = ThreadingHTTPServer(server_address, MalwareScannerHTTPHandler)
    print("=" * 70)
    print(f"🛡️  SHIELD-AI MALWARE SCANNER API SERVER ĐANG CHẠY...")
    print(f"📡  Lắng nghe trên:     http://localhost:{PORT}")
    print(f"🔍  Quét & Lưu tệp:      POST http://localhost:{PORT}/api/scan")
    print(f"📁  Danh sách đã quét:  GET  http://localhost:{PORT}/api/scans")
    print(f"📥  Tải lại tệp gốc:    GET  http://localhost:{PORT}/api/download/<scan_id>")
    print(f"💚  Kiểm tra kết nối:   GET  http://localhost:{PORT}/api/health")
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

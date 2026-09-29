"""
scanner_engine.py
Engine phân tích tệp tin người dùng tải lên, trích xuất đặc trưng tĩnh / PE Headers
và thực hiện suy luận dự đoán mã độc bằng 3 mô hình: Random Forest, XGBoost, MLP.
"""

import os
import sys
import json
import math
import hashlib
import struct
import joblib
import numpy as np
import pandas as pd
from collections import Counter

# Danh sách API hàm đáng ngờ thường xuất hiện trong mã độc / ransomware / trojan
SUSPICIOUS_APIS = [
    'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx',
    'WriteProcessMemory', 'CreateRemoteThread', 'OpenProcess', 'SetWindowsHookEx',
    'GetAsyncKeyState', 'GetProcAddress', 'LoadLibraryA', 'LoadLibraryW',
    'URLDownloadToFile', 'URLDownloadToFileA', 'URLDownloadToFileW',
    'InternetOpenA', 'InternetOpenW', 'InternetConnectA', 'HttpSendRequestA',
    'RegSetValueExA', 'RegSetValueExW', 'RegCreateKeyA', 'RegCreateKeyExA',
    'ShellExecuteA', 'ShellExecuteW', 'WinExec', 'CreateProcessA', 'CreateProcessW',
    'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'CryptEncrypt', 'CryptDecrypt'
]

# Danh sách tên section thường thấy ở packer / crypter
SUSPICIOUS_SECTION_NAMES = {
    'upx0', 'upx1', 'upx2', 'aspack', 'fsg', 'themida', 'vmp0', 'vmp1',
    'pec1', 'pec2', 'nsp0', 'nsp1', 'petite', 'mew', 'yoda'
}


class MalwareScannerEngine:
    def __init__(self, model_dir=None):
        if model_dir is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            self.model_dir = os.path.join(base_dir, "models")
        else:
            self.model_dir = model_dir

        self.rf_model = None
        self.xgb_model = None
        self.mlp_model = None
        self.scaler = None
        self.metadata = None
        self.models_loaded = False
        self._load_models()

    def _load_models(self):
        """Nạp các mô hình đã huấn luyện từ đĩa. Nếu chưa có, tiến hành huấn luyện tự động."""
        meta_path = os.path.join(self.model_dir, "model_metadata.json")
        rf_path = os.path.join(self.model_dir, "rf_malware_model.pkl")
        xgb_path = os.path.join(self.model_dir, "xgb_malware_model.pkl")
        mlp_path = os.path.join(self.model_dir, "mlp_malware_model.pkl")
        scaler_path = os.path.join(self.model_dir, "pe_scaler.pkl")

        if not (os.path.exists(rf_path) and os.path.exists(meta_path)):
            print("[ENGINE] Chưa tìm thấy mô hình đã lưu, đang khởi tạo huấn luyện tự động...")
            try:
                from train_detector_models import train_and_export_models
                train_and_export_models()
            except Exception as e:
                print(f"[ENGINE LỖI] Huấn luyện tự động thất bại: {e}")

        # Nạp mô hình nếu file tồn tại
        try:
            if os.path.exists(meta_path):
                with open(meta_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
            if os.path.exists(rf_path):
                self.rf_model = joblib.load(rf_path)
            if os.path.exists(xgb_path):
                self.xgb_model = joblib.load(xgb_path)
            if os.path.exists(mlp_path):
                self.mlp_model = joblib.load(mlp_path)
            if os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)

            if self.rf_model is not None and self.metadata is not None:
                self.models_loaded = True
                print(">> [ENGINE SẴN SÀNG] Đã nạp thành công bộ 3 mô hình học máy phát hiện mã độc!")
            else:
                print(">> [ENGINE CẢNH BÁO] Chưa nạp đầy đủ các mô hình.")
        except Exception as e:
            print(f"[ENGINE LỖI] Lỗi khi nạp mô hình: {e}")

    @staticmethod
    def calculate_entropy(byte_data):
        """Tính toán Shannon Entropy của chuỗi byte (giá trị từ 0.0 đến 8.0)"""
        if not byte_data:
            return 0.0
        occ = Counter(byte_data)
        entropy = 0.0
        total_len = len(byte_data)
        for count in occ.values():
            p = float(count) / total_len
            entropy -= p * math.log(p, 2)
        return round(entropy, 4)

    @staticmethod
    def calculate_hashes(byte_data):
        """Tính toán các mã băm nhận diện tệp (MD5, SHA1, SHA256)"""
        return {
            "md5": hashlib.md5(byte_data).hexdigest(),
            "sha1": hashlib.sha1(byte_data).hexdigest(),
            "sha256": hashlib.sha256(byte_data).hexdigest()
        }

    def parse_pe_features(self, byte_data, file_path=None):
        """
        Trích xuất các trường đặc trưng chuẩn PE Header từ file byte_data.
        Sử dụng pefile nếu có, hoặc fallback sang native struct parser.
        """
        features_dict = {}
        suspicious_apis_found = []
        suspicious_sections_found = []
        is_pe = False

        # Kiểm tra Magic 'MZ'
        if len(byte_data) > 64 and byte_data[:2] == b'MZ':
            try:
                # Kiểm tra PE offset tại 0x3C
                pe_offset = struct.unpack('<I', byte_data[0x3C:0x40])[0]
                if pe_offset < len(byte_data) - 4 and byte_data[pe_offset:pe_offset+4] == b'PE\0\0':
                    is_pe = True
            except Exception:
                is_pe = False

        # 1. Thử dùng pefile nếu có
        used_pefile = False
        if is_pe:
            try:
                import pefile
                pe = pefile.PE(data=byte_data, fast_load=False)
                used_pefile = True

                # DOS Header
                features_dict['e_magic'] = getattr(pe.DOS_HEADER, 'e_magic', 23117)
                features_dict['e_cblp'] = getattr(pe.DOS_HEADER, 'e_cblp', 144)
                features_dict['e_cp'] = getattr(pe.DOS_HEADER, 'e_cp', 3)
                features_dict['e_crlc'] = getattr(pe.DOS_HEADER, 'e_crlc', 0)
                features_dict['e_cparhdr'] = getattr(pe.DOS_HEADER, 'e_cparhdr', 4)
                features_dict['e_minalloc'] = getattr(pe.DOS_HEADER, 'e_minalloc', 0)
                features_dict['e_maxalloc'] = getattr(pe.DOS_HEADER, 'e_maxalloc', 65535)
                features_dict['e_ss'] = getattr(pe.DOS_HEADER, 'e_ss', 0)
                features_dict['e_sp'] = getattr(pe.DOS_HEADER, 'e_sp', 184)
                features_dict['e_csum'] = getattr(pe.DOS_HEADER, 'e_csum', 0)
                features_dict['e_ip'] = getattr(pe.DOS_HEADER, 'e_ip', 0)
                features_dict['e_cs'] = getattr(pe.DOS_HEADER, 'e_cs', 0)
                features_dict['e_lfarlc'] = getattr(pe.DOS_HEADER, 'e_lfarlc', 64)
                features_dict['e_ovno'] = getattr(pe.DOS_HEADER, 'e_ovno', 0)
                features_dict['e_oemid'] = getattr(pe.DOS_HEADER, 'e_oemid', 0)
                features_dict['e_oeminfo'] = getattr(pe.DOS_HEADER, 'e_oeminfo', 0)
                features_dict['e_lfanew'] = getattr(pe.DOS_HEADER, 'e_lfanew', pe_offset)

                # File Header
                fh = pe.FILE_HEADER
                features_dict['Machine'] = getattr(fh, 'Machine', 332)
                features_dict['NumberOfSections'] = getattr(fh, 'NumberOfSections', len(pe.sections))
                features_dict['TimeDateStamp'] = getattr(fh, 'TimeDateStamp', 0)
                features_dict['PointerToSymbolTable'] = getattr(fh, 'PointerToSymbolTable', 0)
                features_dict['NumberOfSymbols'] = getattr(fh, 'NumberOfSymbols', 0)
                features_dict['SizeOfOptionalHeader'] = getattr(fh, 'SizeOfOptionalHeader', 224)
                features_dict['Characteristics'] = getattr(fh, 'Characteristics', 258)

                # Optional Header
                if hasattr(pe, 'OPTIONAL_HEADER'):
                    oh = pe.OPTIONAL_HEADER
                    features_dict['Magic'] = getattr(oh, 'Magic', 267)
                    features_dict['MajorLinkerVersion'] = getattr(oh, 'MajorLinkerVersion', 9)
                    features_dict['MinorLinkerVersion'] = getattr(oh, 'MinorLinkerVersion', 0)
                    features_dict['SizeOfCode'] = getattr(oh, 'SizeOfCode', 0)
                    features_dict['SizeOfInitializedData'] = getattr(oh, 'SizeOfInitializedData', 0)
                    features_dict['SizeOfUninitializedData'] = getattr(oh, 'SizeOfUninitializedData', 0)
                    features_dict['AddressOfEntryPoint'] = getattr(oh, 'AddressOfEntryPoint', 0)
                    features_dict['BaseOfCode'] = getattr(oh, 'BaseOfCode', 4096)
                    features_dict['ImageBase'] = getattr(oh, 'ImageBase', 4194304)
                    features_dict['SectionAlignment'] = getattr(oh, 'SectionAlignment', 4096)
                    features_dict['FileAlignment'] = getattr(oh, 'FileAlignment', 512)
                    features_dict['MajorOperatingSystemVersion'] = getattr(oh, 'MajorOperatingSystemVersion', 4)
                    features_dict['MinorOperatingSystemVersion'] = getattr(oh, 'MinorOperatingSystemVersion', 0)
                    features_dict['MajorImageVersion'] = getattr(oh, 'MajorImageVersion', 0)
                    features_dict['MinorImageVersion'] = getattr(oh, 'MinorImageVersion', 0)
                    features_dict['MajorSubsystemVersion'] = getattr(oh, 'MajorSubsystemVersion', 4)
                    features_dict['MinorSubsystemVersion'] = getattr(oh, 'MinorSubsystemVersion', 0)
                    features_dict['SizeOfHeaders'] = getattr(oh, 'SizeOfHeaders', 1024)
                    features_dict['CheckSum'] = getattr(oh, 'CheckSum', 0)
                    features_dict['SizeOfImage'] = getattr(oh, 'SizeOfImage', 0)
                    features_dict['Subsystem'] = getattr(oh, 'Subsystem', 2)
                    features_dict['DllCharacteristics'] = getattr(oh, 'DllCharacteristics', 0)
                    features_dict['SizeOfStackReserve'] = getattr(oh, 'SizeOfStackReserve', 1048576)
                    features_dict['SizeOfStackCommit'] = getattr(oh, 'SizeOfStackCommit', 4096)
                    features_dict['SizeOfHeapReserve'] = getattr(oh, 'SizeOfHeapReserve', 1048576)
                    features_dict['SizeOfHeapCommit'] = getattr(oh, 'SizeOfHeapCommit', 4096)
                    features_dict['LoaderFlags'] = getattr(oh, 'LoaderFlags', 0)
                    features_dict['NumberOfRvaAndSizes'] = getattr(oh, 'NumberOfRvaAndSizes', 16)

                # Sections Analysis
                entropies = []
                raw_sizes = []
                virt_sizes = []
                for s in pe.sections:
                    sec_name = s.Name.decode('latin-1', errors='ignore').strip('\x00').lower()
                    if sec_name in SUSPICIOUS_SECTION_NAMES or sec_name == '':
                        suspicious_sections_found.append(sec_name if sec_name else "[rỗng]")
                    s_entropy = s.get_entropy()
                    entropies.append(s_entropy)
                    raw_sizes.append(s.SizeOfRawData)
                    virt_sizes.append(s.Misc_VirtualSize)

                features_dict['SectionsLength'] = len(pe.sections)
                features_dict['SectionMinEntropy'] = min(entropies) if entropies else 0.0
                features_dict['SectionMaxEntropy'] = max(entropies) if entropies else 0.0
                features_dict['SectionMinRawsize'] = min(raw_sizes) if raw_sizes else 0
                features_dict['SectionMaxRawsize'] = max(raw_sizes) if raw_sizes else 0
                features_dict['SectionMinVirtualsize'] = min(virt_sizes) if virt_sizes else 0
                features_dict['SectionMaxVirtualsize'] = max(virt_sizes) if virt_sizes else 0
                features_dict['SuspiciousNameSection'] = len(suspicious_sections_found)

                # Imports Analysis
                susp_func_count = 0
                import_dir_size = 0
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        import_dir_size += len(entry.imports)
                        for imp in entry.imports:
                            if imp.name:
                                func_name = imp.name.decode('latin-1', errors='ignore')
                                for s_api in SUSPICIOUS_APIS:
                                    if s_api.lower() == func_name.lower():
                                        susp_func_count += 1
                                        if func_name not in suspicious_apis_found:
                                            suspicious_apis_found.append(func_name)

                features_dict['SuspiciousImportFunctions'] = susp_func_count
                features_dict['DirectoryEntryImport'] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0
                features_dict['DirectoryEntryImportSize'] = import_dir_size
                features_dict['DirectoryEntryExport'] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0

                pe.close()
            except Exception as pe_err:
                print(f"[pefile parser error]: {pe_err}")
                used_pefile = False

        # 2. Fallback sang Native Parser nếu pefile không dùng được
        if is_pe and not used_pefile:
            try:
                features_dict['e_magic'] = 23117
                features_dict['e_lfanew'] = pe_offset
                fh_offset = pe_offset + 4
                if fh_offset + 20 <= len(byte_data):
                    machine, num_sections, timedatestamp, p_sym, num_sym, opt_hdr_sz, charact = struct.unpack(
                        '<HHIIIHH', byte_data[fh_offset:fh_offset+20]
                    )
                    features_dict['Machine'] = machine
                    features_dict['NumberOfSections'] = num_sections
                    features_dict['TimeDateStamp'] = timedatestamp
                    features_dict['SizeOfOptionalHeader'] = opt_hdr_sz
                    features_dict['Characteristics'] = charact
                    features_dict['SectionsLength'] = num_sections

                # Quét chuỗi tìm API đáng ngờ trong binary
                for api in SUSPICIOUS_APIS:
                    if api.encode('latin-1') in byte_data:
                        suspicious_apis_found.append(api)
                features_dict['SuspiciousImportFunctions'] = len(suspicious_apis_found)
                features_dict['SectionMaxEntropy'] = self.calculate_entropy(byte_data)
            except Exception as e:
                print(f"[Native struct parser error]: {e}")

        # 3. Nếu là file phi PE (scripts, documents, etc.)
        if not is_pe:
            file_entropy = self.calculate_entropy(byte_data)
            features_dict['SectionsLength'] = 0
            features_dict['SectionMinEntropy'] = file_entropy
            features_dict['SectionMaxEntropy'] = file_entropy
            # Tìm kiếm từ khóa mã độc nhị phân
            generic_threat_patterns = [
                b'powershell', b'cmd.exe', b'eval(', b'base64_decode',
                b'WScript.Shell', b'AutoRun', b'CreateObject'
            ]
            for pat in generic_threat_patterns:
                if pat in byte_data.lower():
                    suspicious_apis_found.append(pat.decode('latin-1', errors='ignore'))
            features_dict['SuspiciousImportFunctions'] = len(suspicious_apis_found)

        return {
            "is_pe": is_pe,
            "features_dict": features_dict,
            "suspicious_apis": suspicious_apis_found,
            "suspicious_sections": suspicious_sections_found
        }

    def analyze_file(self, file_content_bytes, file_name="uploaded_sample.bin"):
        """
        Phân tích toàn diện file người dùng tải lên:
        - Tính Hash, Entropy
        - Trích xuất PE / Static Features
        - Dự đoán bằng 3 mô hình (RF, XGBoost, MLP)
        - Đưa ra SOC Consensus Verdict
        """
        file_size = len(file_content_bytes)
        file_hashes = self.calculate_hashes(file_content_bytes)
        entropy = self.calculate_entropy(file_content_bytes)

        # Phân tích cấu trúc PE
        pe_info = self.parse_pe_features(file_content_bytes)
        is_pe = pe_info["is_pe"]
        features_dict = pe_info["features_dict"]
        suspicious_apis = pe_info["suspicious_apis"]
        suspicious_sections = pe_info["suspicious_sections"]

        # Định dạng vector đặc trưng phù hợp với mô hình đã huấn luyện
        rf_result = {"prediction": 0, "probability": 0.0, "status": "Clean"}
        xgb_result = {"prediction": 0, "probability": 0.0, "status": "Clean"}
        mlp_result = {"prediction": 0, "probability": 0.0, "status": "Clean"}

        if self.metadata is not None and "feature_cols" in self.metadata:
            cols = self.metadata["feature_cols"]
            medians = self.metadata.get("feature_medians", {})

            # Xây dựng dòng dữ liệu vector
            row_vals = []
            for col in cols:
                if col in features_dict:
                    val = features_dict[col]
                elif col in medians:
                    val = medians[col]
                else:
                    val = 0.0
                try:
                    row_vals.append(float(val))
                except Exception:
                    row_vals.append(0.0)

            X_vector = np.array([row_vals])

            # Dự đoán Random Forest
            if self.rf_model is not None:
                try:
                    prob = float(self.rf_model.predict_proba(X_vector)[0, 1])
                    pred = int(prob >= 0.5)
                    rf_result = {
                        "prediction": pred,
                        "probability": round(prob, 4),
                        "status": "Malware" if pred == 1 else "Benign"
                    }
                except Exception as e:
                    print(f"[RF Predict Error]: {e}")

            # Dự đoán XGBoost
            if self.xgb_model is not None:
                try:
                    prob = float(self.xgb_model.predict_proba(X_vector)[0, 1])
                    pred = int(prob >= 0.5)
                    xgb_result = {
                        "prediction": pred,
                        "probability": round(prob, 4),
                        "status": "Malware" if pred == 1 else "Benign"
                    }
                except Exception as e:
                    print(f"[XGB Predict Error]: {e}")

            # Dự đoán MLP (cần chuẩn hóa bằng Scaler)
            if self.mlp_model is not None and self.scaler is not None:
                try:
                    X_scaled = self.scaler.transform(X_vector)
                    prob = float(self.mlp_model.predict_proba(X_scaled)[0, 1])
                    pred = int(prob >= 0.5)
                    mlp_result = {
                        "prediction": pred,
                        "probability": round(prob, 4),
                        "status": "Malware" if pred == 1 else "Benign"
                    }
                except Exception as e:
                    print(f"[MLP Predict Error]: {e}")

        # Nếu tệp không phải PE thực thi và không chứa payload nguy hiểm:
        # Không áp đặt dự đoán PE lên tệp dữ liệu thông thường để tránh dương tính giả
        if not is_pe:
            if len(suspicious_apis) == 0 and entropy < 7.0:
                rf_result = {"prediction": 0, "probability": 0.02, "status": "Benign"}
                xgb_result = {"prediction": 0, "probability": 0.01, "status": "Benign"}
                mlp_result = {"prediction": 0, "probability": 0.01, "status": "Benign"}
                ensemble_risk = 0.02
            elif len(suspicious_apis) > 0:
                risk_val = min(0.95, 0.45 + len(suspicious_apis) * 0.15)
                rf_result = {"prediction": 1, "probability": round(risk_val, 4), "status": "Malware"}
                xgb_result = {"prediction": 1, "probability": round(risk_val, 4), "status": "Malware"}
                mlp_result = {"prediction": 1, "probability": round(risk_val, 4), "status": "Malware"}
                ensemble_risk = risk_val
            elif entropy >= 7.0:
                risk_val = min(0.85, 0.50 + (entropy - 7.0) * 0.3)
                rf_result = {"prediction": 1 if risk_val >= 0.5 else 0, "probability": round(risk_val, 4), "status": "Malware" if risk_val >= 0.5 else "Benign"}
                xgb_result = {"prediction": 1 if risk_val >= 0.5 else 0, "probability": round(risk_val, 4), "status": "Malware" if risk_val >= 0.5 else "Benign"}
                mlp_result = {"prediction": 1 if risk_val >= 0.5 else 0, "probability": round(risk_val, 4), "status": "Malware" if risk_val >= 0.5 else "Benign"}
                ensemble_risk = risk_val
            else:
                ensemble_risk = (
                    xgb_result["probability"] * 0.40 +
                    rf_result["probability"] * 0.35 +
                    mlp_result["probability"] * 0.25
                )
        else:
            # Heuristic Risk & Consensus Calculation cho tệp PE
            # Trọng số kết hợp: XGBoost (40%), Random Forest (35%), MLP (25%)
            ensemble_risk = (
                xgb_result["probability"] * 0.40 +
                rf_result["probability"] * 0.35 +
                mlp_result["probability"] * 0.25
            )

        # Đánh giá cảnh báo đặc trưng (Threat Indicators)
        threat_indicators = []
        if entropy > 7.15:
            threat_indicators.append({
                "type": "HIGH_ENTROPY",
                "severity": "CRITICAL",
                "message": f"Độ hỗn loạn Entropy rất cao ({entropy}/8.0): Dấu hiệu mã bị nén (Packer) hoặc mã hóa Ransomware nhằm né tránh Antivirus."
            })
        elif entropy > 6.7:
            threat_indicators.append({
                "type": "ELEVATED_ENTROPY",
                "severity": "MEDIUM",
                "message": f"Entropy ở mức trung bình cao ({entropy}/8.0): Tệp tin có thể chứa dữ liệu tài nguyên mã hóa hoặc nén."
            })

        if len(suspicious_apis) > 0:
            threat_indicators.append({
                "type": "SUSPICIOUS_APIS",
                "severity": "HIGH" if len(suspicious_apis) >= 3 else "MEDIUM",
                "message": f"Phát hiện {len(suspicious_apis)} hàm gọi API an ninh mạng nguy hiểm: {', '.join(suspicious_apis[:6])}" + ("..." if len(suspicious_apis) > 6 else "")
            })

        if len(suspicious_sections) > 0:
            threat_indicators.append({
                "type": "SUSPICIOUS_SECTIONS",
                "severity": "HIGH",
                "message": f"Phát hiện Section bất thường đặc trưng của Packer/Crypter: {', '.join(suspicious_sections)}"
            })

        if not is_pe and len(suspicious_apis) > 0:
            threat_indicators.append({
                "type": "MALICIOUS_SCRIPT_PATTERNS",
                "severity": "CRITICAL",
                "message": "Phát hiện mẫu lệnh thực thi script nguy hiểm (PowerShell / Shell / Base64 Payload)."
            })

        # Điều chỉnh ensemble_risk nếu có quá nhiều chỉ báo nguy hiểm thực tế
        if len(suspicious_apis) >= 4 and entropy > 7.0 and ensemble_risk < 0.75:
            ensemble_risk = max(ensemble_risk, 0.85)

        # Xếp loại kết luận cuối cùng (SOC Consensus Verdict)
        if ensemble_risk >= 0.70:
            verdict = "MALWARE DETECTED"
            verdict_vi = "🚨 PHÁT HIỆN MÃ ĐỘC NGUY HIỂM"
            threat_level = "CRITICAL"
            badge_color = "#f43f5e"
            action_recommendation = "Cách ly tệp tin ngay lập tức. Khuyến cáo không thực thi tệp tin này trên hệ điều hành thực."
        elif ensemble_risk >= 0.40:
            verdict = "SUSPICIOUS / ELEVATED RISK"
            verdict_vi = "⚠️ TỆP TIN ĐÁNG NGỜ / RỦI RO CAO"
            threat_level = "WARNING"
            badge_color = "#f59e0b"
            action_recommendation = "Cần phân tích chuyên sâu thêm trong môi trường Sandbox cô lập trước khi cho phép người dùng chạy."
        else:
            verdict = "BENIGN / CLEAN"
            verdict_vi = "🛡️ TỆP TIN AN TOÀN / LÀNH TÍNH"
            threat_level = "SAFE"
            badge_color = "#10b981"
            action_recommendation = "Không tìm thấy dấu hiệu mã độc rõ ràng từ 3 mô hình học máy. Tệp tin đạt chuẩn an toàn."

        return {
            "file_name": file_name,
            "file_size": file_size,
            "file_size_formatted": f"{file_size / 1024:.2f} KB" if file_size < 1048576 else f"{file_size / 1048576:.2f} MB",
            "hashes": file_hashes,
            "entropy": entropy,
            "is_pe": is_pe,
            "file_type_detected": "Windows PE Executable (EXE/DLL)" if is_pe else "Binary / Script / Document",
            "models_loaded": self.models_loaded,
            "algorithms": {
                "Random Forest": rf_result,
                "XGBoost": xgb_result,
                "Deep Learning (MLP)": mlp_result
            },
            "consensus": {
                "verdict": verdict,
                "verdict_vi": verdict_vi,
                "threat_level": threat_level,
                "risk_score_percent": round(ensemble_risk * 100, 2),
                "badge_color": badge_color,
                "action_recommendation": action_recommendation
            },
            "threat_indicators": threat_indicators,
            "forensics": {
                "suspicious_apis_count": len(suspicious_apis),
                "suspicious_apis_list": suspicious_apis,
                "suspicious_sections": suspicious_sections,
                "sections_count": features_dict.get("SectionsLength", 0),
                "extracted_features_sample": {k: features_dict[k] for k in list(features_dict.keys())[:12]}
            }
        }


# Khởi tạo singleton engine
_global_engine = None

def get_scanner_engine():
    global _global_engine
    if _global_engine is None:
        _global_engine = MalwareScannerEngine()
    return _global_engine


if __name__ == "__main__":
    engine = MalwareScannerEngine()
    print(">> Scanner Engine Test initialized successfully.")

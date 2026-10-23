# -*- coding: utf-8 -*-
"""
train_detector_models.py
Huấn luyện và đóng gói bộ mô hình học máy đa miền (Multi-Domain Machine Learning Models):
1. PE Malware Models: Random Forest, XGBoost, MLP (dataset_malwares.csv - 77 đặc trưng PE)
2. PDF Malware Models: Random Forest, XGBoost, MLP (PDF_Malware_Structural_2022.csv)
3. Script Malware Models: Random Forest, XGBoost, MLP (Malicious_Scripts_PowerShell_VBS.csv)
4. Office Macro Models: Random Forest, XGBoost, MLP (Office_Macro_OLE_Malware.csv)

Toàn bộ mô hình sau khi huấn luyện được lưu trữ trong dags/models/ phục vụ Scanner suy luận thời gian thực.
"""

import os
import sys
import json
import joblib
import pandas as pd
import numpy as np

# Cấu hình hỗ trợ mã hóa UTF-8 trên mọi môi trường Windows/Linux
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except ImportError:
    HAS_XGB = False
    from sklearn.ensemble import GradientBoostingClassifier


def build_models():
    """Tạo bộ 3 thuật toán phân loại tiêu chuẩn"""
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_leaf=2,
        min_samples_split=4,
        max_features='sqrt',
        class_weight='balanced',
        n_jobs=-1,
        random_state=42
    )

    if HAS_XGB:
        xgb = XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            eval_metric='logloss',
            random_state=42,
            n_jobs=-1
        )
    else:
        xgb = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            random_state=42
        )

    mlp = MLPClassifier(
        hidden_layer_sizes=(64, 32),
        activation='relu',
        solver='adam',
        alpha=0.0005,
        batch_size=64,
        learning_rate_init=0.001,
        max_iter=150,
        early_stopping=True,
        n_iter_no_change=10,
        random_state=42
    )
    return rf, xgb, mlp


def train_domain(domain_name, dataset_filename, target_candidates, id_cols, model_prefix, model_dir):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_path = os.path.join(base_dir, "datasets", dataset_filename)
    if not os.path.exists(dataset_path):
        print(f"[{domain_name.upper()} LỖI] Không tìm thấy dataset: {dataset_path}")
        return None

    print("\n" + "=" * 70)
    print(f"[{domain_name.upper()}] HUẤN LUYỆN BỘ 3 MÔ HÌNH: {dataset_filename}")
    print("=" * 70)

    df = pd.read_csv(dataset_path)
    print(f">> Nạp thành công {len(df):,} mẫu, {len(df.columns)} cột.")

    # Tìm cột nhãn
    target_col = None
    for cand in target_candidates:
        for c in df.columns:
            if str(c).strip().lower() == cand.lower():
                target_col = c
                break
        if target_col:
            break
    if target_col is None:
        target_col = df.columns[-1]

    # Lọc bỏ cột định danh và nhãn
    feature_cols = [c for c in df.columns if c != target_col and c not in id_cols]
    
    # Ép kiểu số & tính median
    X_df = df[feature_cols].apply(pd.to_numeric, errors='coerce')
    medians = X_df.median().to_dict()
    X_df = X_df.fillna(X_df.median()).fillna(0.0)

    # Chuyển nhãn về 0 / 1
    y_raw = df[target_col].astype(str).str.strip().str.lower()
    if set(y_raw.unique()).issubset({'0', '1'}):
        y = y_raw.astype(int).values
    elif any(pos in y_raw.values for pos in ['malware', '1', 'attack', 'suspicious']):
        y = y_raw.apply(lambda val: 1 if any(pos in val for pos in ['malware', '1', 'attack', 'suspicious']) else 0).values
    else:
        # Nhị phân hóa theo lớp đầu tiên
        first_cls = y_raw.unique()[0]
        y = (y_raw != first_cls).astype(int).values

    X = X_df.values

    # Chia train/test (80/20)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # Scaler
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    scaler_filename = f"{model_prefix}_scaler.pkl"
    joblib.dump(scaler, os.path.join(model_dir, scaler_filename))

    rf, xgb, mlp = build_models()
    results = {}

    # 1. Random Forest
    rf.fit(X_train, y_train)
    rf_pred = rf.predict(X_test)
    rf_prob = rf.predict_proba(X_test)[:, 1] if hasattr(rf, 'predict_proba') else rf_pred
    rf_metrics = {
        "accuracy": round(float(accuracy_score(y_test, rf_pred)), 4),
        "precision": round(float(precision_score(y_test, rf_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, rf_pred, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_test, rf_pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, rf_prob)), 4)
    }
    joblib.dump(rf, os.path.join(model_dir, f"{model_prefix}_rf_model.pkl"))
    results["Random Forest"] = rf_metrics
    print(f"  [1/3] Random Forest: Acc={rf_metrics['accuracy']*100:.2f}% | F1={rf_metrics['f1_score']*100:.2f}% | AUC={rf_metrics['roc_auc']:.4f}")

    # 2. XGBoost
    xgb.fit(X_train, y_train)
    xgb_pred = xgb.predict(X_test)
    xgb_prob = xgb.predict_proba(X_test)[:, 1] if hasattr(xgb, 'predict_proba') else xgb_pred
    xgb_metrics = {
        "accuracy": round(float(accuracy_score(y_test, xgb_pred)), 4),
        "precision": round(float(precision_score(y_test, xgb_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, xgb_pred, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_test, xgb_pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, xgb_prob)), 4)
    }
    joblib.dump(xgb, os.path.join(model_dir, f"{model_prefix}_xgb_model.pkl"))
    results["XGBoost"] = xgb_metrics
    print(f"  [2/3] XGBoost:       Acc={xgb_metrics['accuracy']*100:.2f}% | F1={xgb_metrics['f1_score']*100:.2f}% | AUC={xgb_metrics['roc_auc']:.4f}")

    # 3. MLP
    mlp.fit(X_train_scaled, y_train)
    mlp_pred = mlp.predict(X_test_scaled)
    mlp_prob = mlp.predict_proba(X_test_scaled)[:, 1] if hasattr(mlp, 'predict_proba') else mlp_pred
    mlp_metrics = {
        "accuracy": round(float(accuracy_score(y_test, mlp_pred)), 4),
        "precision": round(float(precision_score(y_test, mlp_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, mlp_pred, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_test, mlp_pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, mlp_prob)), 4)
    }
    joblib.dump(mlp, os.path.join(model_dir, f"{model_prefix}_mlp_model.pkl"))
    results["MLP"] = mlp_metrics
    print(f"  [3/3] Deep MLP:      Acc={mlp_metrics['accuracy']*100:.2f}% | F1={mlp_metrics['f1_score']*100:.2f}% | AUC={mlp_metrics['roc_auc']:.4f}")

    return {
        "dataset_name": dataset_filename,
        "total_samples": len(df),
        "feature_cols": feature_cols,
        "feature_medians": {k: float(v) if not np.isnan(v) else 0.0 for k, v in medians.items()},
        "metrics": results
    }


def train_and_export_models():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    model_dir = os.path.join(base_dir, "models")
    os.makedirs(model_dir, exist_ok=True)

    print("=" * 70)
    print("🚀 BẮT ĐẦU HUẤN LUYỆN BỘ MÔ HÌNH HỌC MÁY ĐA ĐỊNH DẠNG CHO SCANNER ENGINE")
    print("=" * 70)

    # 1. PE Malware Models (Giữ tên file cũ để tương thích hoàn toàn: rf_malware_model.pkl, xgb_malware_model.pkl, mlp_malware_model.pkl, pe_scaler.pkl)
    pe_meta = train_domain(
        domain_name="PE Windows Executables",
        dataset_filename="dataset_malwares.csv",
        target_candidates=['malware', 'label', 'class'],
        id_cols=['Name', 'md5', 'hash'],
        model_prefix="pe",
        model_dir=model_dir
    )
    # Tạo symlink hoặc copy ra rf_malware_model.pkl cho tương thích ngược
    if pe_meta:
        for m in ['rf', 'xgb', 'mlp']:
            src = os.path.join(model_dir, f"pe_{m}_model.pkl")
            dst = os.path.join(model_dir, f"{m}_malware_model.pkl")
            if os.path.exists(src):
                joblib.dump(joblib.load(src), dst)

    # 2. PDF Malware Models
    pdf_meta = train_domain(
        domain_name="PDF Documents (CIC-Evasive-PDFMal2022)",
        dataset_filename="PDF_Malware_Structural_2022.csv",
        target_candidates=['label', 'class'],
        id_cols=['id', 'name', 'filename'],
        model_prefix="pdf",
        model_dir=model_dir
    )

    # 3. Script Malware Models (PowerShell, VBS, Batch)
    script_meta = train_domain(
        domain_name="Script Threats (PowerShell/VBS/BAT)",
        dataset_filename="Malicious_Scripts_PowerShell_VBS.csv",
        target_candidates=['label', 'class'],
        id_cols=['id', 'name', 'filename'],
        model_prefix="script",
        model_dir=model_dir
    )

    # 4. Office Documents Macro Models
    office_meta = train_domain(
        domain_name="MS Office Macro Threats",
        dataset_filename="Office_Macro_OLE_Malware.csv",
        target_candidates=['label', 'class'],
        id_cols=['id', 'name', 'filename'],
        model_prefix="office",
        model_dir=model_dir
    )

    # Xuất file metadata tổng thể
    full_metadata = {
        "trained_date": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
        "version": "3.0.0-multi-domain",
        "domains": {
            "pe": pe_meta,
            "pdf": pdf_meta,
            "script": script_meta,
            "office": office_meta
        },
        # Tương thích ngược với scanner_engine phiên bản trước
        "feature_cols": pe_meta["feature_cols"] if pe_meta else [],
        "feature_medians": pe_meta["feature_medians"] if pe_meta else {},
        "metrics": pe_meta["metrics"] if pe_meta else {}
    }

    meta_path = os.path.join(model_dir, "model_metadata.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(full_metadata, f, indent=2, ensure_ascii=False)

    print("\n" + "=" * 70)
    print(f"🎉 [HOÀN TẤT] ĐÃ HUẤN LUYỆN VÀ ĐÓNG GÓI ĐẦY ĐỦ BỘ MÔ HÌNH ĐA MIỀN TẠI: {model_dir}")
    print("=" * 70)
    return True


if __name__ == "__main__":
    train_and_export_models()

"""
train_detector_models.py
Huấn luyện và đóng gói 3 mô hình học máy phát hiện mã độc (Random Forest, XGBoost, MLP)
từ tập dữ liệu cấu trúc PE Malware thực tế (dataset_malwares.csv).
Mô hình sau khi huấn luyện được lưu vào dags/models/ để phục vụ suy luận thời gian thực.
"""

import os
import sys
import json
import joblib
import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except ImportError:
    HAS_XGB = False
    print("[CẢNH BÁO] Chưa cài đặt thư viện xgboost, sẽ dùng GradientBoostingClassifier thay thế nếu cần.")
    from sklearn.ensemble import GradientBoostingClassifier


def train_and_export_models():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_path = os.path.join(base_dir, "datasets", "dataset_malwares.csv")
    model_dir = os.path.join(base_dir, "models")
    os.makedirs(model_dir, exist_ok=True)

    if not os.path.exists(dataset_path):
        print(f"[LỖI] Không tìm thấy file dữ liệu tại {dataset_path}")
        return False

    print("=" * 70)
    print("🚀 BẮT ĐẦU QUÁ TRÌNH HUẤN LUYỆN BỘ 3 MÔ HÌNH PHÁT HIỆN MÃ ĐỘC PE")
    print(f"📁 Nguồn dữ liệu: {dataset_path}")
    print("=" * 70)

    # 1. Đọc dữ liệu
    df = pd.read_csv(dataset_path)
    print(f">> Nạp thành công {len(df)} mẫu PE với {len(df.columns)} cột đặc trưng.")

    # 2. Tiền xử lý
    target_col = 'Malware'
    id_cols = ['Name']

    feature_cols = [c for c in df.columns if c != target_col and c not in id_cols]
    
    # Ép kiểu số và điền giá trị thiếu bằng median
    X_df = df[feature_cols].apply(pd.to_numeric, errors='coerce')
    feature_medians = X_df.median().to_dict()
    X_df = X_df.fillna(X_df.median())

    y = df[target_col].astype(int).values
    X = X_df.values

    # Lưu danh sách đặc trưng để phục vụ trích xuất PE thời gian thực
    feature_info = {
        "features": feature_cols,
        "feature_count": len(feature_cols),
        "medians": {k: float(v) if not np.isnan(v) else 0.0 for k, v in feature_medians.items()}
    }

    # 3. Phân chia tập huấn luyện và kiểm thử (80/20)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # 4. Chuẩn hóa dữ liệu (Scaler)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Lưu Scaler
    scaler_path = os.path.join(model_dir, "pe_scaler.pkl")
    joblib.dump(scaler, scaler_path)
    print(f">> Đã lưu Scaler chuẩn hóa: {scaler_path}")

    results_summary = {}

    # 5. Huấn luyện Mô hình 1: RANDOM FOREST CLASSIFIER
    print("\n-------------------------------------------------------------")
    print("🌲 1/3: Đang huấn luyện Random Forest Classifier...")
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=25,
        min_samples_leaf=2,
        min_samples_split=4,
        max_features='sqrt',
        class_weight='balanced',
        n_jobs=-1,
        random_state=42
    )
    rf_model.fit(X_train, y_train)

    rf_pred = rf_model.predict(X_test)
    rf_prob = rf_model.predict_proba(X_test)[:, 1]

    rf_metrics = {
        "accuracy": round(float(accuracy_score(y_test, rf_pred)), 4),
        "precision": round(float(precision_score(y_test, rf_pred)), 4),
        "recall": round(float(recall_score(y_test, rf_pred)), 4),
        "f1_score": round(float(f1_score(y_test, rf_pred)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, rf_prob)), 4)
    }
    results_summary["Random Forest"] = rf_metrics
    rf_path = os.path.join(model_dir, "rf_malware_model.pkl")
    joblib.dump(rf_model, rf_path)
    print(f">> Đã lưu Random Forest Model: {rf_path}")
    print(f"   Acc: {rf_metrics['accuracy']*100:.2f}% | F1: {rf_metrics['f1_score']*100:.2f}% | AUC: {rf_metrics['roc_auc']:.4f}")

    # 6. Huấn luyện Mô hình 2: XGBOOST CLASSIFIER
    print("\n-------------------------------------------------------------")
    print("⚡ 2/3: Đang huấn luyện XGBoost Classifier...")
    if HAS_XGB:
        xgb_model = XGBClassifier(
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
        xgb_model = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            random_state=42
        )
    xgb_model.fit(X_train, y_train)

    xgb_pred = xgb_model.predict(X_test)
    xgb_prob = xgb_model.predict_proba(X_test)[:, 1]

    xgb_metrics = {
        "accuracy": round(float(accuracy_score(y_test, xgb_pred)), 4),
        "precision": round(float(precision_score(y_test, xgb_pred)), 4),
        "recall": round(float(recall_score(y_test, xgb_pred)), 4),
        "f1_score": round(float(f1_score(y_test, xgb_pred)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, xgb_prob)), 4)
    }
    results_summary["XGBoost"] = xgb_metrics
    xgb_path = os.path.join(model_dir, "xgb_malware_model.pkl")
    joblib.dump(xgb_model, xgb_path)
    print(f">> Đã lưu XGBoost Model: {xgb_path}")
    print(f"   Acc: {xgb_metrics['accuracy']*100:.2f}% | F1: {xgb_metrics['f1_score']*100:.2f}% | AUC: {xgb_metrics['roc_auc']:.4f}")

    # 7. Huấn luyện Mô hình 3: MULTI-LAYER PERCEPTRON (MLP)
    print("\n-------------------------------------------------------------")
    print("🧠 3/3: Đang huấn luyện Deep Learning MLP Classifier...")
    mlp_model = MLPClassifier(
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
    mlp_model.fit(X_train_scaled, y_train)

    mlp_pred = mlp_model.predict(X_test_scaled)
    mlp_prob = mlp_model.predict_proba(X_test_scaled)[:, 1]

    mlp_metrics = {
        "accuracy": round(float(accuracy_score(y_test, mlp_pred)), 4),
        "precision": round(float(precision_score(y_test, mlp_pred)), 4),
        "recall": round(float(recall_score(y_test, mlp_pred)), 4),
        "f1_score": round(float(f1_score(y_test, mlp_pred)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, mlp_prob)), 4)
    }
    results_summary["MLP"] = mlp_metrics
    mlp_path = os.path.join(model_dir, "mlp_malware_model.pkl")
    joblib.dump(mlp_model, mlp_path)
    print(f">> Đã lưu MLP Model: {mlp_path}")
    print(f"   Acc: {mlp_metrics['accuracy']*100:.2f}% | F1: {mlp_metrics['f1_score']*100:.2f}% | AUC: {mlp_metrics['roc_auc']:.4f}")

    # 8. Xuất file metadata cấu hình
    metadata = {
        "trained_date": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
        "dataset_name": "dataset_malwares.csv",
        "total_samples": len(df),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "feature_cols": feature_cols,
        "feature_medians": {k: float(v) if not np.isnan(v) else 0.0 for k, v in feature_medians.items()},
        "metrics": results_summary
    }
    meta_path = os.path.join(model_dir, "model_metadata.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    print("\n" + "=" * 70)
    print(f"🎉 HOÀN TẤT HUẤN LUYỆN BỘ 3 MÔ HÌNH! Dữ liệu đã lưu tại: {model_dir}")
    print("=" * 70)
    return True


if __name__ == "__main__":
    train_and_export_models()

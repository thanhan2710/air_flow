# -*- coding: utf-8 -*-
"""
train_detector_models.py
Huan luyen va dong goi 3 mo hinh hoc may phat hien ma doc (Random Forest, XGBoost, MLP)
tu tap du lieu cau truc PE Malware thuc te (dataset_malwares.csv).
Mo hinh sau khi huan luyen duoc luu vao dags/models/ de phuc vu suy luan thoi gian thuc.
"""

import os
import sys
import json
import joblib
import pandas as pd
import numpy as np

# Cau hinh ho tro ma hoa UTF-8 tren moi moi truong Windows/Linux
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

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
    print("[CANH BAO] Chua cai dat thu vien xgboost, se dung GradientBoostingClassifier thay the neu can.")
    from sklearn.ensemble import GradientBoostingClassifier


def train_and_export_models():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_path = os.path.join(base_dir, "datasets", "dataset_malwares.csv")
    model_dir = os.path.join(base_dir, "models")
    os.makedirs(model_dir, exist_ok=True)

    if not os.path.exists(dataset_path):
        print(f"[LOI] Khong tim thay file du lieu tai: {dataset_path}")
        return False

    print("=" * 70)
    print("[BAT DAU] QUÁ TRÌNH HUẤN LUYỆN BỘ 3 MÔ HÌNH PHÁT HIỆN MÃ ĐỘC PE")
    print(f"[NGUON DU LIEU] {dataset_path}")
    print("=" * 70)

    # 1. Doc du lieu
    df = pd.read_csv(dataset_path)
    print(f">> Nap thanh cong {len(df):,} mau PE voi {len(df.columns)} cot dac trung.")

    # 2. Tien xu ly
    target_col = 'Malware'
    id_cols = ['Name']

    feature_cols = [c for c in df.columns if c != target_col and c not in id_cols]
    
    # Ep kieu so va dien gia tri thieu bang median
    X_df = df[feature_cols].apply(pd.to_numeric, errors='coerce')
    feature_medians = X_df.median().to_dict()
    X_df = X_df.fillna(X_df.median())

    y = df[target_col].astype(int).values
    X = X_df.values

    # Luu danh sach dac trung de phuc vu trich xuat PE thoi gian thuc
    feature_info = {
        "features": feature_cols,
        "feature_count": len(feature_cols),
        "medians": {k: float(v) if not np.isnan(v) else 0.0 for k, v in feature_medians.items()}
    }

    # 3. Phan chia tap huan luyen va kiem thu (80/20)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # 4. Chuan hoa du lieu (Scaler)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Luu Scaler
    scaler_path = os.path.join(model_dir, "pe_scaler.pkl")
    joblib.dump(scaler, scaler_path)
    print(f">> Da luu Scaler chuan hoa: {scaler_path}")

    results_summary = {}

    # 5. Huan luyen Mo hinh 1: RANDOM FOREST CLASSIFIER
    print("\n-------------------------------------------------------------")
    print("[1/3] [Random Forest] Dang huan luyen Random Forest Classifier...")
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
    print(f">> Da luu Random Forest Model: {rf_path}")
    print(f"   Acc: {rf_metrics['accuracy']*100:.2f}% | F1: {rf_metrics['f1_score']*100:.2f}% | AUC: {rf_metrics['roc_auc']:.4f}")

    # 6. Huan luyen Mo hinh 2: XGBOOST CLASSIFIER
    print("\n-------------------------------------------------------------")
    print("[2/3] [XGBoost] Dang huan luyen XGBoost Classifier...")
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
    print(f">> Da luu XGBoost Model: {xgb_path}")
    print(f"   Acc: {xgb_metrics['accuracy']*100:.2f}% | F1: {xgb_metrics['f1_score']*100:.2f}% | AUC: {xgb_metrics['roc_auc']:.4f}")

    # 7. Huan luyen Mo hinh 3: MULTI-LAYER PERCEPTRON (MLP)
    print("\n-------------------------------------------------------------")
    print("[3/3] [Deep MLP] Dang huan luyen Deep Learning MLP Classifier...")
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
    print(f">> Da luu MLP Model: {mlp_path}")
    print(f"   Acc: {mlp_metrics['accuracy']*100:.2f}% | F1: {mlp_metrics['f1_score']*100:.2f}% | AUC: {mlp_metrics['roc_auc']:.4f}")

    # 8. Xuat file metadata cau hinh
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
    print(f"[HOAN TAT] DA HUAN LUYEN XONG BO 3 MO HINH! Luu tai: {model_dir}")
    print("=" * 70)
    return True


if __name__ == "__main__":
    train_and_export_models()

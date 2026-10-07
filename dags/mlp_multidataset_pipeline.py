from airflow.decorators import dag, task
from datetime import datetime, timedelta
import os

default_args = {
    'owner': 'airflow',
    'retries': 1,
    'retry_delay': timedelta(minutes=2),
}

@dag(
    default_args=default_args,
    schedule_interval=None,
    start_date=datetime(2023, 1, 1),
    catchup=False,
    tags=['mã_độc', 'mlp', 'nhiều_dataset', 'chống_rò_rỉ']
)
def mlp_multidataset_pipeline():

    @task
    def extract_datasets(dataset_dir="/opt/airflow/dags/datasets"):
        if not os.path.exists(dataset_dir):
            raise ValueError(f"Không tìm thấy thư mục {dataset_dir}")
        files = [os.path.join(dataset_dir, f) for f in os.listdir(dataset_dir) if f.endswith('.csv')]
        print(f"MLP: Tìm thấy {len(files)} file CSV cần xử lý.")
        return files

    @task
    def transform_data(file_paths):
        import pandas as pd
        import numpy as np
        import os
        from sklearn.feature_extraction.text import TfidfVectorizer
        
        processed_paths = []
        out_dir = "/opt/airflow/dags/processed_datasets"
        os.makedirs(out_dir, exist_ok=True)
        
        target_candidates = [
            'malware', 'classification', 'label', 'classe', 'class', 
            'attack_type', 'result', 'prediction', 'smishing label', 
            'legitimate', 'malware_type', 'gr', 'class_label'
        ]
        leaky_cols = {
            'family', 'threats', 'threat_type', 'threat', 'spam label', 
            'score_binary', 'prf', 'ipreputation', 'domainreputation', 
            'millisecond', 'time', 'timestamp', 'ipaddress', 'seddaddress', 
            'expaddress', 'clusters', 'dnsrecordtype', 'creationdate', 'lastupdatedate'
        }
        id_cols = {'md5', 'name', 'id', 'ip', 'hash'}
        
        for path in file_paths:
            filename = os.path.basename(path)
            try:
                if "dataset-features-categories" in filename or "dataset_test" in filename:
                    continue
                    
                df = pd.read_csv(path, sep=None, engine='python', on_bad_lines='skip')
                if df.empty or len(df.columns) < 2 or len(df) < 20: 
                    continue
                
                target_col = None
                for c in df.columns:
                    if str(c).strip().lower() in target_candidates:
                        target_col = c
                        break
                if target_col is None:
                    target_col = df.columns[-1]
                
                n_classes = df[target_col].nunique()
                if n_classes < 2 or n_classes > 50:
                    continue
                
                # Lưu Group ID (ví dụ hash ứng dụng hoặc domain) để chia theo nhóm chống rò rỉ phiên
                group_series = None
                for c in df.columns:
                    if str(c).strip().lower() in ['domain']:
                        group_series = df[c].astype(str)
                        break
                
                # Khử trùng lặp (Deduplication)
                df = df.drop_duplicates()
                if len(df) < 20:
                    continue
                if group_series is not None:
                    group_series = group_series.loc[df.index]
                
                # Lọc bỏ cột rò rỉ đáp án
                cols_to_drop = [target_col]
                for c in df.columns:
                    cl = str(c).strip().lower()
                    if cl in leaky_cols or cl in id_cols or cl in ['hash', 'domain']:
                        cols_to_drop.append(c)
                
                features = df.drop(columns=[c for c in cols_to_drop if c in df.columns]).copy()
                target = df[target_col].copy()
                
                # Xử lý text: TF-IDF nâng cấp 200 features + bigrams
                text_col = None
                for candidate in ['message', 'query', 'sentence', 'text', 'payload', 'url']:
                    for col in features.columns:
                        if str(col).strip().lower() == candidate:
                            text_col = col
                            break
                    if text_col:
                        break

                if text_col is not None:
                    tfidf = TfidfVectorizer(
                        max_features=200, 
                        stop_words='english',
                        ngram_range=(1, 2),       # Bắt cụm từ 2 từ: "click here", "free prize"
                        sublinear_tf=True          # Giảm ảnh hưởng của từ xuất hiện quá nhiều
                    )
                    tfidf_matrix = tfidf.fit_transform(features[text_col].astype(str)).toarray()
                    n_feats = tfidf_matrix.shape[1]
                    text_m = pd.DataFrame(
                        tfidf_matrix,
                        columns=[f"tfidf_{i}" for i in range(n_feats)],
                        index=features.index
                    )
                    features = pd.concat([features.drop(columns=[text_col]), text_m], axis=1)
                
                # Mã hóa categorical: One-Hot cho ≤20 giá trị, factorize cho >20
                cat_cols = [col for col in features.columns if features[col].dtype == 'object']
                low_card_cols = [col for col in cat_cols if features[col].nunique() <= 20]
                high_card_cols = [col for col in cat_cols if features[col].nunique() > 20]
                
                if low_card_cols:
                    features = pd.get_dummies(features, columns=low_card_cols, drop_first=True, dtype=int)
                for col in high_card_cols:
                    features[col] = pd.factorize(features[col])[0]
                features = features.apply(pd.to_numeric, errors='coerce').fillna(0)
                
                # Lấy mẫu tối đa 12,000 dòng (tăng từ 10K)
                if len(features) > 12000:
                    idx_sample = features.sample(12000, random_state=42).index
                    features = features.loc[idx_sample]
                    target = target.loc[idx_sample]
                    if group_series is not None:
                        group_series = group_series.loc[idx_sample]
                
                df_processed = features.reset_index(drop=True).copy()
                df_processed['__target__'] = target.reset_index(drop=True).values
                if group_series is not None and group_series.nunique() >= 5:
                    df_processed['__group__'] = group_series.reset_index(drop=True).values
                
                out_path = os.path.join(out_dir, f"mlp_clean_{filename}")
                df_processed.to_csv(out_path, index=False)
                processed_paths.append(out_path)
                print(f"MLP: Chuẩn hóa chống rò rỉ thành công {filename}: {len(df_processed)} mẫu.")
                
            except Exception as e:
                print(f"Bỏ qua file {path} do lỗi: {e}")
                
        return processed_paths

    @task
    def train_mlp_model(processed_paths):
        import subprocess, sys
        try:
            import tensorflow
        except Exception:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "numpy<2.0.0", "tensorflow", "scikit-learn", "--user", "--no-cache-dir"])
            import site, importlib
            importlib.reload(site)
        
        import pandas as pd
        import numpy as np
        import tensorflow as tf
        from tensorflow.keras.models import Sequential
        from tensorflow.keras.layers import Dense, Dropout, BatchNormalization
        from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
        from sklearn.model_selection import train_test_split, GroupShuffleSplit, StratifiedShuffleSplit
        from sklearn.preprocessing import StandardScaler, LabelEncoder
        from sklearn.metrics import accuracy_score, precision_score, f1_score, roc_auc_score, confusion_matrix
        from sklearn.utils.class_weight import compute_class_weight
        import gc, os
        
        tf.config.threading.set_intra_op_parallelism_threads(0)
        tf.config.threading.set_inter_op_parallelism_threads(0)
        
        reports = []
        for path in processed_paths:
            try:
                df = pd.read_csv(path)
                if len(df) < 15 or '__target__' not in df.columns: 
                    continue
                    
                y_raw = df['__target__'].astype(str).values
                
                if '__group__' in df.columns:
                    groups = df['__group__'].values
                    X = df.drop(columns=['__target__', '__group__']).values
                    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
                    train_idx, test_idx = next(gss.split(X, y_raw, groups))
                    X_train, X_test = X[train_idx], X[test_idx]
                    y_train_raw, y_test_raw = y_raw[train_idx], y_raw[test_idx]
                else:
                    # Stratified Split: đảm bảo tỷ lệ nhãn công bằng
                    X = df.drop(columns=['__target__']).values
                    try:
                        sss = StratifiedShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
                        train_idx, test_idx = next(sss.split(X, y_raw))
                        X_train, X_test = X[train_idx], X[test_idx]
                        y_train_raw, y_test_raw = y_raw[train_idx], y_raw[test_idx]
                    except ValueError:
                        X_train, X_test, y_train_raw, y_test_raw = train_test_split(X, y_raw, test_size=0.2, random_state=42)
                
                le = LabelEncoder()
                y_train = le.fit_transform(y_train_raw)
                
                mask = np.isin(y_test_raw, le.classes_)
                if not np.all(mask):
                    X_test = X_test[mask]
                    y_test_raw = y_test_raw[mask]
                y_test = le.transform(y_test_raw)
                
                num_classes = len(np.unique(y_train))
                if num_classes < 2 or len(y_test) == 0:
                    continue
                
                scaler = StandardScaler()
                X_train = scaler.fit_transform(X_train)
                X_test = scaler.transform(X_test)
                
                # 1. Tự động tính trọng số cân bằng lớp (Class Weights)
                classes = np.unique(y_train)
                weights = compute_class_weight('balanced', classes=classes, y=y_train)
                class_weight_dict = {int(c): float(w) for c, w in zip(classes, weights)}
                
                # 2. Kiến trúc mạng nơ-ron 3 tầng + BatchNormalization chống gradient triệt tiêu
                n_features = X_train.shape[1]
                hidden_1 = max(64, min(256, int(n_features * 1.5)))
                hidden_2 = max(32, min(128, int(hidden_1 // 2)))
                hidden_3 = max(16, min(64, int(hidden_2 // 2)))
                
                if num_classes <= 2:
                    loss_fn = 'binary_crossentropy'
                    out_activation = 'sigmoid'
                    out_units = 1
                else:
                    loss_fn = 'sparse_categorical_crossentropy'
                    out_activation = 'softmax'
                    out_units = num_classes
                
                model = Sequential([
                    Dense(hidden_1, input_shape=(n_features,)),
                    BatchNormalization(),        # Ổn định phân phối activation
                    tf.keras.layers.Activation('relu'),
                    Dropout(0.3),               # Tăng từ 0.2 → 0.3
                    
                    Dense(hidden_2),
                    BatchNormalization(),
                    tf.keras.layers.Activation('relu'),
                    Dropout(0.3),
                    
                    Dense(hidden_3),             # Tầng ẩn thứ 3 mới
                    BatchNormalization(),
                    tf.keras.layers.Activation('relu'),
                    Dropout(0.2),
                    
                    Dense(out_units, activation=out_activation)
                ])
                
                model.compile(optimizer='adam', loss=loss_fn)
                early_stop = EarlyStopping(monitor='val_loss', patience=6, restore_best_weights=True)
                reduce_lr = ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=3, min_lr=1e-5)
                
                from sklearn.model_selection import train_test_split as _tts
                X_tr, X_val, y_tr, y_val = _tts(X_train, y_train, test_size=0.15, random_state=42)
                
                model.fit(
                    X_tr, y_tr, 
                    epochs=50,                   # Tăng từ 25 → 50 (EarlyStopping sẽ tự dừng)
                    batch_size=128,              # Giảm từ 256 → 128 → gradient đa dạng hơn
                    validation_data=(X_val, y_val), 
                    callbacks=[early_stop, reduce_lr], 
                    class_weight=class_weight_dict,
                    verbose=0
                )
                
                y_prob_raw = model.predict(X_test, verbose=0)
                if num_classes <= 2:
                    y_prob = y_prob_raw.flatten()
                    val_prob = model.predict(X_val, verbose=0).flatten()
                    best_t = 0.5
                    best_f1 = -1.0
                    min_v_fpr = 1.0
                    fallback_t = 0.5
                    for t in np.linspace(0.40, 0.95, 56):
                        v_pred = (val_prob >= t).astype(int)
                        cm_v = confusion_matrix(y_val, v_pred, labels=[0, 1])
                        tn_v, fp_v, fn_v, tp_v = cm_v.ravel()
                        fpr_v = fp_v / (fp_v + tn_v) if (fp_v + tn_v) > 0 else 0.0
                        f1_v = f1_score(y_val, v_pred, zero_division=0)
                        if fpr_v < min_v_fpr:
                            min_v_fpr = fpr_v
                            fallback_t = t
                        if fpr_v <= 0.035 and f1_v > best_f1:
                            best_f1 = f1_v
                            best_t = t
                    chosen_t = best_t if best_f1 > 0 else fallback_t
                    y_pred = (y_prob >= chosen_t).astype(int)
                    try:
                        roc_auc = round(float(roc_auc_score(y_test, y_prob)), 4)
                    except Exception:
                        roc_auc = round(float(accuracy_score(y_test, y_pred)), 4)
                else:
                    y_pred = np.argmax(y_prob_raw, axis=1)
                    try:
                        roc_auc = round(float(roc_auc_score(y_test, y_prob_raw, multi_class='ovr', average='weighted')), 4)
                    except Exception:
                        roc_auc = round(float(accuracy_score(y_test, y_pred)), 4)
                
                filename = os.path.basename(path).replace("mlp_clean_", "")
                acc = round(float(accuracy_score(y_test, y_pred)), 4)
                prec = round(float(precision_score(y_test, y_pred, average='weighted', zero_division=0)), 4)
                f1 = round(float(f1_score(y_test, y_pred, average='weighted', zero_division=0)), 4)
                
                # 3. Tính toán FPR (False Positive Rate)
                try:
                    cm = confusion_matrix(y_test, y_pred, labels=np.arange(num_classes))
                    if num_classes == 2:
                        tn, fp, fn, tp = cm.ravel()
                        fpr = round(float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0, 4)
                    else:
                        fpr_list = []
                        total_samples = cm.sum()
                        for i in range(num_classes):
                            fp_cls = cm[:, i].sum() - cm[i, i]
                            tn_cls = total_samples - (cm[i, :].sum() + cm[:, i].sum() - cm[i, i])
                            fpr_val = fp_cls / (fp_cls + tn_cls) if (fp_cls + tn_cls) > 0 else 0.0
                            fpr_list.append(fpr_val)
                        fpr = round(float(np.mean(fpr_list)), 4)
                except Exception:
                    fpr = 0.0
                
                reports.append({
                    "Dataset": filename,
                    "Thuật_Toán": "MLP",
                    "Accuracy": acc,
                    "Precision": prec,
                    "F1_Score": f1,
                    "FPR": fpr,
                    "ROC_AUC": roc_auc
                })
                print(f"[MLP - Tối Ưu] {filename} -> Acc: {acc*100:.2f}% | F1: {f1*100:.2f}% | FPR: {fpr*100:.2f}% | AUC: {roc_auc:.4f}")
                
                tf.keras.backend.clear_session()
                del model, X, y_train, y_test, X_train, X_test
                gc.collect()
                
            except Exception as e:
                print(f"LỖI HUẤN LUYỆN TRÊN {path}: {e}")
        return reports

    @task
    def save_data_to_file(report_data):
        import pandas as pd
        if not report_data: 
            return "Skipped"
        df = pd.DataFrame(report_data)
        file_path = "/opt/airflow/dags/MLP_MultiDataset_Report.csv"
        df.to_csv(file_path, index=False, encoding='utf-8-sig')
        print(f"Đã lưu báo cáo MLP sạch với {len(df)} datasets vào {file_path}")
        return file_path

    raw_files = extract_datasets()
    clean_files = transform_data(raw_files)
    metrics_report = train_mlp_model(clean_files)
    save_data_to_file(metrics_report)

dag_instance = mlp_multidataset_pipeline()
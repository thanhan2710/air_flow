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
    tags=['mã_độc', 'random_forest', 'nhiều_dataset', 'chống_rò_rỉ']
)
def rf_multidataset_pipeline():

    @task
    def extract_datasets(dataset_dir="/opt/airflow/dags/datasets"):
        if not os.path.exists(dataset_dir):
            raise ValueError(f"Không tìm thấy thư mục {dataset_dir}")
        files = [os.path.join(dataset_dir, f) for f in os.listdir(dataset_dir) if f.endswith('.csv')]
        print(f"Random Forest: Tìm thấy {len(files)} file CSV cần kiểm tra.")
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
            'legitimate', 'malware_type'
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
                
                group_series = None
                for c in df.columns:
                    if str(c).strip().lower() in ['domain']:
                        group_series = df[c].astype(str)
                        break
                
                df = df.drop_duplicates()
                if len(df) < 20:
                    continue
                if group_series is not None:
                    group_series = group_series.loc[df.index]
                
                cols_to_drop = [target_col]
                for c in df.columns:
                    cl = str(c).strip().lower()
                    if cl in leaky_cols or cl in id_cols or cl in ['hash', 'domain']:
                        cols_to_drop.append(c)
                
                features = df.drop(columns=[c for c in cols_to_drop if c in df.columns]).copy()
                target = df[target_col].copy()
                
                # Xử lý text: TF-IDF nâng cấp 200 features + bigrams
                if 'message' in features.columns:
                    tfidf = TfidfVectorizer(
                        max_features=200, 
                        stop_words='english',
                        ngram_range=(1, 2),       # Bắt cụm từ 2 từ: "click here", "free prize"
                        sublinear_tf=True          # Giảm ảnh hưởng của từ xuất hiện quá nhiều
                    )
                    tfidf_matrix = tfidf.fit_transform(features['message'].astype(str)).toarray()
                    n_feats = tfidf_matrix.shape[1]
                    text_m = pd.DataFrame(
                        tfidf_matrix,
                        columns=[f"tfidf_{i}" for i in range(n_feats)],
                        index=features.index
                    )
                    features = pd.concat([features.drop(columns=['message']), text_m], axis=1)
                
                # Mã hóa categorical: One-Hot cho ≤20 giá trị, factorize cho >20
                cat_cols = [col for col in features.columns if features[col].dtype == 'object']
                low_card_cols = [col for col in cat_cols if features[col].nunique() <= 20]
                high_card_cols = [col for col in cat_cols if features[col].nunique() > 20]
                
                if low_card_cols:
                    features = pd.get_dummies(features, columns=low_card_cols, drop_first=True, dtype=int)
                for col in high_card_cols:
                    features[col] = pd.factorize(features[col])[0]
                features = features.apply(pd.to_numeric, errors='coerce').fillna(0)
                
                # Lấy mẫu tối đa 15,000 dòng (tăng từ 12K)
                if len(features) > 15000:
                    idx_sample = features.sample(15000, random_state=42).index
                    features = features.loc[idx_sample]
                    target = target.loc[idx_sample]
                    if group_series is not None:
                        group_series = group_series.loc[idx_sample]
                
                df_processed = features.reset_index(drop=True).copy()
                df_processed['__target__'] = target.reset_index(drop=True).values
                if group_series is not None and group_series.nunique() >= 5:
                    df_processed['__group__'] = group_series.reset_index(drop=True).values
                
                out_path = os.path.join(out_dir, f"rf_clean_{filename}")
                df_processed.to_csv(out_path, index=False)
                processed_paths.append(out_path)
                print(f"RF: Chuẩn hóa chống rò rỉ thành công {filename}: {len(df_processed)} mẫu.")
                
            except Exception as e:
                print(f"Bỏ qua file {path} do lỗi: {e}")
                
        return processed_paths

    @task
    def train_rf_model(processed_paths):
        import pandas as pd
        import numpy as np
        from sklearn.model_selection import train_test_split, GroupShuffleSplit, StratifiedShuffleSplit
        from sklearn.preprocessing import LabelEncoder
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import accuracy_score, precision_score, f1_score, roc_auc_score, confusion_matrix
        import gc, os
        
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
                
                # 1. Tính toán độ sâu thích ứng theo số lượng mẫu và đặc trưng
                dynamic_depth = max(15, min(30, int(np.log2(len(X_train)) * 2)))
                
                # 2. Tối ưu mô hình với regularization chống học vẹt
                model = RandomForestClassifier(
                    n_estimators=120,              # Tăng vừa phải (75→120)
                    max_depth=dynamic_depth,
                    min_samples_leaf=3,            # Mỗi lá tối thiểu 3 mẫu → chống overfitting
                    min_samples_split=6,           # Tối thiểu 6 mẫu để tách nhánh
                    max_features='sqrt',           # Chỉ xét √n features mỗi nút → đa dạng cây
                    n_jobs=-1,
                    class_weight='balanced_subsample',
                    random_state=42
                )
                from sklearn.model_selection import train_test_split as _tts
                X_tr, X_val, y_tr, y_val = _tts(X_train, y_train, test_size=0.15, random_state=42)
                model.fit(X_tr, y_tr)
                
                # 3. Tính toán xác suất, ROC-AUC và tối ưu ngưỡng quyết định kiểm soát FPR (<= 3.5%)
                try:
                    y_prob = model.predict_proba(X_test)
                    if num_classes == 2:
                        roc_auc = round(float(roc_auc_score(y_test, y_prob[:, 1])), 4)
                        val_prob = model.predict_proba(X_val)[:, 1]
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
                        y_pred = (y_prob[:, 1] >= chosen_t).astype(int)
                    else:
                        roc_auc = round(float(roc_auc_score(y_test, y_prob, multi_class='ovr', average='weighted')), 4)
                        y_pred = np.argmax(y_prob, axis=1)
                except Exception:
                    y_pred = model.predict(X_test)
                    roc_auc = round(float(acc), 4)
                
                filename = os.path.basename(path).replace("rf_clean_", "")
                acc = round(float(accuracy_score(y_test, y_pred)), 4)
                prec = round(float(precision_score(y_test, y_pred, average='weighted', zero_division=0)), 4)
                f1 = round(float(f1_score(y_test, y_pred, average='weighted', zero_division=0)), 4)
                
                # 4. Tính toán FPR (False Positive Rate)
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
                    "Thuật_Toán": "Random Forest",
                    "Accuracy": acc,
                    "Precision": prec,
                    "F1_Score": f1,
                    "FPR": fpr,
                    "ROC_AUC": roc_auc
                })
                print(f"[Random Forest - Tối Ưu] {filename} -> Acc: {acc*100:.2f}% | F1: {f1*100:.2f}% | FPR: {fpr*100:.2f}% | AUC: {roc_auc:.4f}")
                
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
        file_path = "/opt/airflow/dags/RandomForest_MultiDataset_Report.csv"
        df.to_csv(file_path, index=False, encoding='utf-8-sig')
        print(f"Đã lưu báo cáo Random Forest sạch với {len(df)} datasets vào {file_path}")
        return file_path

    raw_files = extract_datasets()
    clean_files = transform_data(raw_files)
    metrics_report = train_rf_model(clean_files)
    save_data_to_file(metrics_report)

dag_instance = rf_multidataset_pipeline()
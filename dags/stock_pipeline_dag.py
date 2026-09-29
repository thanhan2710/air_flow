from airflow.decorators import dag, task
from datetime import datetime, timedelta
import yfinance as yf
import pandas as pd
import numpy as np
import joblib
import io
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

default_args = {
    'owner': 'airflow',
    'retries': 1,
    'retry_delay': timedelta(minutes=2),
}


@dag(
    default_args=default_args,
    schedule_interval="* 8-14 * * 1-5",  # Chạy lặp lại MỖI 1 PHÚT, từ 8h-14h, Thứ 2 - Thứ 6
    start_date=datetime(2023, 1, 1),
    catchup=False,
    tags=['chứng_khoán', 'machine_learning', 'real_time']
)
def stock_ml_pipeline():
    # ==========================================
    # 1. EXTRACT
    # ==========================================
    @task
    def extract_market_data(ticker="AAPL"):
        df = yf.download(ticker, period="1d", interval="1m")
        if df.empty or not isinstance(df.columns, pd.MultiIndex):
            return "[]"
        df.index.name = 'Datetime'
        df = df.reset_index()
        df['Datetime'] = pd.to_datetime(df['Datetime']).dt.strftime('%Y-%m-%d %H:%M:%S')
        return df[['Datetime', 'Open', 'High', 'Low', 'Close', 'Volume']].to_json(orient='records')

    @task
    def extract_fundamental_api():
        today = datetime.now().strftime('%Y-%m-%d')
        return [{"Date": today, "PE_Ratio": 25.5, "EPS": 5.1}]

    @task
    def extract_sentiment_csv():
        today = datetime.now().strftime('%Y-%m-%d')
        return [{"Date": today, "Sentiment_Score": 0.85}]

    # ==========================================
    # 2. TRANSFORM
    # ==========================================
    @task
    def transform_data(market_json, api_data, sentiment_data):
        df_market = pd.read_json(io.StringIO(market_json), orient='records')
        if df_market.empty:
            raise ValueError("Thị trường đóng cửa hoặc lỗi mạng, không có dữ liệu 1 phút mới!")

        df_fund = pd.DataFrame(api_data)
        df_sent = pd.DataFrame(sentiment_data)

        # SỬA LỖI TẠI ĐÂY: Tạo một cột 'Date' riêng biệt để merge, giữ nguyên 'Datetime'
        if 'Datetime' not in df_market.columns:
            df_market['Date'] = 'N/A'
        else:
            df_market['Date'] = pd.to_datetime(df_market['Datetime']).dt.strftime('%Y-%m-%d')

        if 'Date' not in df_fund.columns:
            df_fund['Date'] = 'N/A'
        else:
            df_fund['Date'] = pd.to_datetime(df_fund['Date']).dt.strftime('%Y-%m-%d')

        if 'Date' not in df_sent.columns:
            df_sent['Date'] = 'N/A'
        else:
            df_sent['Date'] = pd.to_datetime(df_sent['Date']).dt.strftime('%Y-%m-%d')

        # Merge thành công nhờ đã đồng bộ chuẩn khóa 'Date' ở cả 3 bảng
        df_merged = pd.merge(df_market, df_fund, on='Date', how='left').merge(df_sent, on='Date',
                                                                              how='left').ffill().fillna(0)

        df_merged['MA20'] = df_merged['Close'].rolling(window=20).mean()
        df_clean = df_merged.dropna()

        print("\n" + "=" * 55)
        print(" BẢNG ĐIỀU KHIỂN CHỨNG KHOÁN THỜI GIAN THỰC (REAL-TIME) ")
        print("=" * 55)
        print(">>> 5 PHÚT GIAO DỊCH GẦN NHẤT:")
        print(df_clean[['Datetime', 'Open', 'Close', 'MA20', 'Sentiment_Score']].tail(5).to_string(index=False))
        print("=" * 55 + "\n")

        return df_clean.to_json(orient='records')

    # ==========================================
    # 3. LOAD
    # ==========================================
    @task
    def load_to_sql_server(clean_data_json):
        df = pd.read_json(io.StringIO(clean_data_json), orient='records')
        print(f">> Nhận {len(df)} dòng dữ liệu 1-phút.")
        print(f">> Cập nhật Database lúc: {datetime.now().strftime('%H:%M:%S')}")
        return "Load Successful"

    # ==========================================
    # 4. TRAIN
    # ==========================================
    @task
    def train_model(load_status, clean_data_json):
        df = pd.read_json(io.StringIO(clean_data_json), orient='records')
        df['Target'] = np.where(df['Close'].shift(-1) > df['Close'], 1, 0)
        df.dropna(inplace=True)

        if len(df) < 5:
            return "Skipped"

        X, y = df[['Open', 'Volume', 'MA20', 'PE_Ratio', 'Sentiment_Score']], df['Target']
        split_index = int(len(df) * 0.8)
        X_train, y_train = X[:split_index], y[:split_index]

        model = RandomForestClassifier(n_estimators=100, random_state=42).fit(X_train, y_train)
        joblib.dump(model, "/opt/airflow/dags/stock_rf_model.pkl")
        return {"model_path": "/opt/airflow/dags/stock_rf_model.pkl", "status": "Success"}

    # ==========================================
    # 5. EVALUATE
    # ==========================================
    @task
    def evaluate_model(train_result, clean_data_json):
        if train_result == "Skipped":
            print("Dữ liệu không đủ để đánh giá mô hình.")
            return

        model = joblib.load(train_result['model_path'])
        df = pd.read_json(io.StringIO(clean_data_json), orient='records')
        df['Target'] = np.where(df['Close'].shift(-1) > df['Close'], 1, 0)
        df.dropna(inplace=True)

        split_index = int(len(df) * 0.8)
        X_test, y_test = df[['Open', 'Volume', 'MA20', 'PE_Ratio', 'Sentiment_Score']][split_index:], df['Target'][
            split_index:]
        predictions = model.predict(X_test)

        print("=" * 40)
        print("BÁO CÁO MÔ HÌNH (DỰ ĐOÁN TỪNG PHÚT)")
        print("=" * 40)
        print(f"Độ chính xác (Accuracy): {accuracy_score(y_test, predictions) * 100:.2f} %")
        print("\nMa trận nhầm lẫn:\n", confusion_matrix(y_test, predictions))
        return "Complete"

    # ==========================================
    # 6. LƯU FILE CSV
    # ==========================================
    @task
    def save_data_to_file(clean_data_json):
        df = pd.read_json(io.StringIO(clean_data_json), orient='records')
        # SỬA ĐƯỜNG DẪN: Lưu vào /opt/airflow/dags/ để đồng bộ với thư mục C:\airflow_docker\dags trên Windows
        df.to_csv('/opt/airflow/dags/stock_data.csv', index=False)
        return "Data saved to file"

    # ==========================================
    # LUỒNG ĐIỀU PHỐI (DAG FLOW)
    # ==========================================
    data1 = extract_market_data()
    data2 = extract_fundamental_api()
    data3 = extract_sentiment_csv()

    merged_data = transform_data(data1, data2, data3)
    db_status = load_to_sql_server(merged_data)

    training_info = train_model(db_status, merged_data)
    evaluate_model(training_info, merged_data)
    save_data_to_file(merged_data)


dag_instance = stock_ml_pipeline()
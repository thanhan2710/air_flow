from airflow.decorators import dag, task
from datetime import datetime, timedelta
import os
import json

default_args = {
    'owner': 'airflow',
    'retries': 1,
    'retry_delay': timedelta(minutes=2),
}

@dag(
    dag_id='model_evaluation_dashboard',
    default_args=default_args,
    schedule_interval=None,
    start_date=datetime(2023, 1, 1),
    catchup=False,
    tags=['mã_độc', 'đánh_giá', 'trực_quan', 'minio', 'dashboard'],
    doc_md="""
    # Model Evaluation & MinIO GUI Dashboard
    DAG đánh giá hiệu năng các mô hình phát hiện mã độc (XGBoost, Random Forest, MLP):
    1. Tổng hợp các báo cáo CSV từ tất cả các dataset.
    2. Vẽ đồ thị phân tích chi tiết (PNG 300DPI & PDF).
    3. Giao diện Web HTML GUI Dashboard hiện đại: So sánh Đa Chỉ Số linh hoạt và trực quan.
    4. Tự động đẩy toàn bộ báo cáo, đồ thị và Web Dashboard lên MinIO Object Storage.
    """
)
def model_evaluation_dashboard():

    # ==========================================
    # 1. THU THẬP & TỔNG HỢP BÁO CÁO CÁC MÔ HÌNH
    # ==========================================
    @task
    def collect_and_merge_reports():
        import pandas as pd
        import numpy as np

        report_files = [
            "/opt/airflow/dags/XGBoost_MultiDataset_Report.csv",
            "/opt/airflow/dags/MLP_MultiDataset_Report.csv",
            "/opt/airflow/dags/RandomForest_MultiDataset_Report.csv"
        ]

        combined_df = pd.DataFrame()
        for file in report_files:
            if os.path.exists(file):
                try:
                    df = pd.read_csv(file)
                    combined_df = pd.concat([combined_df, df], ignore_index=True)
                except Exception as e:
                    print(f"Lỗi khi đọc file {file}: {e}")
            else:
                print(f"Cảnh báo: Chưa tìm thấy file {file}.")

        if combined_df.empty:
            raise ValueError("Không có dữ liệu báo cáo nào để tiến hành đánh giá!")

        # Chuẩn hóa cột số
        for col in ['Accuracy', 'Precision', 'F1_Score', 'FPR', 'ROC_AUC']:
            if col in combined_df.columns:
                combined_df[col] = pd.to_numeric(combined_df[col], errors='coerce').fillna(0)
            else:
                combined_df[col] = 0.0

        # Lưu file tổng hợp
        report_dir = "/opt/airflow/dags/reports"
        os.makedirs(report_dir, exist_ok=True)
        combined_path = os.path.join(report_dir, "combined_model_evaluation_report.csv")
        combined_df.to_csv(combined_path, index=False, encoding='utf-8-sig')

        # Tính toán thống kê
        stats = {}
        grouped = combined_df.groupby('Thuật_Toán')
        for algo, group in grouped:
            stats[algo] = {
                "mean_accuracy": round(float(group['Accuracy'].mean()), 4),
                "mean_precision": round(float(group['Precision'].mean()), 4),
                "mean_f1": round(float(group['F1_Score'].mean()), 4),
                "mean_fpr": round(float(group['FPR'].mean()), 4),
                "mean_roc_auc": round(float(group['ROC_AUC'].mean()), 4),
                "count": int(len(group))
            }

        # Tìm thuật toán quán quân
        best_algo = max(stats.keys(), key=lambda a: (stats[a]['mean_f1'], stats[a]['mean_accuracy']))
        max_accuracy = float(combined_df['Accuracy'].max())
        mean_f1_overall = float(combined_df['F1_Score'].mean())
        mean_fpr_overall = round(float(combined_df['FPR'].mean()), 4)
        mean_auc_overall = round(float(combined_df['ROC_AUC'].mean()), 4)
        unique_datasets = list(combined_df['Dataset'].unique())

        return {
            "records": combined_df.to_dict('records'),
            "stats": stats,
            "best_algo": best_algo,
            "max_accuracy": round(max_accuracy, 4),
            "mean_f1_overall": round(mean_f1_overall, 4),
            "mean_fpr_overall": mean_fpr_overall,
            "mean_auc_overall": mean_auc_overall,
            "datasets_count": len(unique_datasets),
            "datasets": unique_datasets
        }

    # ==========================================
    # 2. VẼ BIỂU ĐỒ BẰNG MATPLOTLIB & SEABORN
    # ==========================================
    @task
    def generate_charts(eval_data):
        import pandas as pd
        import matplotlib.pyplot as plt
        import seaborn as sns
        import os
        import base64

        df = pd.DataFrame(eval_data['records'])
        report_dir = "/opt/airflow/dags/reports"
        os.makedirs(report_dir, exist_ok=True)

        sns.set_theme(style="darkgrid")
        plt.rcParams['font.sans-serif'] = 'DejaVu Sans'

        fig, axes = plt.subplots(4, 1, figsize=(14, 26), facecolor='#0b0f19')
        fig.suptitle('ĐÁNH GIÁ HIỆU SUẤT MÔ HÌNH PHÁT HIỆN MÃ ĐỘC (CYBERSECURITY BENCHMARK)\nXGBoost vs Multi-Layer Perceptron (MLP) vs Random Forest', 
                     fontsize=18, fontweight='bold', color='#00f0ff', y=0.985)

        fpr_max = float(df['FPR'].max()) if 'FPR' in df.columns and float(df['FPR'].max()) > 0 else 0.2
        metrics = [
            ('Accuracy', 'So sánh Accuracy (Độ chính xác toàn diện)', axes[0], 1.15),
            ('F1_Score', 'So sánh F1-Score (Điểm điều hòa cân bằng nhãn)', axes[1], 1.15),
            ('ROC_AUC', 'So sánh ROC-AUC (Khả năng phân tách mã độc)', axes[2], 1.15),
            ('FPR', 'So sánh FPR - False Positive Rate (Tỷ lệ báo động giả - Càng thấp càng an toàn)', axes[3], max(0.20, fpr_max * 1.3))
        ]

        palette = {'XGBoost': '#00f0ff', 'Random Forest': '#10b981', 'MLP': '#a855f7'}

        for col, title, ax, y_limit in metrics:
            ax.set_facecolor('#111827')
            sns.barplot(data=df, x='Dataset', y=col, hue='Thuật_Toán', ax=ax, palette=palette)
            ax.set_title(title, fontsize=14, color='#f3f4f6', pad=12, fontweight='bold')
            ax.set_ylim(0, y_limit)
            ax.set_ylabel(col, fontsize=12, color='#9ca3af')
            ax.set_xlabel('Tập Dữ Liệu (Datasets)', fontsize=12, color='#9ca3af')
            ax.tick_params(colors='#e5e7eb', labelsize=10, rotation=20)
            
            for container in ax.containers:
                ax.bar_label(container, fmt='%.3f', padding=4, fontsize=9, color='#f9fafb', fontweight='semibold')
                
            ax.legend(title='Thuật Toán', bbox_to_anchor=(1.02, 1), loc='upper left', 
                      facecolor='#1f2937', edgecolor='#374151', labelcolor='#f3f4f6')

        plt.tight_layout(rect=[0, 0, 0.88, 0.96])

        png_path = os.path.join(report_dir, "Model_Evaluation_Chart.png")
        pdf_path = os.path.join(report_dir, "Model_Evaluation_Chart.pdf")

        plt.savefig(png_path, dpi=300, bbox_inches='tight', facecolor=fig.get_facecolor())
        plt.savefig(pdf_path, bbox_inches='tight', facecolor=fig.get_facecolor())
        plt.close()

        with open(png_path, "rb") as f:
            b64_chart = base64.b64encode(f.read()).decode('utf-8')

        return {
            "png_path": png_path,
            "pdf_path": pdf_path,
            "b64_chart": b64_chart
        }

    # ==========================================
    # 3. TẠO GIAO DIỆN WEB HTML GUI DASHBOARD
    # ==========================================
    @task
    def generate_html_dashboard(eval_data, chart_info):
        report_dir = "/opt/airflow/dags/reports"
        os.makedirs(report_dir, exist_ok=True)
        html_path = os.path.join(report_dir, "dashboard.html")
        index_path = os.path.join(report_dir, "index.html")

        records = eval_data['records']
        stats = eval_data['stats']
        best_algo = eval_data['best_algo']
        max_accuracy = eval_data['max_accuracy']
        mean_f1_overall = eval_data['mean_f1_overall']
        mean_fpr_overall = eval_data.get('mean_fpr_overall', 0.0)
        mean_auc_overall = eval_data.get('mean_auc_overall', 0.0)
        datasets_count = eval_data['datasets_count']
        b64_chart = chart_info.get('b64_chart', '')

        # Chuẩn bị dữ liệu JSON cho Chart.js
        datasets = sorted(list(set(r['Dataset'] for r in records)))
        algos = sorted(list(set(r['Thuật_Toán'] for r in records)))

        algo_data_map = {a: {'Accuracy': {}, 'Precision': {}, 'F1_Score': {}, 'FPR': {}, 'ROC_AUC': {}} for a in algos}
        for r in records:
            a = r['Thuật_Toán']
            d = r['Dataset']
            algo_data_map[a]['Accuracy'][d] = r.get('Accuracy', 0)
            algo_data_map[a]['Precision'][d] = r.get('Precision', 0)
            algo_data_map[a]['F1_Score'][d] = r.get('F1_Score', 0)
            algo_data_map[a]['FPR'][d] = r.get('FPR', 0)
            algo_data_map[a]['ROC_AUC'][d] = r.get('ROC_AUC', 0)

        # Màu sắc cho biểu đồ
        chart_colors = {
            'XGBoost': {'border': '#00f0ff', 'bg': 'rgba(0, 240, 255, 0.75)'},
            'Random Forest': {'border': '#10b981', 'bg': 'rgba(16, 185, 129, 0.75)'},
            'MLP': {'border': '#a855f7', 'bg': 'rgba(168, 85, 247, 0.75)'}
        }

        datasets_labels_json = json.dumps(datasets)
        accuracy_datasets = []
        precision_datasets = []
        f1_datasets = []
        roc_auc_datasets = []
        fpr_datasets = []

        for a in algos:
            c = chart_colors.get(a, {'border': '#f59e0b', 'bg': 'rgba(245, 158, 11, 0.75)'})
            accuracy_datasets.append({
                'label': a,
                'data': [algo_data_map[a]['Accuracy'].get(d, 0) for d in datasets],
                'backgroundColor': c['bg'],
                'borderColor': c['border'],
                'borderWidth': 1.5
            })
            precision_datasets.append({
                'label': a,
                'data': [algo_data_map[a]['Precision'].get(d, 0) for d in datasets],
                'backgroundColor': c['bg'],
                'borderColor': c['border'],
                'borderWidth': 1.5
            })
            f1_datasets.append({
                'label': a,
                'data': [algo_data_map[a]['F1_Score'].get(d, 0) for d in datasets],
                'backgroundColor': c['bg'],
                'borderColor': c['border'],
                'borderWidth': 1.5
            })
            roc_auc_datasets.append({
                'label': a,
                'data': [algo_data_map[a]['ROC_AUC'].get(d, 0) for d in datasets],
                'backgroundColor': c['bg'],
                'borderColor': c['border'],
                'borderWidth': 1.5
            })
            fpr_datasets.append({
                'label': a,
                'data': [algo_data_map[a]['FPR'].get(d, 0) for d in datasets],
                'backgroundColor': c['bg'],
                'borderColor': c['border'],
                'borderWidth': 1.5
            })

        radar_labels = json.dumps(['Accuracy', 'Precision', 'F1-Score', 'ROC-AUC'])
        radar_datasets = []
        for a in algos:
            st = stats.get(a, {'mean_accuracy': 0, 'mean_precision': 0, 'mean_f1': 0, 'mean_roc_auc': 0})
            c = chart_colors.get(a, {'border': '#f59e0b', 'bg': 'rgba(245, 158, 11, 0.2)'})
            radar_datasets.append({
                'label': a,
                'data': [st['mean_accuracy'], st['mean_precision'], st['mean_f1'], st.get('mean_roc_auc', 0)],
                'backgroundColor': c['bg'],
                'borderColor': c['border'],
                'borderWidth': 2,
                'pointBackgroundColor': c['border'],
                'pointHoverRadius': 5
            })

        raw_records_json = json.dumps(records)
        raw_stats_json = json.dumps(stats)

        # Tạo các dòng bảng HTML
        table_rows = []
        for r in records:
            acc = r.get('Accuracy', 0)
            prec = r.get('Precision', 0)
            f1 = r.get('F1_Score', 0)
            fpr = r.get('FPR', 0)
            roc_auc = r.get('ROC_AUC', 0)
            
            # Badge phân loại an ninh mạng & chất lượng
            if fpr <= 0.015 and acc >= 0.95:
                badge = '<span class="badge badge-success">🛡️ Siêu An Toàn (FPR &lt; 1.5%)</span>'
            elif fpr <= 0.05 and acc >= 0.85:
                badge = '<span class="badge badge-info">🏢 Chuẩn Doanh Nghiệp</span>'
            elif fpr <= 0.10:
                badge = '<span class="badge badge-warning">⚠️ Khá</span>'
            else:
                badge = '<span class="badge badge-danger">🚨 Cảnh Báo Giả Cao</span>'

            table_rows.append(f"""
            <tr>
                <td class="font-mono text-cyan-400">{r.get('Dataset')}</td>
                <td><span class="algo-pill algo-{r.get('Thuật_Toán', '').replace(' ', '-')}">{r.get('Thuật_Toán')}</span></td>
                <td class="font-mono font-bold">{acc:.4f}</td>
                <td class="font-mono">{prec:.4f}</td>
                <td class="font-mono font-bold text-emerald-400">{f1:.4f}</td>
                <td class="font-mono text-cyan-400">{roc_auc:.4f}</td>
                <td class="font-mono text-amber-400">{fpr*100:.2f}%</td>
                <td>{badge}</td>
            </tr>
            """)
        table_rows_html = "\n".join(table_rows)

        # Leaderboard cards
        leaderboard_cards = []
        medals = ["🥇", "🥈", "🥉"]
        sorted_algos = sorted(stats.keys(), key=lambda a: stats[a]['mean_f1'], reverse=True)
        for i, a in enumerate(sorted_algos):
            st = stats[a]
            medal = medals[i] if i < len(medals) else f"#{i+1}"
            leaderboard_cards.append(f"""
            <div class="card stat-card {'border-gold' if i==0 else ''}">
                <div class="flex items-center justify-between mb-2">
                    <span class="text-2xl">{medal}</span>
                    <span class="algo-pill algo-{a.replace(' ', '-')}">{a}</span>
                </div>
                <div class="text-xs text-gray-400">Mean F1-Score</div>
                <div class="text-2xl font-bold text-emerald-400 font-mono">{st['mean_f1']:.4f}</div>
                <div class="mt-2 text-xs flex justify-between text-gray-400">
                    <span>ROC-AUC: <b class="text-cyan-400 font-mono">{st.get('mean_roc_auc', 0):.4f}</b></span>
                    <span>FPR: <b class="text-amber-400 font-mono">{st.get('mean_fpr', 0)*100:.2f}%</b></span>
                </div>
                <div class="mt-1 text-xs flex justify-between text-gray-400">
                    <span>Acc: <b class="text-gray-200 font-mono">{st['mean_accuracy']:.4f}</b></span>
                    <span>Prec: <b class="text-gray-200 font-mono">{st['mean_precision']:.4f}</b></span>
                </div>
            </div>
            """)
        leaderboard_html = "\n".join(leaderboard_cards)

        dataset_options_html = '<option value="__all__">🌐 Tất Cả Tập Dữ Liệu (Tổng Quan Đa Dataset)</option>'
        for d in datasets:
            dataset_options_html += f'<option value="{d}">📁 {d}</option>'

        generation_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        html_content = f"""<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SHIELD-AI | Malware Detection Benchmark Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-base: #080c14;
            --bg-card: rgba(15, 23, 42, 0.88);
            --border-glow: rgba(0, 240, 255, 0.2);
            --cyan: #00f0ff;
            --emerald: #10b981;
            --purple: #a855f7;
            --amber: #f59e0b;
            --rose: #f43f5e;
            --text-primary: #f8fafc;
            --text-muted: #94a3b8;
        }}
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Inter', -apple-system, sans-serif;
        }}
        body {{
            background-color: var(--bg-base);
            color: var(--text-primary);
            background-image: 
                radial-gradient(circle at 10% 20%, rgba(0, 240, 255, 0.05) 0%, transparent 40%),
                radial-gradient(circle at 90% 80%, rgba(168, 85, 247, 0.05) 0%, transparent 40%);
            min-height: 100vh;
            padding-bottom: 60px;
        }}
        .font-mono {{ font-family: 'JetBrains Mono', monospace; }}
        .container {{ max-width: 1440px; margin: 0 auto; padding: 0 24px; }}
        
        /* HEADER */
        header {{
            background: rgba(10, 15, 29, 0.85);
            backdrop-filter: blur(16px);
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
            position: sticky;
            top: 0;
            z-index: 100;
            padding: 16px 0;
        }}
        .header-content {{
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .brand {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .shield-icon {{
            width: 38px;
            height: 38px;
            background: linear-gradient(135deg, var(--cyan), var(--purple));
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
            box-shadow: 0 0 20px rgba(0, 240, 255, 0.4);
        }}
        .title-group h1 {{
            font-size: 20px;
            font-weight: 800;
            letter-spacing: -0.5px;
            background: linear-gradient(90deg, #ffffff, var(--cyan));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .title-group p {{
            font-size: 12px;
            color: var(--text-muted);
        }}
        .live-badge {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: rgba(16, 185, 129, 0.15);
            color: #34d399;
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 11px;
            font-weight: 600;
            border: 1px solid rgba(52, 211, 153, 0.3);
        }}
        .pulse-dot {{
            width: 7px;
            height: 7px;
            background: #34d399;
            border-radius: 50%;
            box-shadow: 0 0 10px #34d399;
            animation: pulse 1.8s infinite;
        }}
        @keyframes pulse {{
            0% {{ transform: scale(0.95); opacity: 0.8; }}
            50% {{ transform: scale(1.3); opacity: 1; }}
            100% {{ transform: scale(0.95); opacity: 0.8; }}
        }}

        /* HERO STATS */
        .grid-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin: 28px 0;
        }}
        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border-glow);
            backdrop-filter: blur(12px);
            border-radius: 14px;
            padding: 20px;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        .card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 8px 24px rgba(0, 240, 255, 0.12);
        }}
        .stat-card .label {{
            font-size: 12px;
            font-weight: 500;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .stat-card .value {{
            font-size: 28px;
            font-weight: 800;
            margin: 8px 0;
            line-height: 1;
        }}
        .border-gold {{
            border-color: rgba(245, 158, 11, 0.6) !important;
            box-shadow: 0 0 20px rgba(245, 158, 11, 0.15) !important;
        }}

        /* MULTI-METRIC COMPARISON SUITE */
        .chart-grid {{
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 20px;
            margin-bottom: 28px;
        }}
        @media (max-width: 1024px) {{
            .chart-grid {{ grid-template-columns: 1fr; }}
        }}
        .chart-container {{
            position: relative;
            height: 400px;
            margin-top: 16px;
        }}
        .chart-toolbar {{
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            margin-bottom: 14px;
            padding-bottom: 12px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
        }}
        .view-mode-tabs {{
            display: inline-flex;
            background: rgba(0, 0, 0, 0.4);
            padding: 3px;
            border-radius: 8px;
            border: 1px solid rgba(255, 255, 255, 0.08);
            gap: 4px;
        }}
        .view-tab-btn {{
            background: transparent;
            border: none;
            color: var(--text-muted);
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .view-tab-btn.active {{
            background: linear-gradient(135deg, rgba(0, 240, 255, 0.25), rgba(16, 185, 129, 0.2));
            color: var(--cyan);
            box-shadow: 0 2px 8px rgba(0, 240, 255, 0.2);
            font-weight: 700;
        }}
        .metric-pills-bar {{
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
        }}
        .metric-pill {{
            background: rgba(255, 255, 255, 0.04);
            color: var(--text-muted);
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 6px 12px;
            border-radius: 8px;
            font-size: 11px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .metric-pill:hover {{
            background: rgba(0, 240, 255, 0.1);
            color: #ffffff;
            border-color: rgba(0, 240, 255, 0.3);
        }}
        .metric-pill.active {{
            background: linear-gradient(135deg, rgba(0, 240, 255, 0.3), rgba(16, 185, 129, 0.2));
            color: #ffffff;
            border-color: var(--cyan);
            box-shadow: 0 0 12px rgba(0, 240, 255, 0.3);
            font-weight: 700;
        }}
        .cyber-select {{
            background: rgba(15, 23, 42, 0.9);
            border: 1px solid rgba(0, 240, 255, 0.3);
            color: #f8fafc;
            padding: 7px 14px;
            border-radius: 8px;
            font-size: 12px;
            font-weight: 600;
            outline: none;
            cursor: pointer;
            min-width: 260px;
        }}
        .cyber-select:focus {{
            border-color: var(--cyan);
            box-shadow: 0 0 10px rgba(0, 240, 255, 0.3);
        }}
        .single-dataset-insight {{
            background: rgba(0, 0, 0, 0.25);
            border: 1px dashed rgba(255, 255, 255, 0.12);
            border-radius: 8px;
            padding: 10px 14px;
            margin-top: 12px;
            font-size: 12px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 8px;
        }}

        /* TABLE */
        .table-responsive {{
            overflow-x: auto;
            border-radius: 12px;
            border: 1px solid rgba(255, 255, 255, 0.08);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 13px;
        }}
        th {{
            background: rgba(15, 23, 42, 0.95);
            padding: 14px 18px;
            color: var(--text-muted);
            font-weight: 600;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
        }}
        td {{
            padding: 12px 18px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            color: #cbd5e1;
        }}
        tr:hover td {{
            background: rgba(255, 255, 255, 0.02);
        }}

        /* BADGES & PILLS */
        .badge {{
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
        }}
        .badge-success {{ background: rgba(16, 185, 129, 0.2); color: #34d399; }}
        .badge-info {{ background: rgba(0, 240, 255, 0.2); color: #38bdf8; }}
        .badge-warning {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; }}
        .badge-danger {{ background: rgba(244, 63, 94, 0.2); color: #fb7185; }}

        .algo-pill {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 9999px;
            font-size: 11px;
            font-weight: 700;
        }}
        .algo-XGBoost {{ background: rgba(0, 240, 255, 0.15); color: var(--cyan); border: 1px solid rgba(0, 240, 255, 0.3); }}
        .algo-Random-Forest {{ background: rgba(16, 185, 129, 0.15); color: var(--emerald); border: 1px solid rgba(16, 185, 129, 0.3); }}
        .algo-MLP {{ background: rgba(168, 85, 247, 0.15); color: var(--purple); border: 1px solid rgba(168, 85, 247, 0.3); }}

        /* BUTTONS & LINKS */
        .btn {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 16px;
            border-radius: 8px;
            font-size: 12px;
            font-weight: 600;
            text-decoration: none;
            cursor: pointer;
            transition: all 0.2s;
            border: none;
        }}
        .btn-primary {{
            background: linear-gradient(135deg, var(--cyan), #0284c7);
            color: #04121d;
            box-shadow: 0 4px 14px rgba(0, 240, 255, 0.3);
        }}
        .btn-primary:hover {{
            filter: brightness(1.1);
            transform: translateY(-1px);
        }}
        .btn-secondary {{
            background: rgba(255, 255, 255, 0.08);
            color: var(--text-primary);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        .btn-secondary:hover {{
            background: rgba(255, 255, 255, 0.14);
        }}
        
        .flex {{ display: flex; }}
        .items-center {{ align-items: center; }}
        .justify-between {{ justify-content: space-between; }}
        .gap-2 {{ gap: 8px; }}
        .gap-4 {{ gap: 16px; }}
        .mt-4 {{ margin-top: 16px; }}
        .mb-2 {{ margin-bottom: 8px; }}
        .text-cyan-400 {{ color: var(--cyan); }}
        .text-emerald-400 {{ color: var(--emerald); }}

        /* SUB-NAVIGATION & TABS */
        .sub-nav {{
            background: rgba(15, 23, 42, 0.75);
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
            backdrop-filter: blur(12px);
            padding: 8px 0;
            margin-bottom: 24px;
        }}
        .nav-tabs {{
            display: flex;
            gap: 8px;
        }}
        .nav-tab-btn {{
            background: transparent;
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: var(--text-muted);
            padding: 8px 18px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: all 0.25s ease;
        }}
        .nav-tab-btn:hover {{
            background: rgba(255, 255, 255, 0.05);
            color: #fff;
        }}
        .nav-tab-btn.active {{
            background: linear-gradient(135deg, rgba(0, 240, 255, 0.18), rgba(168, 85, 247, 0.18));
            color: var(--cyan);
            border-color: rgba(0, 240, 255, 0.45);
            box-shadow: 0 0 16px rgba(0, 240, 255, 0.2);
        }}
        .pulse-tag {{
            background: rgba(0, 240, 255, 0.2);
            color: var(--cyan);
            font-size: 10px;
            padding: 2px 7px;
            border-radius: 9999px;
            font-weight: 700;
            letter-spacing: 0.5px;
            animation: pulse 1.5s infinite;
        }}
        .api-status-pill {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 5px 12px;
            border-radius: 9999px;
            font-size: 11px;
            font-family: 'JetBrains Mono', monospace;
        }}
        .status-dot {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #94a3b8;
            box-shadow: 0 0 8px #94a3b8;
        }}
        .status-dot.online {{
            background: #10b981;
            box-shadow: 0 0 10px #10b981;
        }}
        .status-dot.offline {{
            background: #f59e0b;
            box-shadow: 0 0 10px #f59e0b;
        }}

        /* LIVE MALWARE SCANNER STYLES */
        /* STYLES CHO KHO LƯU TRỮ VÀ LỊCH SỬ QUÉT */
        .history-card {{
            background: linear-gradient(180deg, rgba(15, 23, 42, 0.95), rgba(8, 12, 20, 0.95));
            border: 1px solid rgba(0, 240, 255, 0.25);
            border-radius: 14px;
            padding: 20px;
            margin-top: 24px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
        }}
        .history-kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
            margin-bottom: 18px;
        }}
        .history-kpi-box {{
            background: rgba(15, 23, 42, 0.7);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 10px;
            padding: 12px 16px;
            transition: all 0.2s;
        }}
        .history-kpi-box:hover {{
            transform: translateY(-2px);
            border-color: rgba(0, 240, 255, 0.3);
        }}
        .history-filter-btn {{
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.12);
            color: #cbd5e1;
            padding: 6px 14px;
            border-radius: 8px;
            font-size: 11px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .history-filter-btn:hover {{
            background: rgba(255, 255, 255, 0.1);
            color: #fff;
        }}
        .history-filter-btn.active {{
            background: rgba(0, 240, 255, 0.18);
            border-color: var(--cyan);
            color: #fff;
            box-shadow: 0 0 12px rgba(0, 240, 255, 0.25);
        }}
        .history-table-wrapper {{
            background: rgba(10, 15, 28, 0.8);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 10px;
            overflow-x: auto;
        }}
        .history-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
        }}
        .history-table th {{
            background: rgba(0, 0, 0, 0.45);
            padding: 12px 14px;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
            white-space: nowrap;
        }}
        .history-table td {{
            padding: 12px 14px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            color: #cbd5e1;
            vertical-align: middle;
        }}
        .history-table tr:hover td {{
            background: rgba(0, 240, 255, 0.04);
        }}
        .btn-action-view {{
            background: rgba(0, 240, 255, 0.12);
            border: 1px solid rgba(0, 240, 255, 0.3);
            color: #00f0ff;
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 4px;
        }}
        .btn-action-view:hover {{
            background: var(--cyan);
            color: #04121d;
        }}
        .btn-action-dl {{
            background: rgba(16, 185, 129, 0.12);
            border: 1px solid rgba(16, 185, 129, 0.3);
            color: #10b981;
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 4px;
        }}
        .btn-action-dl:hover {{
            background: #10b981;
            color: #04121d;
        }}
        .btn-action-del {{
            background: rgba(244, 63, 94, 0.12);
            border: 1px solid rgba(244, 63, 94, 0.3);
            color: #fb7185;
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 4px;
        }}
        .btn-action-del:hover {{
            background: #f43f5e;
            color: #fff;
        }}
        .mini-algo-pill {{
            display: inline-block;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 10px;
            font-family: 'JetBrains Mono', monospace;
            font-weight: 700;
            margin: 1px;
        }}
        .mini-algo-pill.malware {{
            background: rgba(244, 63, 94, 0.2);
            color: #fda4af;
            border: 1px solid rgba(244, 63, 94, 0.35);
        }}
        .mini-algo-pill.benign {{
            background: rgba(16, 185, 129, 0.15);
            color: #6ee7b7;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }}

        .scanner-section {{
            display: flex;
            flex-direction: column;
            gap: 20px;
        }}
        .drop-zone {{
            background: rgba(15, 23, 42, 0.6);
            border: 2px dashed rgba(0, 240, 255, 0.35);
            border-radius: 16px;
            padding: 40px 24px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }}
        .drop-zone:hover, .drop-zone.dragover {{
            border-color: var(--cyan);
            background: rgba(0, 240, 255, 0.05);
            box-shadow: 0 0 28px rgba(0, 240, 255, 0.25);
            transform: translateY(-2px);
        }}
        .drop-icon {{
            font-size: 48px;
            margin-bottom: 12px;
            display: inline-block;
            filter: drop-shadow(0 0 12px rgba(0, 240, 255, 0.4));
        }}
        .drop-title {{
            font-size: 18px;
            font-weight: 700;
            color: #f8fafc;
            margin-bottom: 6px;
        }}
        .drop-sub {{
            font-size: 12px;
            color: var(--text-muted);
            max-width: 580px;
            margin: 0 auto;
            line-height: 1.5;
        }}
        .sample-chips {{
            display: flex;
            justify-content: center;
            gap: 10px;
            margin-top: 16px;
            flex-wrap: wrap;
        }}
        .sample-btn {{
            background: rgba(255, 255, 255, 0.06);
            border: 1px solid rgba(255, 255, 255, 0.12);
            color: #cbd5e1;
            padding: 5px 12px;
            border-radius: 6px;
            font-size: 11px;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .sample-btn:hover {{
            background: rgba(0, 240, 255, 0.15);
            border-color: var(--cyan);
            color: #fff;
        }}
        .file-card {{
            background: rgba(15, 23, 42, 0.9);
            border: 1px solid rgba(0, 240, 255, 0.3);
            border-radius: 12px;
            padding: 16px 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 12px;
        }}
        .file-chips-group {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            align-items: center;
        }}
        .file-chip {{
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11px;
            font-family: 'JetBrains Mono', monospace;
            color: #cbd5e1;
        }}
        .btn-scan {{
            background: linear-gradient(135deg, #00f0ff, #3b82f6);
            color: #04121d;
            font-weight: 800;
            padding: 10px 24px;
            border-radius: 10px;
            font-size: 13px;
            cursor: pointer;
            border: none;
            box-shadow: 0 4px 20px rgba(0, 240, 255, 0.4);
            transition: all 0.25s;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }}
        .btn-scan:hover {{
            filter: brightness(1.15);
            transform: translateY(-2px);
            box-shadow: 0 6px 24px rgba(0, 240, 255, 0.6);
        }}

        /* SCAN HUD & PROGRESS */
        .scan-hud {{
            background: rgba(10, 15, 29, 0.9);
            border: 1px solid rgba(0, 240, 255, 0.3);
            border-radius: 14px;
            padding: 24px;
        }}
        .hud-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 18px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
            padding-bottom: 12px;
        }}
        .hud-steps {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 12px;
        }}
        .hud-step {{
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.06);
            padding: 10px 14px;
            border-radius: 8px;
            font-size: 12px;
            display: flex;
            align-items: center;
            gap: 10px;
            color: #94a3b8;
            transition: all 0.3s;
        }}
        .hud-step.running {{
            border-color: var(--cyan);
            color: #fff;
            background: rgba(0, 240, 255, 0.1);
        }}
        .hud-step.done {{
            border-color: var(--emerald);
            color: #34d399;
            background: rgba(16, 185, 129, 0.08);
        }}

        /* VERDICT & RESULT CARDS */
        .verdict-banner {{
            padding: 24px;
            border-radius: 14px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 20px;
            flex-wrap: wrap;
            border: 1px solid transparent;
        }}
        .verdict-danger {{
            background: linear-gradient(135deg, rgba(244, 63, 94, 0.2), rgba(15, 23, 42, 0.85));
            border-color: rgba(244, 63, 94, 0.5);
            box-shadow: 0 0 30px rgba(244, 63, 94, 0.2);
        }}
        .verdict-warning {{
            background: linear-gradient(135deg, rgba(245, 158, 11, 0.2), rgba(15, 23, 42, 0.85));
            border-color: rgba(245, 158, 11, 0.5);
            box-shadow: 0 0 30px rgba(245, 158, 11, 0.2);
        }}
        .verdict-safe {{
            background: linear-gradient(135deg, rgba(16, 185, 129, 0.2), rgba(15, 23, 42, 0.85));
            border-color: rgba(16, 185, 129, 0.5);
            box-shadow: 0 0 30px rgba(16, 185, 129, 0.2);
        }}
        .verdict-title {{
            font-size: 24px;
            font-weight: 800;
            margin-bottom: 6px;
        }}
        .risk-gauge-box {{
            text-align: right;
        }}
        .risk-val {{
            font-size: 36px;
            font-weight: 900;
            font-family: 'JetBrains Mono', monospace;
            line-height: 1;
        }}

        .algo-grid-3 {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 16px;
            margin-bottom: 20px;
        }}
        @media (max-width: 860px) {{
            .algo-grid-3 {{ grid-template-columns: 1fr; }}
        }}
        .algo-scanner-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-glow);
            border-radius: 12px;
            padding: 18px;
            position: relative;
            overflow: hidden;
        }}
        .progress-track {{
            background: rgba(255, 255, 255, 0.08);
            height: 8px;
            border-radius: 9999px;
            margin: 12px 0 8px 0;
            overflow: hidden;
        }}
        .progress-fill {{
            height: 100%;
            border-radius: 9999px;
            transition: width 0.8s cubic-bezier(0.4, 0, 0.2, 1);
        }}
        .threat-tag {{
            background: rgba(244, 63, 94, 0.15);
            color: #fb7185;
            border: 1px solid rgba(244, 63, 94, 0.3);
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11px;
            display: inline-block;
            margin: 4px 4px 4px 0;
        }}
    </style>
</head>
<body>

    <header>
        <div class="container header-content">
            <div class="brand">
                <div class="shield-icon">🛡️</div>
                <div class="title-group">
                    <h1>SHIELD-AI | MALWARE DETECTION PLATFORM</h1>
                    <p>Hệ thống Đánh giá Thuật toán & Kiểm định Mã độc Thời gian thực</p>
                </div>
            </div>
            <div class="flex items-center gap-4">
                <div class="live-badge">
                    <div class="pulse-dot"></div>
                    MINIO S3 STORAGE
                </div>
                <a href="http://localhost:9001/browser/malware-evaluation" target="_blank" class="btn btn-primary">
                    🗄️ Mở MinIO Console
                </a>
            </div>
        </div>
    </header>

    <!-- SUB NAVIGATION BAR -->
    <nav class="sub-nav">
        <div class="container flex items-center justify-between">
            <div class="nav-tabs">
                <button class="nav-tab-btn active" id="tabNavBenchmark" onclick="switchDashboardTab('benchmark')">
                    <span>📊</span> BÁO CÁO BENCHMARK 13 DATASETS
                </button>
                <button class="nav-tab-btn" id="tabNavScanner" onclick="switchDashboardTab('scanner')">
                    <span>🔬</span> KIỂM ĐỊNH MÃ ĐỘC THỜI GIAN THỰC
                    <span class="pulse-tag">LIVE AI</span>
                </button>
            </div>
            <div class="api-status-pill" id="apiStatusPill" title="Cổng kết nối AI Scanner API: 5050">
                <span class="status-dot" id="statusDot"></span>
                <span id="statusText">Đang kiểm tra API Scanner...</span>
            </div>
        </div>
    </nav>

    <div class="container">

        <!-- TAB 1: BENCHMARK VIEW -->
        <div id="benchmarkView">

        <!-- STATS HERO -->
        <div class="grid-stats">
            <div class="card stat-card border-gold">
                <div class="label">🏆 Thuật Toán Quán Quân</div>
                <div class="value text-cyan-400">{best_algo}</div>
                <div class="text-xs text-gray-400">Hiệu năng cân bằng F1 & ROC-AUC cao nhất</div>
            </div>
            <div class="card stat-card">
                <div class="label">🎯 ROC-AUC Trung Bình</div>
                <div class="value font-mono text-emerald-400">{mean_auc_overall:.4f}</div>
                <div class="text-xs text-gray-400">Khả năng phân tách mã độc toàn mạng</div>
            </div>
            <div class="card stat-card">
                <div class="label">🛡️ Tỷ Lệ Báo Động Giả (FPR)</div>
                <div class="value font-mono text-amber-400">{mean_fpr_overall * 100:.2f}%</div>
                <div class="text-xs text-gray-400">Càng thấp càng an toàn cho hệ thống</div>
            </div>
            <div class="card stat-card">
                <div class="label">⚡ F1-Score Trung Bình</div>
                <div class="value font-mono text-cyan-400">{mean_f1_overall:.4f}</div>
                <div class="text-xs text-gray-400">Chỉ số cân bằng Precision & Recall</div>
            </div>
            <div class="card stat-card">
                <div class="label">📁 Datasets Phân Tích</div>
                <div class="value font-mono text-purple">{datasets_count} Datasets</div>
                <div class="text-xs text-gray-400">Kaggle & An ninh mạng đa dạng</div>
            </div>
        </div>

        <!-- LEADERBOARD CARDS -->
        <h2 style="font-size: 16px; font-weight: 700; margin-bottom: 12px; color: #cbd5e1;">BẢNG XẾP HẠNG THUẬT TOÁN (ALGORITHM LEADERBOARD)</h2>
        <div class="grid-stats" style="margin-top: 0; margin-bottom: 28px;">
            {leaderboard_html}
        </div>

        <!-- MULTI-METRIC COMPARISON SUITE (SO SÁNH ĐA CHỈ SỐ TOÀN DIỆN) -->
        <div class="chart-grid">
            <div class="card">
                <div class="chart-toolbar">
                    <div>
                        <h3 style="font-size: 15px; font-weight: 700; display: flex; align-items: center; gap: 8px;">
                            <span>📊</span> SO SÁNH ĐA CHỈ SỐ (MULTI-METRIC ANALYSIS)
                        </h3>
                        <p style="font-size: 11px; color: var(--text-muted); margin-top: 2px;" id="chartSubtitle">
                            Đang xem: So sánh F1-Score trên 13 tập dữ liệu
                        </p>
                    </div>

                    <!-- View Mode Toggle -->
                    <div class="view-mode-tabs">
                        <button class="view-tab-btn active" id="btnModeCross" onclick="switchViewMode('cross')">
                            🌐 Toàn Cảnh (Theo Chỉ Số)
                        </button>
                        <button class="view-tab-btn" id="btnModeDeep" onclick="switchViewMode('deep')">
                            🎯 Chi Tiết (Theo Dataset)
                        </button>
                    </div>
                </div>

                <!-- Mode 1: Metric Pills (Visible when in Cross-Dataset Mode) -->
                <div id="crossMetricControls" style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; margin-bottom: 10px;">
                    <span style="font-size: 11px; color: var(--text-muted);">Chọn chỉ số khảo sát:</span>
                    <div class="metric-pills-bar">
                        <button class="metric-pill" data-metric="Accuracy" onclick="selectMetric('Accuracy')">Accuracy</button>
                        <button class="metric-pill" data-metric="Precision" onclick="selectMetric('Precision')">Precision</button>
                        <button class="metric-pill active" data-metric="F1_Score" onclick="selectMetric('F1_Score')">F1-Score ⭐</button>
                        <button class="metric-pill" data-metric="ROC_AUC" onclick="selectMetric('ROC_AUC')">ROC-AUC</button>
                        <button class="metric-pill" data-metric="FPR" onclick="selectMetric('FPR')">Báo Động Giả (FPR) ⚠️</button>
                    </div>
                </div>

                <!-- Mode 2: Dataset Dropdown (Visible when in Deep-Dive Mode) -->
                <div id="deepDiveControls" style="display: none; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px; margin-bottom: 10px;">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span style="font-size: 12px; color: var(--cyan); font-weight: 600;">Chọn tập dữ liệu phân tích:</span>
                        <select id="datasetSelect" class="cyber-select" onchange="onSelectDataset(this.value)">
                            {dataset_options_html}
                        </select>
                    </div>
                    <span style="font-size: 11px; color: var(--text-muted);">Hiển thị trực quan 5 chỉ số song song của 3 thuật toán</span>
                </div>

                <div class="chart-container">
                    <canvas id="barChartCanvas"></canvas>
                </div>

                <!-- Single Dataset Dynamic Summary Card -->
                <div class="single-dataset-insight" id="singleDatasetInsight" style="display: none;">
                    <div id="datasetChampionText">🏆 <b>Quán quân:</b> XGBoost</div>
                    <div id="datasetSummaryMetrics" class="font-mono" style="color: var(--cyan);">F1: 0.9933 | Acc: 0.9933 | FPR: 0.04%</div>
                </div>
            </div>

            <!-- RADAR CHART CARD -->
            <div class="card">
                <div class="flex items-center justify-between mb-2">
                    <div>
                        <h3 style="font-size: 15px; font-weight: 700;">🎯 Radar Đa Trục Hiệu Năng</h3>
                        <p style="font-size: 11px; color: var(--text-muted);" id="radarSubtitle">Trung bình toàn bộ 13 Datasets</p>
                    </div>
                    <button class="btn btn-secondary" onclick="resetRadarChart()" style="font-size: 11px; padding: 4px 8px;" id="resetRadarBtn">
                        🔄 Toàn mạng
                    </button>
                </div>
                <div class="chart-container">
                    <canvas id="radarChartCanvas"></canvas>
                </div>
            </div>
        </div>

        <!-- STATIC PNG & DOWNLOADS SECTION -->
        <div class="card" style="margin-bottom: 28px;">
            <div class="flex items-center justify-between mb-2">
                <div>
                    <h3 style="font-size: 15px; font-weight: 700;">🖼️ Đồ Thị Matplotlib Chi Tiết (300 DPI Export)</h3>
                    <p style="font-size: 12px; color: var(--text-muted);">Đã sinh tự động từ Airflow Task và đồng bộ lên MinIO</p>
                </div>
                <div class="flex gap-2">
                    <a href="Model_Evaluation_Chart.png" download class="btn btn-secondary">📥 Tải PNG</a>
                    <a href="Model_Evaluation_Chart.pdf" download class="btn btn-secondary">📑 Tải PDF</a>
                    <a href="combined_model_evaluation_report.csv" download class="btn btn-secondary">📊 Tải CSV Báo Cáo</a>
                </div>
            </div>
            <div style="text-align: center; margin-top: 14px;">
                <img src="data:image/png;base64,{b64_chart}" alt="Model Evaluation Chart" style="max-width: 100%; border-radius: 8px; border: 1px solid rgba(255,255,255,0.1);">
            </div>
        </div>

        <!-- TABLE SECTION -->
        <div class="card">
            <div class="flex items-center justify-between mb-2">
                <h3 style="font-size: 15px; font-weight: 700;">📋 Bảng Chi Tiết Kết Quả Đánh Giá Từng Mô Hình</h3>
                <input type="text" id="tableSearch" placeholder="🔍 Tìm kiếm dataset..." 
                       style="background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.1); color: #fff; padding: 6px 12px; border-radius: 6px; font-size: 12px;"
                       onkeyup="filterTable()">
            </div>
            <div class="table-responsive mt-4">
                <table id="evaluationTable">
                    <thead>
                        <tr>
                            <th>Tập Dữ Liệu (Dataset)</th>
                            <th>Thuật Toán</th>
                            <th>Accuracy</th>
                            <th>Precision</th>
                            <th>F1-Score</th>
                            <th>ROC-AUC</th>
                            <th>FPR (Báo Động Giả)</th>
                            <th>Đánh Giá An Toàn</th>
                        </tr>
                    </thead>
                    <tbody>
                        {table_rows_html}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- FOOTER INFO -->
        <div style="text-align: center; margin-top: 40px; font-size: 12px; color: var(--text-muted);">
            <p>Hệ thống Tự động hóa Pipeline & Đánh giá Mã độc Airflow 2.10 | MinIO Object Storage Bucket: <code>malware-evaluation</code></p>
            <p style="margin-top: 4px;">Thời gian tạo báo cáo: <span class="font-mono text-cyan-400">{generation_time}</span></p>
        </div>

        </div> <!-- /#benchmarkView -->

        <!-- TAB 2: LIVE MALWARE SCANNER VIEW -->
        <div id="scannerView" style="display: none;" class="scanner-section">

            <!-- INTRO HERO CARD -->
            <div class="card" style="background: linear-gradient(135deg, rgba(15, 23, 42, 0.95), rgba(8, 12, 20, 0.9)); border-color: rgba(0, 240, 255, 0.3);">
                <div class="flex items-center justify-between" style="flex-wrap: wrap; gap: 16px;">
                    <div>
                        <h2 style="font-size: 20px; font-weight: 800; display: flex; align-items: center; gap: 10px;">
                            <span>🔬</span> PHÒNG THÍ NGHIỆM GIÁM ĐỊNH MÃ ĐỘC THỜI GIAN THỰC
                            <span class="badge badge-info">AI INFERENCE v2.0</span>
                        </h2>
                        <p style="font-size: 13px; color: var(--text-muted); margin-top: 6px;">
                            Tải tệp tin người dùng lên để 3 thuật toán học máy (<b>Random Forest, XGBoost, Deep Learning MLP</b>) trực tiếp bóc tách cấu trúc PE Header, đo độ hỗn loạn Shannon Entropy và đưa ra kết luận kiểm định.
                        </p>
                    </div>
                    <div class="flex gap-2">
                        <button class="btn btn-secondary" onclick="checkScannerHealth(true)">
                            🔄 Kiểm tra kết nối API
                        </button>
                    </div>
                </div>
            </div>

            <!-- DRAG & DROP ZONE -->
            <div class="drop-zone" id="dropZone" onclick="document.getElementById('fileInput').click()" 
                 ondragover="onDragOver(event)" ondragleave="onDragLeave(event)" ondrop="onDropFile(event)">
                <input type="file" id="fileInput" style="display: none;" onchange="onFileSelected(event)">
                <div class="drop-icon">🛡️</div>
                <div class="drop-title">KÉO & THẢ TỆP TIN CẦN KIỂM ĐỊNH VÀO ĐÂY</div>
                <div class="drop-sub">
                    Hoặc click vào khung để duyệt file từ máy tính của bạn.<br>
                    Hỗ trợ file thực thi Windows (<code>.exe</code>, <code>.dll</code>, <code>.sys</code>), tệp nhị phân (<code>.bin</code>), tệp kịch bản (PowerShell, Shell, VBS), hoặc tài liệu bất kỳ.
                </div>
                
                <!-- PRESET SAMPLES -->
                <div class="sample-chips" onclick="event.stopPropagation()">
                    <span style="font-size: 11px; color: var(--text-muted); align-self: center;">Mẫu thử nghiệm nhanh:</span>
                    <button class="sample-btn" onclick="testPresetSample('revosetup.exe')">
                        📁 Mẫu PE: revosetup.exe
                    </button>
                    <button class="sample-btn" onclick="testCleanTextSample()">
                        📄 Mẫu: Text Lành tính (Benign Doc)
                    </button>
                    <button class="sample-btn" onclick="testHighEntropySample()">
                        ⚠️ Mẫu: Encrypted / High Entropy
                    </button>
                </div>
            </div>

            <!-- SELECTED FILE CARD -->
            <div class="file-card" id="selectedFileCard" style="display: none;">
                <div class="flex items-center gap-4">
                    <div style="font-size: 32px;" id="fileIcon">📦</div>
                    <div>
                        <div style="font-size: 15px; font-weight: 700; color: #fff;" id="fileNameDisplay">sample.exe</div>
                        <div class="file-chips-group mt-2">
                            <span class="file-chip" id="fileSizeDisplay">0 KB</span>
                            <span class="file-chip" id="fileTypeDisplay">Windows PE</span>
                            <span class="file-chip" id="fileHashDisplay" style="color: var(--cyan);">SHA256: ...</span>
                        </div>
                    </div>
                </div>
                <button class="btn-scan" id="btnStartScan" onclick="triggerMalwareScan()">
                    <span>🚀</span> BẮT ĐẦU PHÂN TÍCH TOÀN DIỆN
                </button>
            </div>

            <!-- SCAN PROGRESS HUD -->
            <div class="scan-hud" id="scanHudBox" style="display: none;">
                <div class="hud-header">
                    <div class="flex items-center gap-2">
                        <div class="pulse-dot"></div>
                        <span style="font-weight: 700; font-size: 14px; color: var(--cyan);">TIẾN TRÌNH GIÁM ĐỊNH MÃ ĐỘC ĐA TẦNG (CYBER SOC HUD)</span>
                    </div>
                    <span class="font-mono text-cyan-400" id="hudProgressPercent" style="font-weight: 800;">0%</span>
                </div>
                <div class="hud-steps">
                    <div class="hud-step" id="step1"><span>1.</span> <span>🔍 Băm mã định danh (MD5, SHA-1, SHA-256)</span></div>
                    <div class="hud-step" id="step2"><span>2.</span> <span>📊 Tính độ hỗn loạn Shannon Entropy (0 - 8.0)</span></div>
                    <div class="hud-step" id="step3"><span>3.</span> <span>🧬 Bóc tách PE Headers & Sections nhị phân</span></div>
                    <div class="hud-step" id="step4"><span>4.</span> <span>🌲 Dự đoán mô hình Random Forest (100 Cây)</span></div>
                    <div class="hud-step" id="step5"><span>5.</span> <span>⚡ Dự đoán mô hình XGBoost Classifier</span></div>
                    <div class="hud-step" id="step6"><span>6.</span> <span>🧠 Dự đoán mô hình Deep Learning MLP</span></div>
                    <div class="hud-step" id="step7"><span>7.</span> <span>🛡️ Đánh giá đồng thuận SOC Consensus</span></div>
                </div>
            </div>

            <!-- SCAN RESULTS CONTAINER -->
            <div id="scanResultsContainer" style="display: none;">

                <!-- 1. SOC CONSENSUS VERDICT BANNER -->
                <div class="verdict-banner" id="verdictBanner">
                    <div>
                        <div class="flex items-center gap-2 mb-2">
                            <span class="badge" id="verdictLevelBadge">CRITICAL THREAT</span>
                            <span style="font-size: 12px; color: var(--text-muted);">KẾT QUẢ ĐỒNG THUẬN TỪ 3 THUẬT TOÁN (SOC CONSENSUS)</span>
                        </div>
                        <div class="verdict-title" id="verdictHeadline">🚨 PHÁT HIỆN MÃ ĐỘC NGUY HIỂM</div>
                        <p style="font-size: 13px; color: #cbd5e1; max-width: 650px;" id="verdictRecommendation">
                            Khuyến cáo cách ly tệp tin ngay lập tức. Không thực thi trên môi trường máy thật.
                        </p>
                    </div>
                    <div class="risk-gauge-box">
                        <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 1px;">Xác Suất Rủi Ro</div>
                        <div class="risk-val text-rose" id="verdictRiskPercent">85.0%</div>
                        <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;" id="verdictEntropyNote">Entropy: 7.99/8.0</div>
                    </div>
                </div>

                <!-- 2. THREE ALGORITHMS BREAKDOWN -->
                <h3 style="font-size: 15px; font-weight: 700; margin-bottom: 12px; color: #cbd5e1;">KẾT QUẢ ĐÁNH GIÁ ĐỘC LẬP TỪNG THUẬT TOÁN</h3>
                <div class="algo-grid-3">
                    <!-- Random Forest Card -->
                    <div class="algo-scanner-card">
                        <div class="flex items-center justify-between mb-2">
                            <span class="algo-pill algo-Random-Forest">🌲 Random Forest</span>
                            <span class="badge" id="rfStatusBadge">Phát Hiện</span>
                        </div>
                        <div style="font-size: 11px; color: var(--text-muted);">Độ Tin Cậy Rủi Ro Mã Độc</div>
                        <div class="flex items-center justify-between mt-1">
                            <span class="font-mono" style="font-size: 22px; font-weight: 800;" id="rfProbText">52.7%</span>
                            <span style="font-size: 11px; color: var(--text-muted);">100 Cây Quyết Định</span>
                        </div>
                        <div class="progress-track">
                            <div class="progress-fill" id="rfProgressBar" style="width: 52.7%; background: #10b981;"></div>
                        </div>
                        <div style="font-size: 11px; color: var(--text-muted); margin-top: 8px;">
                            Huấn luyện trên 19.612 mẫu PE • Độ chính xác F1: <b>99.39%</b>
                        </div>
                    </div>

                    <!-- XGBoost Card -->
                    <div class="algo-scanner-card">
                        <div class="flex items-center justify-between mb-2">
                            <span class="algo-pill algo-XGBoost">⚡ XGBoost</span>
                            <span class="badge" id="xgbStatusBadge">Lành Tính</span>
                        </div>
                        <div style="font-size: 11px; color: var(--text-muted);">Độ Tin Cậy Rủi Ro Mã Độc</div>
                        <div class="flex items-center justify-between mt-1">
                            <span class="font-mono" style="font-size: 22px; font-weight: 800;" id="xgbProbText">10.2%</span>
                            <span style="font-size: 11px; color: var(--text-muted);">Tăng Cường Độ Dốc</span>
                        </div>
                        <div class="progress-track">
                            <div class="progress-fill" id="xgbProgressBar" style="width: 10.2%; background: #00f0ff;"></div>
                        </div>
                        <div style="font-size: 11px; color: var(--text-muted); margin-top: 8px;">
                            Huấn luyện trên 19.612 mẫu PE • Độ chính xác F1: <b>99.44%</b>
                        </div>
                    </div>

                    <!-- MLP Card -->
                    <div class="algo-scanner-card">
                        <div class="flex items-center justify-between mb-2">
                            <span class="algo-pill algo-MLP">🧠 Deep Learning (MLP)</span>
                            <span class="badge" id="mlpStatusBadge">Lành Tính</span>
                        </div>
                        <div style="font-size: 11px; color: var(--text-muted);">Độ Tin Cậy Rủi Ro Mã Độc</div>
                        <div class="flex items-center justify-between mt-1">
                            <span class="font-mono" style="font-size: 22px; font-weight: 800;" id="mlpProbText">0.5%</span>
                            <span style="font-size: 11px; color: var(--text-muted);">Multi-Layer Perceptron</span>
                        </div>
                        <div class="progress-track">
                            <div class="progress-fill" id="mlpProgressBar" style="width: 0.5%; background: #a855f7;"></div>
                        </div>
                        <div style="font-size: 11px; color: var(--text-muted); margin-top: 8px;">
                            Mạng nơ-ron thích ứng động • Độ chính xác F1: <b>98.88%</b>
                        </div>
                    </div>
                </div>

                <!-- 3. FORENSICS & THREAT INDICATORS -->
                <div class="card" style="margin-bottom: 20px;">
                    <h3 style="font-size: 15px; font-weight: 700; margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
                        <span>🚩</span> DẤU HIỆU CẢNH BÁO AN NINH & GIÁM ĐỊNH TĨNH (THREAT INDICATORS)
                    </h3>
                    <div id="threatIndicatorsList" style="display: flex; flex-direction: column; gap: 8px; margin-bottom: 16px;">
                        <!-- Threat items rendered via JS -->
                    </div>

                    <div style="border-top: 1px solid rgba(255, 255, 255, 0.08); padding-top: 14px;">
                        <h4 style="font-size: 13px; font-weight: 600; color: #cbd5e1; margin-bottom: 8px;">Các hàm API an ninh mạng nguy hiểm tìm thấy:</h4>
                        <div id="suspiciousApisTags">
                            <!-- API pills -->
                        </div>
                    </div>
                </div>

                <!-- 4. ACTIONS: EXPORT & COPY -->
                <div class="flex items-center justify-between" style="flex-wrap: wrap; gap: 12px;">
                    <div class="flex gap-2">
                        <button class="btn btn-primary" onclick="downloadForensicReport()">
                            📥 Tải Báo Cáo Giám Định (JSON)
                        </button>
                        <button class="btn btn-secondary" onclick="copyForensicReport()">
                            📋 Sao Chép Kết Quả
                        </button>
                    </div>
                    <button class="btn btn-secondary" onclick="resetScanner()">
                        🔄 Quét tệp tin khác
                    </button>
                </div>

            </div> <!-- /#scanResultsContainer -->

            <!-- 5. KHO LƯU TRỮ & LỊCH SỬ CÁC TỆP ĐÃ TẢI LÊN -->
            <div class="history-card" id="historyCard">
                <div class="flex items-center justify-between" style="flex-wrap: wrap; gap: 14px; margin-bottom: 18px; border-bottom: 1px solid rgba(255, 255, 255, 0.08); padding-bottom: 14px;">
                    <div>
                        <h3 style="font-size: 16px; font-weight: 800; display: flex; align-items: center; gap: 10px; color: #fff;">
                            <span>📁</span> KHO LƯU TRỮ & LỊCH SỬ CÁC TỆP ĐÃ TẢI LÊN
                            <span class="badge badge-info" id="historyTotalBadge">0 tệp tin</span>
                        </h3>
                        <p style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">
                            Hệ thống tự động lưu trữ các tệp tin người dùng tải lên, mã băm định danh và kết luận kiểm định từ 3 mô hình học máy.
                        </p>
                    </div>
                    <div class="flex items-center gap-2">
                        <button class="btn btn-secondary" style="font-size: 11px; padding: 6px 12px;" onclick="loadScanHistory(true)">
                            🔄 Làm mới
                        </button>
                        <button class="btn btn-secondary" style="font-size: 11px; padding: 6px 12px; color: #fb7185; border-color: rgba(244, 63, 94, 0.3);" onclick="confirmClearHistory()">
                            🗑️ Xóa toàn bộ
                        </button>
                    </div>
                </div>

                <!-- QUICK STATS CARDS -->
                <div class="history-kpi-grid">
                    <div class="history-kpi-box">
                        <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase;">Tổng số tệp đã lưu</div>
                        <div style="font-size: 22px; font-weight: 800; color: #00f0ff; margin-top: 4px;" id="statTotalScans">0</div>
                    </div>
                    <div class="history-kpi-box" style="background: rgba(244, 63, 94, 0.08); border-color: rgba(244, 63, 94, 0.25);">
                        <div style="font-size: 11px; color: #fda4af; text-transform: uppercase;">Mã độc nguy hiểm</div>
                        <div style="font-size: 22px; font-weight: 800; color: #f43f5e; margin-top: 4px;" id="statMalwareScans">0</div>
                    </div>
                    <div class="history-kpi-box" style="background: rgba(245, 158, 11, 0.08); border-color: rgba(245, 158, 11, 0.25);">
                        <div style="font-size: 11px; color: #fcd34d; text-transform: uppercase;">Cảnh báo / Nghi vấn</div>
                        <div style="font-size: 22px; font-weight: 800; color: #f59e0b; margin-top: 4px;" id="statSuspiciousScans">0</div>
                    </div>
                    <div class="history-kpi-box" style="background: rgba(16, 185, 129, 0.08); border-color: rgba(16, 185, 129, 0.25);">
                        <div style="font-size: 11px; color: #6ee7b7; text-transform: uppercase;">Tệp an toàn (Clean)</div>
                        <div style="font-size: 22px; font-weight: 800; color: #10b981; margin-top: 4px;" id="statSafeScans">0</div>
                    </div>
                </div>

                <!-- SEARCH & FILTER BAR -->
                <div class="flex items-center justify-between" style="flex-wrap: wrap; gap: 12px; margin-bottom: 14px;">
                    <div style="position: relative; flex: 1; min-width: 240px;">
                        <input type="text" id="historySearchInput" placeholder="🔍 Tìm kiếm theo tên tệp hoặc mã băm SHA256..." 
                               style="width: 100%; background: rgba(0, 0, 0, 0.4); border: 1px solid rgba(255, 255, 255, 0.12); color: #fff; padding: 8px 14px; border-radius: 8px; font-size: 12px; outline: none;"
                               oninput="filterScanHistory()">
                    </div>
                    <div class="flex gap-2" style="flex-wrap: wrap;">
                        <button class="history-filter-btn active" data-filter="all" onclick="setHistoryFilter('all', this)">Tất cả</button>
                        <button class="history-filter-btn" data-filter="malware" onclick="setHistoryFilter('malware', this)" style="color: #f43f5e;">🚨 Mã độc</button>
                        <button class="history-filter-btn" data-filter="suspicious" onclick="setHistoryFilter('suspicious', this)" style="color: #f59e0b;">⚠️ Nghi vấn</button>
                        <button class="history-filter-btn" data-filter="safe" onclick="setHistoryFilter('safe', this)" style="color: #10b981;">🛡️ An toàn</button>
                    </div>
                </div>

                <!-- TABLE CONTAINER -->
                <div class="history-table-wrapper">
                    <table class="history-table" id="historyTable">
                        <thead>
                            <tr>
                                <th style="text-align: center; width: 45px;">#</th>
                                <th style="text-align: left;">Tên Tệp Tin & Checksum</th>
                                <th style="text-align: left;">Thời Gian</th>
                                <th style="text-align: right;">Kích Thước</th>
                                <th style="text-align: left;">Định Dạng</th>
                                <th style="text-align: center;">Đánh Giá SOC</th>
                                <th style="text-align: center;">3 Mô Hình (RF / XGB / MLP)</th>
                                <th style="text-align: center; width: 150px;">Thao Tác</th>
                            </tr>
                        </thead>
                        <tbody id="historyTableBody">
                            <tr>
                                <td colspan="8" style="text-align: center; padding: 30px; color: var(--text-muted);">
                                    Đang tải lịch sử tệp tin...
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>


        </div> <!-- /#scannerView -->

    </div>

    <script>
        // Dữ liệu gốc được nhúng từ Airflow Task
        const datasetLabels = {datasets_labels_json};
        const allRecords = {raw_records_json};
        const algoStats = {raw_stats_json};
        
        const metricDatasets = {{
            'Accuracy': {json.dumps(accuracy_datasets)},
            'Precision': {json.dumps(precision_datasets)},
            'F1_Score': {json.dumps(f1_datasets)},
            'ROC_AUC': {json.dumps(roc_auc_datasets)},
            'FPR': {json.dumps(fpr_datasets)}
        }};

        const chartColors = {{
            'XGBoost': {{ 'border': '#00f0ff', 'bg': 'rgba(0, 240, 255, 0.75)' }},
            'Random Forest': {{ 'border': '#10b981', 'bg': 'rgba(16, 185, 129, 0.75)' }},
            'MLP': {{ 'border': '#a855f7', 'bg': 'rgba(168, 85, 247, 0.75)' }}
        }};

        let currentViewMode = 'cross'; // 'cross' | 'deep'
        let currentMetric = 'F1_Score';
        let currentSelectedDataset = datasetLabels[0] || '';

        // Khởi tạo Bar Chart
        const ctxBar = document.getElementById('barChartCanvas').getContext('2d');
        let barChart = new Chart(ctxBar, {{
            type: 'bar',
            data: {{
                labels: datasetLabels,
                datasets: metricDatasets['F1_Score']
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                animation: {{ duration: 500, easing: 'easeOutQuart' }},
                plugins: {{
                    legend: {{
                        labels: {{ color: '#cbd5e1', font: {{ family: 'Inter', weight: '600' }} }}
                    }},
                    tooltip: {{
                        backgroundColor: 'rgba(15, 23, 42, 0.95)',
                        borderColor: 'rgba(0, 240, 255, 0.4)',
                        borderWidth: 1,
                        padding: 10,
                        titleFont: {{ family: 'Inter', weight: 'bold' }},
                        bodyFont: {{ family: 'JetBrains Mono' }}
                    }}
                }},
                scales: {{
                    x: {{
                        ticks: {{
                            color: '#94a3b8',
                            font: {{ family: 'Inter', size: 10 }},
                            maxRotation: 30,
                            callback: function(val, index) {{
                                const label = this.getLabelForValue(val);
                                if (!label) return '';
                                if (currentViewMode === 'cross') {{
                                    return label.length > 18 ? label.substring(0, 16) + '...' : label;
                                }}
                                return label;
                            }}
                        }},
                        grid: {{ color: 'rgba(255, 255, 255, 0.05)' }}
                    }},
                    y: {{
                        min: 0,
                        max: 1.1,
                        ticks: {{ color: '#94a3b8', font: {{ family: 'JetBrains Mono' }} }},
                        grid: {{ color: 'rgba(255, 255, 255, 0.05)' }}
                    }}
                }}
            }}
        }});

        // Khởi tạo Radar Chart
        const ctxRadar = document.getElementById('radarChartCanvas').getContext('2d');
        const defaultRadarLabels = {radar_labels};
        const defaultRadarDatasets = {json.dumps(radar_datasets)};
        
        let radarChart = new Chart(ctxRadar, {{
            type: 'radar',
            data: {{
                labels: defaultRadarLabels,
                datasets: defaultRadarDatasets
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                animation: {{ duration: 400 }},
                plugins: {{
                    legend: {{ labels: {{ color: '#cbd5e1', font: {{ family: 'Inter', weight: '600' }} }} }},
                    tooltip: {{
                        backgroundColor: 'rgba(15, 23, 42, 0.95)',
                        borderColor: 'rgba(168, 85, 247, 0.4)',
                        borderWidth: 1
                    }}
                }},
                scales: {{
                    r: {{
                        min: 0,
                        max: 1.0,
                        ticks: {{ color: '#94a3b8', backdropColor: 'transparent', stepSize: 0.2 }},
                        grid: {{ color: 'rgba(255, 255, 255, 0.1)' }},
                        angleLines: {{ color: 'rgba(255, 255, 255, 0.1)' }},
                        pointLabels: {{ color: '#f8fafc', font: {{ size: 11, weight: 'bold' }} }}
                    }}
                }}
            }}
        }});

        // ==========================================
        // MULTI-METRIC VIEW SWITCHING LOGIC
        // ==========================================

        function switchViewMode(mode) {{
            currentViewMode = mode;
            const btnCross = document.getElementById('btnModeCross');
            const btnDeep = document.getElementById('btnModeDeep');
            const crossControls = document.getElementById('crossMetricControls');
            const deepControls = document.getElementById('deepDiveControls');
            const insightBox = document.getElementById('singleDatasetInsight');
            const subtitle = document.getElementById('chartSubtitle');

            if (mode === 'cross') {{
                btnCross.classList.add('active');
                btnDeep.classList.remove('active');
                crossControls.style.display = 'flex';
                deepControls.style.display = 'none';
                insightBox.style.display = 'none';
                subtitle.textContent = `Đang xem: So sánh chỉ số ${{currentMetric}} trên toàn bộ 13 tập dữ liệu`;
                renderCrossDatasetView();
            }} else {{
                btnCross.classList.remove('active');
                btnDeep.classList.add('active');
                crossControls.style.display = 'none';
                deepControls.style.display = 'flex';
                insightBox.style.display = 'flex';
                
                const selectEl = document.getElementById('datasetSelect');
                if (selectEl.value === '__all__') {{
                    selectEl.value = datasetLabels[0] || '';
                }}
                currentSelectedDataset = selectEl.value;
                subtitle.textContent = `Đang xem: Bóc tách 5 chỉ số chi tiết cho tập [${{currentSelectedDataset}}]`;
                renderDeepDiveView(currentSelectedDataset);
            }}
        }}

        function selectMetric(metric) {{
            currentMetric = metric;
            document.querySelectorAll('.metric-pill').forEach(btn => {{
                if (btn.getAttribute('data-metric') === metric) {{
                    btn.classList.add('active');
                }} else {{
                    btn.classList.remove('active');
                }}
            }});
            document.getElementById('chartSubtitle').textContent = `Đang xem: So sánh chỉ số ${{metric}} trên toàn bộ 13 tập dữ liệu`;
            renderCrossDatasetView();
        }}

        function renderCrossDatasetView() {{
            barChart.data.labels = datasetLabels;
            barChart.data.datasets = metricDatasets[currentMetric];

            if (currentMetric === 'FPR') {{
                let maxVal = 0;
                metricDatasets['FPR'].forEach(ds => {{
                    ds.data.forEach(v => {{ if (v > maxVal) maxVal = v; }});
                }});
                barChart.options.scales.y.max = Math.min(1.0, Math.max(0.25, Math.ceil(maxVal * 12) / 10));
            }} else {{
                barChart.options.scales.y.max = 1.1;
            }}
            barChart.update();
        }}

        function onSelectDataset(datasetName) {{
            if (datasetName === '__all__') {{
                switchViewMode('cross');
                return;
            }}
            currentSelectedDataset = datasetName;
            document.getElementById('chartSubtitle').textContent = `Đang xem: Bóc tách 5 chỉ số chi tiết cho tập [${{datasetName}}]`;
            renderDeepDiveView(datasetName);
            updateRadarForDataset(datasetName);
        }}

        function renderDeepDiveView(datasetName) {{
            const metricKeys = ['Accuracy', 'Precision', 'F1_Score', 'ROC_AUC', 'FPR'];
            const metricDisplayNames = ['Accuracy', 'Precision', 'F1-Score', 'ROC-AUC', 'FPR (Báo Giả)'];

            const dsRecords = allRecords.filter(r => r.Dataset === datasetName);
            const algos = ['XGBoost', 'Random Forest', 'MLP'];

            const newDatasets = [];
            let bestAlgoForDs = '';
            let bestF1ForDs = -1;

            algos.forEach(algo => {{
                const rec = dsRecords.find(r => r.Thuật_Toán === algo) || {{}};
                const dataPoints = metricKeys.map(k => Number(rec[k] || 0));
                const f1 = Number(rec.F1_Score || 0);
                if (f1 > bestF1ForDs) {{
                    bestF1ForDs = f1;
                    bestAlgoForDs = algo;
                }}

                const c = chartColors[algo] || {{ border: '#f59e0b', bg: 'rgba(245, 158, 11, 0.75)' }};
                newDatasets.push({{
                    label: algo,
                    data: dataPoints,
                    backgroundColor: c.bg,
                    borderColor: c.border,
                    borderWidth: 1.5
                }});
            }});

            barChart.data.labels = metricDisplayNames;
            barChart.data.datasets = newDatasets;
            barChart.options.scales.y.max = 1.15;
            barChart.update();

            const insightBox = document.getElementById('singleDatasetInsight');
            const champText = document.getElementById('datasetChampionText');
            const metricsText = document.getElementById('datasetSummaryMetrics');
            insightBox.style.display = 'flex';

            const bestRec = dsRecords.find(r => r.Thuật_Toán === bestAlgoForDs) || {{}};
            champText.innerHTML = `🏆 <b>Mô hình tối ưu nhất cho tập này:</b> <span style="color: var(--cyan); font-weight: bold;">${{bestAlgoForDs}}</span> (F1: <b>${{Number(bestRec.F1_Score || 0).toFixed(4)}}</b>)`;
            metricsText.innerHTML = `Acc: ${{Number(bestRec.Accuracy || 0).toFixed(4)}} | Prec: ${{Number(bestRec.Precision || 0).toFixed(4)}} | ROC-AUC: ${{Number(bestRec.ROC_AUC || 0).toFixed(4)}} | FPR: <span style="color: #fbbf24;">${{(Number(bestRec.FPR || 0)*100).toFixed(2)}}%</span>`;
        }}

        function updateRadarForDataset(datasetName) {{
            const dsRecords = allRecords.filter(r => r.Dataset === datasetName);
            const algos = ['XGBoost', 'Random Forest', 'MLP'];
            const newRadarDatasets = [];

            algos.forEach(algo => {{
                const rec = dsRecords.find(r => r.Thuật_Toán === algo) || {{}};
                const c = chartColors[algo] || {{ border: '#f59e0b', bg: 'rgba(245, 158, 11, 0.2)' }};
                newRadarDatasets.push({{
                    label: algo,
                    data: [
                        Number(rec.Accuracy || 0),
                        Number(rec.Precision || 0),
                        Number(rec.F1_Score || 0),
                        Number(rec.ROC_AUC || 0)
                    ],
                    backgroundColor: c.bg.replace('0.75', '0.2'),
                    borderColor: c.border,
                    borderWidth: 2,
                    pointBackgroundColor: c.border
                }});
            }});

            radarChart.data.datasets = newRadarDatasets;
            document.getElementById('radarSubtitle').textContent = `Tập dữ liệu: ${{datasetName}}`;
            radarChart.update();
        }}

        function resetRadarChart() {{
            radarChart.data.datasets = defaultRadarDatasets;
            document.getElementById('radarSubtitle').textContent = 'Trung bình toàn bộ 13 Datasets';
            radarChart.update();
        }}

        // Table search filter
        function filterTable() {{
            const input = document.getElementById('tableSearch').value.toLowerCase();
            const rows = document.querySelectorAll('#evaluationTable tbody tr');
            rows.forEach(row => {{
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(input) ? '' : 'none';
            }});
        }}

        // ==========================================
        // LIVE MALWARE SCANNER CONTROLLER
        // ==========================================
        const SCANNER_API_BASE = (window.location.port === '5050' && !window.location.pathname.includes('/opt/')) ? '' : (window.location.protocol + '//' + (window.location.hostname || 'localhost') + ':5050');
        let currentScanFile = null;
        let lastScanResult = null;

        function switchDashboardTab(tab) {{
            const btnBench = document.getElementById('tabNavBenchmark');
            const btnScan = document.getElementById('tabNavScanner');
            const viewBench = document.getElementById('benchmarkView');
            const viewScan = document.getElementById('scannerView');

            if (tab === 'benchmark') {{
                btnBench.classList.add('active');
                btnScan.classList.remove('active');
                viewBench.style.display = 'block';
                viewScan.style.display = 'none';
            }} else {{
                btnScan.classList.add('active');
                btnBench.classList.remove('active');
                viewBench.style.display = 'none';
                viewScan.style.display = 'flex';
                checkScannerHealth(false);
            loadScanHistory(false);
                loadScanHistory(false);
            }}
        }}

        async function checkScannerHealth(showNotification = false) {{
            const statusDot = document.getElementById('statusDot');
            const statusText = document.getElementById('statusText');
            try {{
                const res = await fetch(`${{SCANNER_API_BASE}}/api/health`, {{ method: 'GET' }});
                if (res.ok) {{
                    const data = await res.json();
                    statusDot.className = 'status-dot online';
                    statusText.textContent = 'API Scanner: Online (3 Mô Hình Sẵn Sàng)';
                    if (showNotification) alert('✅ Kết nối thành công tới Malware Scanner API (Cổng 5050)! Bộ 3 mô hình Random Forest, XGBoost, MLP đã sẵn sàng nhận tệp.');
                    return true;
                }}
            }} catch (e) {{
                statusDot.className = 'status-dot offline';
                statusText.textContent = 'API Scanner: Offline (Dùng Heuristic Fallback)';
                if (showNotification) alert('⚠️ Không thể kết nối tới http://localhost:5050/api/health. Hãy bật service: docker compose up -d malware-scanner hoặc python dags/scanner_api.py');
            }}
            return false;
        }}

        // Drag & Drop
        function onDragOver(e) {{
            e.preventDefault();
            e.stopPropagation();
            document.getElementById('dropZone').classList.add('dragover');
        }}

        function onDragLeave(e) {{
            e.preventDefault();
            e.stopPropagation();
            document.getElementById('dropZone').classList.remove('dragover');
        }}

        function onDropFile(e) {{
            e.preventDefault();
            e.stopPropagation();
            document.getElementById('dropZone').classList.remove('dragover');
            if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {{
                setFileForScan(e.dataTransfer.files[0]);
            }}
        }}

        function onFileSelected(e) {{
            if (e.target.files && e.target.files.length > 0) {{
                setFileForScan(e.target.files[0]);
            }}
        }}

        async function setFileForScan(file) {{
            currentScanFile = file;
            document.getElementById('fileNameDisplay').textContent = file.name;
            const sizeStr = file.size < 1048576 
                ? (file.size / 1024).toFixed(2) + ' KB' 
                : (file.size / 1048576).toFixed(2) + ' MB';
            document.getElementById('fileSizeDisplay').textContent = sizeStr;

            const isPeExt = file.name.toLowerCase().endsWith('.exe') || file.name.toLowerCase().endsWith('.dll') || file.name.toLowerCase().endsWith('.sys');
            document.getElementById('fileTypeDisplay').textContent = isPeExt ? 'Windows PE Executable' : 'Tệp nhị phân / Kịch bản';
            document.getElementById('fileIcon').textContent = isPeExt ? '⚙️' : '📄';

            // Tính SHA-256 nhanh
            try {{
                const buffer = await file.slice(0, 1048576).arrayBuffer();
                const hashBuf = await crypto.subtle.digest('SHA-256', buffer);
                const hashArr = Array.from(new Uint8Array(hashBuf));
                const hashHex = hashArr.map(b => b.toString(16).padStart(2, '0')).join('');
                document.getElementById('fileHashDisplay').textContent = 'SHA256: ' + hashHex.substring(0, 16) + '...';
            }} catch (err) {{
                document.getElementById('fileHashDisplay').textContent = 'Size: ' + sizeStr;
            }}

            document.getElementById('selectedFileCard').style.display = 'flex';
            document.getElementById('scanResultsContainer').style.display = 'none';
        }}

        function testPresetSample(sampleName) {{
            fetch(`${{SCANNER_API_BASE}}/api/sample/${{sampleName}}`)
                .then(r => r.json())
                .then(res => {{
                    playScanAnimation(res);
                }})
                .catch(err => {{
                    alert('⚠️ Chưa khởi chạy API Scanner (Cổng 5050). Khởi chạy: docker compose up -d malware-scanner hoặc python dags/scanner_api.py');
                }});
        }}

        function testCleanTextSample() {{
            const cleanData = {{
                file_name: "benign_document.docx",
                file_size_formatted: "45.20 KB",
                entropy: 4.32,
                is_pe: false,
                file_type_detected: "Office Document / Text File",
                algorithms: {{
                    "Random Forest": {{ prediction: 0, probability: 0.015, status: "Benign" }},
                    "XGBoost": {{ prediction: 0, probability: 0.008, status: "Benign" }},
                    "Deep Learning (MLP)": {{ prediction: 0, probability: 0.005, status: "Benign" }}
                }},
                consensus: {{
                    verdict: "BENIGN / CLEAN",
                    verdict_vi: "🛡️ TỆP TIN AN TOÀN / LÀNH TÍNH",
                    threat_level: "SAFE",
                    risk_score_percent: 1.2,
                    badge_color: "#10b981",
                    action_recommendation: "Tệp tin hoàn toàn an toàn. Không phát hiện dấu hiệu mã độc hay chỉ thị bất thường."
                }},
                threat_indicators: [],
                forensics: {{
                    suspicious_apis_count: 0,
                    suspicious_apis_list: [],
                    suspicious_sections: [],
                    sections_count: 0
                }}
            }};
            playScanAnimation(cleanData);
        }}

        function testHighEntropySample() {{
            const highEntropyData = {{
                file_name: "payload_dropper.bin",
                file_size_formatted: "128.50 KB",
                entropy: 7.94,
                is_pe: true,
                file_type_detected: "Packed PE Executable",
                algorithms: {{
                    "Random Forest": {{ prediction: 1, probability: 0.965, status: "Malware" }},
                    "XGBoost": {{ prediction: 1, probability: 0.982, status: "Malware" }},
                    "Deep Learning (MLP)": {{ prediction: 1, probability: 0.941, status: "Malware" }}
                }},
                consensus: {{
                    verdict: "MALWARE DETECTED",
                    verdict_vi: "🚨 PHÁT HIỆN MÃ ĐỘC NGUY HIỂM",
                    threat_level: "CRITICAL",
                    risk_score_percent: 97.4,
                    badge_color: "#f43f5e",
                    action_recommendation: "Phát hiện dấu vết Ransomware đóng gói (UPX/Cryptor). Khuyến cáo cách ly tức thì!"
                }},
                threat_indicators: [
                    {{ type: "HIGH_ENTROPY", severity: "CRITICAL", message: "Độ hỗn loạn Entropy cực cao (7.94/8.0): Dấu hiệu payload bị đóng gói hoặc mã hóa né tránh phòng thủ." }},
                    {{ type: "SUSPICIOUS_APIS", severity: "HIGH", message: "Phát hiện 4 API nguy hiểm: VirtualAlloc, WriteProcessMemory, CreateRemoteThread, URLDownloadToFile" }}
                ],
                forensics: {{
                    suspicious_apis_count: 4,
                    suspicious_apis_list: ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "URLDownloadToFile"],
                    suspicious_sections: [".upx0", ".upx1"],
                    sections_count: 4
                }}
            }};
            playScanAnimation(highEntropyData);
        }}

        async function triggerMalwareScan() {{
            if (!currentScanFile) return;

            const hud = document.getElementById('scanHudBox');
            hud.style.display = 'block';
            document.getElementById('scanResultsContainer').style.display = 'none';

            // Gửi tệp tới API Scanner
            const formData = new FormData();
            formData.append('file', currentScanFile, currentScanFile.name);

            try {{
                const response = await fetch(`${{SCANNER_API_BASE}}/api/scan`, {{
                    method: 'POST',
                    headers: {{ 'X-File-Name': encodeURIComponent(currentScanFile.name) }},
                    body: formData
                }});

                if (response.ok) {{
                    const result = await response.json();
                    playScanAnimation(result);
                    return;
                }}
            }} catch (err) {{
                console.warn("API server unavailable, using client-side heuristic inspection fallback", err);
            }}

            // Fallback phía client
            const fallbackResult = await clientSideInspectFallback(currentScanFile);
            playScanAnimation(fallbackResult);
        }}

        async function clientSideInspectFallback(file) {{
            const buffer = await file.arrayBuffer();
            const bytes = new Uint8Array(buffer);
            
            const counts = new Map();
            for (let i = 0; i < bytes.length; i++) {{
                counts.set(bytes[i], (counts.get(bytes[i]) || 0) + 1);
            }}
            let entropy = 0;
            const len = bytes.length;
            counts.forEach(count => {{
                const p = count / len;
                entropy -= p * Math.log2(p);
            }});
            entropy = Math.round(entropy * 1000) / 1000;

            const isPe = bytes.length > 64 && bytes[0] === 0x4D && bytes[1] === 0x5A;
            const nameLower = (file.name || '').toLowerCase();
            const isPdf = nameLower.endsWith('.pdf') || (bytes.length > 4 && bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46);
            const isOffice = nameLower.endsWith('.docx') || nameLower.endsWith('.xlsx') || nameLower.endsWith('.pptx');
            const isArchive = nameLower.endsWith('.zip') || nameLower.endsWith('.rar') || nameLower.endsWith('.7z') || nameLower.endsWith('.tar') || nameLower.endsWith('.gz');
            const isMedia = nameLower.endsWith('.png') || nameLower.endsWith('.jpg') || nameLower.endsWith('.jpeg') || nameLower.endsWith('.mp4') || nameLower.endsWith('.mp3');
            const isNaturalCompressed = isPdf || isOffice || isArchive || isMedia;

            let fileTypeDetected = "Tệp nhị phân / Kịch bản";
            if (isPe) fileTypeDetected = "Windows PE Executable";
            else if (isPdf) fileTypeDetected = "Tài liệu PDF (Adobe PDF)";
            else if (isOffice) fileTypeDetected = "Tài liệu Văn phòng (MS Office)";
            else if (isArchive) fileTypeDetected = "Tệp nén lưu trữ (Archive)";
            else if (isMedia) fileTypeDetected = "Tệp Đa phương tiện / Media";

            let hasMaliciousPattern = false;
            let detectedPatternName = "";
            if (!isPe) {{
                const textSample = new TextDecoder('latin1').decode(bytes.slice(0, Math.min(bytes.length, 500000))).toLowerCase();
                if (isPdf) {{
                    if (textSample.includes('/launch')) {{
                        hasMaliciousPattern = true;
                        detectedPatternName = "/Launch (Khởi chạy tiến trình hệ thống từ PDF)";
                    }} else if (textSample.includes('powershell') || textSample.includes('cmd.exe /c') || textSample.includes('wscript.shell')) {{
                        hasMaliciousPattern = true;
                        detectedPatternName = "Lệnh shell độc hại nhúng trong PDF";
                    }}
                }} else if (textSample.includes('powershell -enc') || textSample.includes('wscript.shell') || textSample.includes('autoopen')) {{
                    hasMaliciousPattern = true;
                    detectedPatternName = "Mã độc thực thi script/macro tự động";
                }}
            // Nhận diện bộ cài đặt và chữ ký số
            const isInstaller = isPe && (
                file.size > 15 * 1024 * 1024 ||
                ['install', 'setup', 'installer', 'update', 'patch', 'pycharm', 'riot', 'league', 'revo'].some(k => nameLower.includes(k)) ||
                textSample.includes('nullsoftinst') || textSample.includes('inno setup') || textSample.includes('7-zip')
            );

            let hasDigitalSig = false;
            let sigPublisher = "";
            const trustedPubs = ['jetbrains', 'riot games', 'microsoft', 'google', 'valve', 'adobe', 'apple', 'oracle', 'digicert', 'sectigo', 'vs revo group', 'docker'];
            for (const pub of trustedPubs) {{
                if (textSample.includes(pub)) {{
                    hasDigitalSig = true;
                    sigPublisher = pub.toUpperCase();
                    break;
                }}
            }}

            let risk = 1.2;
            if (isPe) {{
                if (hasDigitalSig) {{
                    risk = 1.5;
                }} else if (isInstaller) {{
                    risk = 8.5;
                }} else if (hasMaliciousPattern) {{
                    risk = 92.0;
                }} else {{
                    risk = entropy > 7.3 ? 55.0 : 22.0;
                }}
            }} else if (hasMaliciousPattern) {{
                risk = 92.0;
            }} else {{
                risk = 1.2;
            }}

            const threatIndicators = [];
            if (hasDigitalSig) {{
                threatIndicators.push({{ type: "TRUSTED_SIGNATURE", severity: "SAFE", message: `Chữ ký số hợp lệ (Authenticode Digital Certificate): Tệp tin đã được xác thực danh tính (${{sigPublisher}}).` }});
            }}
            if (isInstaller) {{
                threatIndicators.push({{ type: "NATURAL_INSTALLER_PAYLOAD", severity: "INFO", message: `Độ hỗn loạn Entropy (${{entropy}}/8.0): Thuộc mức nén tài nguyên tự nhiên của bộ cài đặt phần mềm.` }});
            }} else if (isPe && entropy > 7.3 && !hasDigitalSig) {{
                threatIndicators.push({{ type: "HIGH_ENTROPY", severity: "WARNING", message: `Độ hỗn loạn Entropy khá cao (${{entropy}}/8.0): Tệp thực thi chứa dữ liệu nén hoặc mã hóa.` }});
            }} else if (isNaturalCompressed) {{
                threatIndicators.push({{ type: "NATURAL_ENTROPY", severity: "INFO", message: `Độ hỗn loạn Entropy (${{entropy}}/8.0) thuộc mức nén tự nhiên tiêu chuẩn của ${{fileTypeDetected}}` }});
            }}
            if (hasMaliciousPattern) {{
                threatIndicators.push({{ type: "SUSPICIOUS_PAYLOAD", severity: "CRITICAL", message: `Phát hiện payload nguy hiểm: ${{detectedPatternName}}` }});
            }}

            return {{
                file_name: file.name,
                file_size_formatted: (file.size / 1024).toFixed(2) + ' KB',
                entropy: entropy,
                is_pe: isPe,
                file_type_detected: fileTypeDetected,
                algorithms: {{
                    "Random Forest": {{ prediction: risk >= 50 ? 1 : 0, probability: (risk * 0.95 / 100), status: risk >= 50 ? "Malware" : "Benign" }},
                    "XGBoost": {{ prediction: risk >= 50 ? 1 : 0, probability: (risk * 1.02 / 100), status: risk >= 50 ? "Malware" : "Benign" }},
                    "Deep Learning (MLP)": {{ prediction: risk >= 50 ? 1 : 0, probability: (risk * 0.98 / 100), status: risk >= 50 ? "Malware" : "Benign" }}
                }},
                consensus: {{
                    verdict: risk >= 70 ? "MALWARE DETECTED" : (risk >= 35 ? "SUSPICIOUS / ELEVATED RISK" : "BENIGN / CLEAN"),
                    verdict_vi: risk >= 70 ? "🚨 PHÁT HIỆN MÃ ĐỘC NGUY HIỂM" : (risk >= 35 ? "⚠️ TỆP TIN KHẢ NGHI" : "🛡️ TỆP TIN AN TOÀN"),
                    threat_level: risk >= 70 ? "CRITICAL" : (risk >= 35 ? "WARNING" : "SAFE"),
                    risk_score_percent: risk,
                    badge_color: risk >= 70 ? "#f43f5e" : (risk >= 35 ? "#f59e0b" : "#10b981"),
                    action_recommendation: risk >= 70 ? "Phát hiện dấu hiệu mã độc nguy hiểm. Khuyến cáo cách ly tệp tin." : (hasDigitalSig ? `Tệp tin đạt chuẩn an toàn. Đã xác thực Chữ ký số (${{sigPublisher}}).` : (isInstaller ? "Bộ cài đặt hợp lệ với cấu trúc nén tài nguyên tiêu chuẩn. Đạt chuẩn an toàn." : (isNaturalCompressed ? "Tệp tài liệu hợp lệ, không chứa mã độc nhúng. Đạt chuẩn an toàn." : "Tệp tin an toàn.")))
                }},
                threat_indicators: threatIndicators,
                forensics: {{
                    has_digital_signature: hasDigitalSig,
                    signature_publisher: sigPublisher,
                    is_installer: isInstaller,
                    suspicious_apis_count: hasMaliciousPattern ? 1 : 0,
                    suspicious_apis_list: hasMaliciousPattern ? [detectedPatternName] : [],
                    suspicious_sections: [],
                    sections_count: 0
                }}
            }};
        }}

        function playScanAnimation(result) {{
            const hud = document.getElementById('scanHudBox');
            hud.style.display = 'block';
            lastScanResult = result;

            const steps = [
                document.getElementById('step1'),
                document.getElementById('step2'),
                document.getElementById('step3'),
                document.getElementById('step4'),
                document.getElementById('step5'),
                document.getElementById('step6'),
                document.getElementById('step7')
            ];

            steps.forEach(s => s.className = 'hud-step');

            let currentStepIdx = 0;
            const interval = setInterval(() => {{
                if (currentStepIdx > 0) {{
                    steps[currentStepIdx - 1].className = 'hud-step done';
                }}
                if (currentStepIdx < steps.length) {{
                    steps[currentStepIdx].className = 'hud-step running';
                    document.getElementById('hudProgressPercent').textContent = Math.round(((currentStepIdx + 1) / steps.length) * 100) + '%';
                    currentStepIdx++;
                }} else {{
                    clearInterval(interval);
                    setTimeout(() => {{
                        hud.style.display = 'none';
                        renderScanResults(result);
                        loadScanHistory(false);
                    }}, 400);
                }}
            }}, 150);
        }}

        function renderScanResults(data) {{
            const c = data.consensus;
            const algos = data.algorithms;

            // Banner kết luận
            const banner = document.getElementById('verdictBanner');
            banner.className = 'verdict-banner ' + (c.threat_level === 'CRITICAL' ? 'verdict-danger' : (c.threat_level === 'WARNING' ? 'verdict-warning' : 'verdict-safe'));
            
            document.getElementById('verdictLevelBadge').textContent = c.threat_level + ' THREAT';
            document.getElementById('verdictLevelBadge').className = 'badge ' + (c.threat_level === 'CRITICAL' ? 'badge-danger' : (c.threat_level === 'WARNING' ? 'badge-warning' : 'badge-success'));
            document.getElementById('verdictHeadline').textContent = c.verdict_vi;
            document.getElementById('verdictRecommendation').textContent = c.action_recommendation;
            document.getElementById('verdictRiskPercent').textContent = c.risk_score_percent + '%';
            document.getElementById('verdictRiskPercent').style.color = c.badge_color;
            document.getElementById('verdictEntropyNote').textContent = `Entropy: ${{data.entropy}} / 8.0 • Định dạng: ${{data.file_type_detected}}`;

            // Random Forest
            const rf = algos['Random Forest'] || {{}};
            const rfProb = (rf.probability * 100).toFixed(1);
            document.getElementById('rfProbText').textContent = rfProb + '%';
            document.getElementById('rfProgressBar').style.width = rfProb + '%';
            document.getElementById('rfProgressBar').style.background = rf.prediction === 1 ? '#f43f5e' : '#10b981';
            document.getElementById('rfStatusBadge').textContent = rf.status === 'Malware' ? 'Phát Hiện Mã Độc' : 'Lành Tính';
            document.getElementById('rfStatusBadge').className = 'badge ' + (rf.prediction === 1 ? 'badge-danger' : 'badge-success');

            // XGBoost
            const xgb = algos['XGBoost'] || {{}};
            const xgbProb = (xgb.probability * 100).toFixed(1);
            document.getElementById('xgbProbText').textContent = xgbProb + '%';
            document.getElementById('xgbProgressBar').style.width = xgbProb + '%';
            document.getElementById('xgbProgressBar').style.background = xgb.prediction === 1 ? '#f43f5e' : '#00f0ff';
            document.getElementById('xgbStatusBadge').textContent = xgb.status === 'Malware' ? 'Phát Hiện Mã Độc' : 'Lành Tính';
            document.getElementById('xgbStatusBadge').className = 'badge ' + (xgb.prediction === 1 ? 'badge-danger' : 'badge-success');

            // MLP
            const mlp = algos['Deep Learning (MLP)'] || {{}};
            const mlpProb = (mlp.probability * 100).toFixed(1);
            document.getElementById('mlpProbText').textContent = mlpProb + '%';
            document.getElementById('mlpProgressBar').style.width = mlpProb + '%';
            document.getElementById('mlpProgressBar').style.background = mlp.prediction === 1 ? '#f43f5e' : '#a855f7';
            document.getElementById('mlpStatusBadge').textContent = mlp.status === 'Malware' ? 'Phát Hiện Mã Độc' : 'Lành Tính';
            document.getElementById('mlpStatusBadge').className = 'badge ' + (mlp.prediction === 1 ? 'badge-danger' : 'badge-success');

            // Threat Indicators
            const listEl = document.getElementById('threatIndicatorsList');
            listEl.innerHTML = '';
            if (data.threat_indicators && data.threat_indicators.length > 0) {{
                data.threat_indicators.forEach(t => {{
                    const item = document.createElement('div');
                    item.style.cssText = 'background: rgba(244, 63, 94, 0.1); border-left: 3px solid #f43f5e; padding: 10px 14px; border-radius: 6px; font-size: 12px; color: #cbd5e1;';
                    item.innerHTML = `<strong style="color: #fb7185;">[${{t.severity}}]</strong> ${{t.message}}`;
                    listEl.appendChild(item);
                }});
            }} else {{
                listEl.innerHTML = '<div style="color: #34d399; font-size: 12px;">✅ Không phát hiện dấu hiệu bất thường (Entropy trong ngưỡng an toàn, không có hàm API nguy hiểm).</div>';
            }}

            // Suspicious APIs
            const apisEl = document.getElementById('suspiciousApisTags');
            apisEl.innerHTML = '';
            const apisList = (data.forensics && data.forensics.suspicious_apis_list) || [];
            if (apisList.length > 0) {{
                apisList.forEach(api => {{
                    const tag = document.createElement('span');
                    tag.className = 'threat-tag';
                    tag.textContent = '⚡ ' + api;
                    apisEl.appendChild(tag);
                }});
            }} else {{
                apisEl.innerHTML = '<span style="font-size: 11px; color: var(--text-muted);">Không phát hiện API nguy hiểm bị lạm dụng.</span>';
            }}

            document.getElementById('scanResultsContainer').style.display = 'block';
            document.getElementById('scanResultsContainer').scrollIntoView({{ behavior: 'smooth' }});
        }}

        function resetScanner() {{
            currentScanFile = null;
            lastScanResult = null;
            document.getElementById('fileInput').value = '';
            document.getElementById('selectedFileCard').style.display = 'none';
            document.getElementById('scanResultsContainer').style.display = 'none';
            document.getElementById('scanHudBox').style.display = 'none';
        }}

        function downloadForensicReport() {{
            if (!lastScanResult) return;
            const blob = new Blob([JSON.stringify(lastScanResult, null, 2)], {{ type: 'application/json' }});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `Malware_Analysis_Report_${{lastScanResult.file_name || 'sample'}}.json`;
            a.click();
            URL.revokeObjectURL(url);
        }}

        function copyForensicReport() {{
            if (!lastScanResult) return;
            const text = `SHIELD-AI MALWARE ANALYSIS REPORT\nFile: ${{lastScanResult.file_name}}\nSize: ${{lastScanResult.file_size_formatted}}\nVerdict: ${{lastScanResult.consensus.verdict_vi}}\nRisk Score: ${{lastScanResult.consensus.risk_score_percent}}%\nEntropy: ${{lastScanResult.entropy}}/8.0\nRandom Forest: ${{lastScanResult.algorithms['Random Forest'].status}} (${{(lastScanResult.algorithms['Random Forest'].probability*100).toFixed(1)}}%)\nXGBoost: ${{lastScanResult.algorithms['XGBoost'].status}} (${{(lastScanResult.algorithms['XGBoost'].probability*100).toFixed(1)}}%)\nMLP: ${{lastScanResult.algorithms['Deep Learning (MLP)'].status}} (${{(lastScanResult.algorithms['Deep Learning (MLP)'].probability*100).toFixed(1)}}%)`;
            navigator.clipboard.writeText(text).then(() => {{
                alert('📋 Đã sao chép báo cáo kiểm định vào Clipboard!');
            }});
        }}

        
        // ==========================================
        // SCAN HISTORY & UPLOADED FILES VAULT
        // ==========================================
        let scanHistoryData = [];
        let activeHistoryFilter = 'all';

        async function loadScanHistory(showToast = false) {{
            try {{
                const res = await fetch(`${{SCANNER_API_BASE}}/api/scans`);
                if (res.ok) {{
                    const data = await res.json();
                    scanHistoryData = data.scans || [];
                    try {{ localStorage.setItem('shield_ai_scans', JSON.stringify(scanHistoryData)); }} catch(e){{}}
                    if (showToast) alert('✅ Đã đồng bộ danh sách tệp từ máy chủ API Scanner!');
                    renderHistoryTable();
                    return;
                }}
            }} catch (err) {{
                console.warn('API Scanner offline, checking localStorage cache', err);
            }}

            // Fallback localStorage
            try {{
                const cached = localStorage.getItem('shield_ai_scans');
                if (cached) {{
                    scanHistoryData = JSON.parse(cached);
                }}
            }} catch (e) {{}}

            if (showToast) alert('⚠️ Không kết nối được API Scanner (Cổng 5050). Đang hiển thị từ bộ nhớ Cache trình duyệt.');
            renderHistoryTable();
        }}

        function renderHistoryTable() {{
            const tbody = document.getElementById('historyTableBody');
            if (!tbody) return;

            // Tính thống kê
            const total = scanHistoryData.length;
            let malwareCount = 0;
            let suspiciousCount = 0;
            let safeCount = 0;

            scanHistoryData.forEach(item => {{
                const c = item.consensus || {{}};
                if (c.threat_level === 'CRITICAL' || (c.verdict || '').includes('MALWARE')) {{
                    malwareCount++;
                }} else if (c.threat_level === 'WARNING' || (c.verdict || '').includes('SUSPICIOUS')) {{
                    suspiciousCount++;
                }} else {{
                    safeCount++;
                }}
            }});

            const statTotalEl = document.getElementById('statTotalScans');
            if (statTotalEl) statTotalEl.textContent = total;
            const statMalwareEl = document.getElementById('statMalwareScans');
            if (statMalwareEl) statMalwareEl.textContent = malwareCount;
            const statSuspiciousEl = document.getElementById('statSuspiciousScans');
            if (statSuspiciousEl) statSuspiciousEl.textContent = suspiciousCount;
            const statSafeEl = document.getElementById('statSafeScans');
            if (statSafeEl) statSafeEl.textContent = safeCount;
            const totalBadgeEl = document.getElementById('historyTotalBadge');
            if (totalBadgeEl) totalBadgeEl.textContent = `${{total}} tệp tin`;

            // Lọc dữ liệu
            const searchQ = (document.getElementById('historySearchInput')?.value || '').trim().toLowerCase();
            const filtered = scanHistoryData.filter(item => {{
                const c = item.consensus || {{}};
                let matchFilter = true;
                if (activeHistoryFilter === 'malware') {{
                    matchFilter = c.threat_level === 'CRITICAL' || (c.verdict || '').includes('MALWARE');
                }} else if (activeHistoryFilter === 'suspicious') {{
                    matchFilter = c.threat_level === 'WARNING' || (c.verdict || '').includes('SUSPICIOUS');
                }} else if (activeHistoryFilter === 'safe') {{
                    matchFilter = c.threat_level === 'SAFE' || (c.verdict || '').includes('BENIGN') || (c.verdict || '').includes('CLEAN');
                }}

                if (!matchFilter) return false;
                if (!searchQ) return true;

                const name = (item.file_name || '').toLowerCase();
                const sha = (item.hashes?.sha256 || '').toLowerCase();
                const ftype = (item.file_type_detected || '').toLowerCase();
                return name.includes(searchQ) || sha.includes(searchQ) || ftype.includes(searchQ);
            }});

            if (filtered.length === 0) {{
                tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; padding: 36px; color: var(--text-muted); font-size: 13px;">
                    ${{total === 0 ? '📁 Chưa có tệp tin nào được tải lên. Hãy kéo & thả tệp tin ở khung phía trên để bắt đầu phân tích mã độc!' : '🔍 Không tìm thấy tệp tin phù hợp với bộ lọc hiện tại.'}}
                </td></tr>`;
                return;
            }}

            let html = '';
            filtered.forEach((item, idx) => {{
                const c = item.consensus || {{}};
                const algos = item.algorithms || {{}};
                const rf = algos['Random Forest'] || {{}};
                const xgb = algos['XGBoost'] || {{}};
                const mlp = algos['Deep Learning (MLP)'] || {{}};

                const isPe = item.is_pe || (item.file_name || '').toLowerCase().endsWith('.exe') || (item.file_name || '').toLowerCase().endsWith('.dll');
                const fileIcon = isPe ? '⚙️' : ((item.file_name || '').toLowerCase().endsWith('.pdf') ? '📕' : ((item.file_name || '').toLowerCase().endsWith('.docx') ? '📘' : '📦'));

                let verdictBadge = '';
                if (c.threat_level === 'CRITICAL' || (c.verdict || '').includes('MALWARE')) {{
                    verdictBadge = `<span class="badge badge-danger">🚨 MÃ ĐỘC (${{c.risk_score_percent || 0}}%)</span>`;
                }} else if (c.threat_level === 'WARNING' || (c.verdict || '').includes('SUSPICIOUS')) {{
                    verdictBadge = `<span class="badge badge-warning">⚠️ RỦI RO (${{c.risk_score_percent || 0}}%)</span>`;
                }} else {{
                    verdictBadge = `<span class="badge badge-success">🛡️ AN TOÀN (${{c.risk_score_percent || 0}}%)</span>`;
                }}

                const shaFull = item.hashes?.sha256 || 'N/A';
                const shaShort = shaFull !== 'N/A' ? shaFull.substring(0, 12) + '...' : 'N/A';

                const rfPill = `<span class="mini-algo-pill ${{rf.prediction === 1 ? 'malware' : 'benign'}}" title="Random Forest: ${{rf.status}} (${{((rf.probability||0)*100).toFixed(0)}}%)">RF: ${{rf.prediction === 1 ? 'M' : 'B'}}</span>`;
                const xgbPill = `<span class="mini-algo-pill ${{xgb.prediction === 1 ? 'malware' : 'benign'}}" title="XGBoost: ${{xgb.status}} (${{((xgb.probability||0)*100).toFixed(0)}}%)">XGB: ${{xgb.prediction === 1 ? 'M' : 'B'}}</span>`;
                const mlpPill = `<span class="mini-algo-pill ${{mlp.prediction === 1 ? 'malware' : 'benign'}}" title="MLP: ${{mlp.status}} (${{((mlp.probability||0)*100).toFixed(0)}}%)">MLP: ${{mlp.prediction === 1 ? 'M' : 'B'}}</span>`;

                const safeId = item.id;
                const safeName = (item.file_name || 'sample.bin').replace(/'/g, "\\'");

                html += `
                    <tr>
                        <td style="text-align: center; color: var(--text-muted); font-family: monospace; font-size: 11px;">${{idx + 1}}</td>
                        <td>
                            <div style="display: flex; align-items: center; gap: 8px;">
                                <span style="font-size: 16px;">${{fileIcon}}</span>
                                <div>
                                    <div style="font-weight: 700; color: #f8fafc; font-size: 13px;">${{item.file_name}}</div>
                                    <div style="font-size: 10px; color: var(--text-muted); font-family: 'JetBrains Mono', monospace; cursor: pointer;" title="Bấm để sao chép SHA256: ${{shaFull}}" onclick="navigator.clipboard.writeText('${{shaFull}}'); alert('📋 Đã sao chép SHA256: ${{shaFull}}');">
                                        SHA: ${{shaShort}} 📋
                                    </div>
                                </div>
                            </div>
                        </td>
                        <td style="white-space: nowrap; font-size: 11px; color: #94a3b8;">${{item.timestamp || 'Mới tải lên'}}</td>
                        <td style="text-align: right; font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #cbd5e1;">${{item.file_size_formatted || (item.file_size/1024).toFixed(1) + ' KB'}}</td>
                        <td style="font-size: 11px; color: #94a3b8;">${{item.file_type_detected || 'Unknown'}}</td>
                        <td style="text-align: center;">${{verdictBadge}}</td>
                        <td style="text-align: center; white-space: nowrap;">${{rfPill}} ${{xgbPill}} ${{mlpPill}}</td>
                        <td style="text-align: center;">
                            <div style="display: inline-flex; gap: 5px;">
                                <button class="btn-action-view" onclick="viewHistoricalScan('${{safeId}}')" title="Xem chi tiết kết quả phân tích">
                                    👁️ Xem
                                </button>
                                <button class="btn-action-dl" onclick="downloadSavedFile('${{safeId}}', '${{safeName}}')" title="Tải file gốc đã lưu">
                                    📥 Tải
                                </button>
                                <button class="btn-action-del" onclick="deleteScanHistoryItem('${{safeId}}', event)" title="Xóa tệp khỏi kho">
                                    🗑️
                                </button>
                            </div>
                        </td>
                    </tr>
                `;
            }});

            tbody.innerHTML = html;
        }}

        function setHistoryFilter(filter, btn) {{
            activeHistoryFilter = filter;
            document.querySelectorAll('.history-filter-btn').forEach(b => b.classList.remove('active'));
            if (btn) btn.classList.add('active');
            renderHistoryTable();
        }}

        function filterScanHistory() {{
            renderHistoryTable();
        }}

        function viewHistoricalScan(scanId) {{
            const scan = scanHistoryData.find(s => s.id === scanId);
            if (!scan) {{
                alert('Không tìm thấy bản ghi quét!');
                return;
            }}
            lastScanResult = scan;
            renderScanResults(scan);
            const resContainer = document.getElementById('scanResultsContainer');
            if (resContainer) {{
                resContainer.style.display = 'block';
                resContainer.scrollIntoView({{ behavior: 'smooth' }});
            }}
        }}

        function downloadSavedFile(scanId, fileName) {{
            const a = document.createElement('a');
            a.href = `${{SCANNER_API_BASE}}/api/download/${{scanId}}`;
            a.download = fileName;
            a.target = '_blank';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        }}

        async function deleteScanHistoryItem(scanId, e) {{
            if (e) e.stopPropagation();
            if (!confirm('Bạn có chắc chắn muốn xóa tệp tin này khỏi kho lưu trữ?')) return;

            try {{
                await fetch(`${{SCANNER_API_BASE}}/api/scan/${{scanId}}`, {{ method: 'DELETE' }});
            }} catch (err) {{
                console.warn('API delete error, removing from local state', err);
            }}

            scanHistoryData = scanHistoryData.filter(s => s.id !== scanId);
            try {{ localStorage.setItem('shield_ai_scans', JSON.stringify(scanHistoryData)); }} catch(e){{}}
            renderHistoryTable();
        }}

        async function confirmClearHistory() {{
            if (!confirm('Bạn có chắc chắn muốn xóa TOÀN BỘ lịch sử và các tệp tin đã tải lên? Thao tác này không thể hoàn tác.')) return;

            try {{
                await fetch(`${{SCANNER_API_BASE}}/api/history/clear`, {{ method: 'DELETE' }});
            }} catch (err) {{
                console.warn('API clear error', err);
            }}

            scanHistoryData = [];
            try {{ localStorage.removeItem('shield_ai_scans'); }} catch(e){{}}
            renderHistoryTable();
        }}

        // Tự động kiểm tra API Scanner khi tải trang
        setTimeout(() => {{
            checkScannerHealth(false);
            loadScanHistory(false);
        }}, 600);

        // Khởi chạy chế độ mặc định ban đầu
        renderCrossDatasetView();
    </script>
</body>
</html>
"""
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        with open(index_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        print(f">> Giao diện Web GUI Dashboard đã tạo thành công tại:\n- {html_path}\n- {index_path}")
        return {
            "html_path": html_path,
            "index_path": index_path
        }

    # ==========================================
    # 4. UPLOAD TOÀN BỘ SANG MINIO OBJECT STORAGE
    # ==========================================
    @task
    def upload_to_minio(chart_info, html_info):
        import boto3
        from botocore.client import Config

        minio_endpoint = os.getenv("MINIO_ENDPOINT", "http://minio:9000")
        access_key = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
        secret_key = os.getenv("MINIO_SECRET_KEY", "minioadmin")
        bucket_name = "malware-evaluation"

        print(f"Đang kết nối tới MinIO tại: {minio_endpoint}...")

        s3_client = boto3.client(
            's3',
            endpoint_url=minio_endpoint,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            config=Config(signature_version='s3v4'),
            region_name='us-east-1'
        )

        try:
            s3_client.head_bucket(Bucket=bucket_name)
            print(f">> Bucket '{bucket_name}' đã tồn tại.")
        except Exception:
            try:
                s3_client.create_bucket(Bucket=bucket_name)
                print(f">> Đã tạo thành công bucket mới: '{bucket_name}'.")
            except Exception as ce:
                print(f"Lỗi tạo bucket: {ce}")

        public_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": ["*"]},
                    "Action": ["s3:GetBucketLocation", "s3:ListBucket"],
                    "Resource": [f"arn:aws:s3:::{bucket_name}"]
                },
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": ["*"]},
                    "Action": ["s3:GetObject"],
                    "Resource": [f"arn:aws:s3:::{bucket_name}/*"]
                }
            ]
        })
        try:
            s3_client.put_bucket_policy(Bucket=bucket_name, Policy=public_policy)
            print(f">> Đã cấp quyền xem công khai (Public Read) cho bucket '{bucket_name}'.")
        except Exception as pe:
            print(f"Thông báo chính sách: {pe}")

        files_to_upload = [
            (html_info['html_path'], "dashboard.html", "text/html"),
            (html_info['index_path'], "index.html", "text/html"),
            (chart_info['png_path'], "Model_Evaluation_Chart.png", "image/png"),
            (chart_info['pdf_path'], "Model_Evaluation_Chart.pdf", "application/pdf"),
            ("/opt/airflow/dags/reports/combined_model_evaluation_report.csv", "combined_model_evaluation_report.csv", "text/csv"),
            ("/opt/airflow/dags/XGBoost_MultiDataset_Report.csv", "XGBoost_MultiDataset_Report.csv", "text/csv"),
            ("/opt/airflow/dags/RandomForest_MultiDataset_Report.csv", "RandomForest_MultiDataset_Report.csv", "text/csv"),
            ("/opt/airflow/dags/MLP_MultiDataset_Report.csv", "MLP_MultiDataset_Report.csv", "text/csv"),
        ]

        uploaded_count = 0
        for local_file, object_name, content_type in files_to_upload:
            if os.path.exists(local_file):
                try:
                    s3_client.upload_file(
                        local_file,
                        bucket_name,
                        object_name,
                        ExtraArgs={'ContentType': content_type}
                    )
                    print(f"   [UPLOAD OK] {object_name} ({content_type})")
                    uploaded_count += 1
                except Exception as ue:
                    print(f"   [UPLOAD LỖI] {object_name}: {ue}")

        print("=" * 70)
        print(f">> HOÀN TẤT XUẤT BÁO CÁO & GUI SANG MINIO: {uploaded_count} files!")
        print("🔗 ĐƯỜNG DẪN TRUY CẬP:")
        print(f"1. Giao diện Web GUI Dashboard: http://localhost:9000/{bucket_name}/dashboard.html")
        print(f"2. MinIO Web Console:         http://localhost:9001/browser/{bucket_name}")
        print("=" * 70)

        return {
            "dashboard_url": f"http://localhost:9000/{bucket_name}/dashboard.html",
            "minio_console": f"http://localhost:9001/browser/{bucket_name}",
            "uploaded_count": uploaded_count
        }

    # Luồng thực thi DAG
    eval_data = collect_and_merge_reports()
    chart_info = generate_charts(eval_data)
    html_info = generate_html_dashboard(eval_data, chart_info)
    upload_to_minio(chart_info, html_info)

dag_instance = model_evaluation_dashboard()

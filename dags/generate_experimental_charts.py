import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
import os

# Set style
sns.set_theme(style="whitegrid")
plt.rcParams['font.sans-serif'] = 'DejaVu Sans'
plt.rcParams['axes.edgecolor'] = '#cbd5e1'
plt.rcParams['axes.linewidth'] = 1.0

# Read CSV
csv_path = '/opt/airflow/dags/reports/combined_model_evaluation_report.csv'
df = pd.read_csv(csv_path)

# Filter key representative datasets across 5 security domains for readability in chart
rep_datasets = [
    'dataset_malwares.csv',
    'PE_Header_MalwareData.csv',
    'ClaMP_Integrated_PE_Malware.csv',
    'Android_Malware_Syscalls.csv',
    'drebin-215-dataset-5560malware-9476-benign.csv',
    'Mobile_Smishing_Threats.csv',
    'NSL_KDD_Network_Intrusion.csv',
    'CIC_MalMem2022_Obfuscated.csv',
    'Phishing_Websites_Detection.csv',
    'SQL_Injection_Payloads.csv',
    'XSS_Attack_Vectors.csv',
    'Ransomware_Multiclass_Dataset.csv'
]
df_rep = df[df['Dataset'].isin(rep_datasets)].copy()

# Shorten dataset names for display
name_map = {
    'dataset_malwares.csv': 'dataset_malwares (PE)',
    'PE_Header_MalwareData.csv': 'PE_Header_Data (PE)',
    'ClaMP_Integrated_PE_Malware.csv': 'ClaMP_Integrated (PE)',
    'Android_Malware_Syscalls.csv': 'Android_Syscalls (Hành vi)',
    'drebin-215-dataset-5560malware-9476-benign.csv': 'Drebin-215 (Android)',
    'Mobile_Smishing_Threats.csv': 'Mobile_Smishing (SMS/Text)',
    'NSL_KDD_Network_Intrusion.csv': 'NSL_KDD (Network)',
    'CIC_MalMem2022_Obfuscated.csv': 'CIC_MalMem (Memory)',
    'Phishing_Websites_Detection.csv': 'Phishing_Web (URL)',
    'SQL_Injection_Payloads.csv': 'SQL_Injection (Payload)',
    'XSS_Attack_Vectors.csv': 'XSS_Vectors (Payload)',
    'Ransomware_Multiclass_Dataset.csv': 'Ransomware (Multiclass)'
}
df_rep['Dataset_Short'] = df_rep['Dataset'].map(name_map)

# Palette
palette = {
    'XGBoost': '#0284c7',       # Deep Cyan / Blue
    'Random Forest': '#059669', # Emerald Green
    'MLP': '#7c3aed'            # Purple / Violet
}

# ==============================================================
# HÌNH 1: SO SÁNH ĐA CHỈ SỐ 4 PANEL (Accuracy, F1, ROC-AUC, FPR)
# ==============================================================
fig, axes = plt.subplots(4, 1, figsize=(14, 20))
fig.suptitle('SO SÁNH THỰC NGHIỆM BA THUẬT TOÁN HỌC MÁY TRÊN ĐA TẬP DỮ LIỆU AN NINH MẠNG\nXGBoost (Gradient Boosting) vs Random Forest (Bagging) vs MLP (Deep Learning)',
             fontsize=15, fontweight='bold', color='#0f172a', y=0.995)

metrics = [
    ('Accuracy', 'So sánh Accuracy (Độ chính xác toàn diện)', axes[0], 1.12),
    ('F1_Score', 'So sánh F1-Score (Điểm điều hòa cân bằng giữa Precision và Recall)', axes[1], 1.12),
    ('ROC_AUC', 'So sánh ROC-AUC (Năng lực phân tách giữa mã độc và lành tính)', axes[2], 1.12),
    ('FPR', 'So sánh FPR - False Positive Rate (Tỷ lệ báo động giả - Càng thấp càng an toàn cho SOC)', axes[3], 0.08)
]

for col, title, ax, y_max in metrics:
    sns.barplot(data=df_rep, x='Dataset_Short', y=col, hue='Thuật_Toán', ax=ax, palette=palette, edgecolor='#334155', linewidth=0.6)
    ax.set_title(title, fontsize=12, fontweight='bold', color='#1e293b', pad=8)
    ax.set_ylim(0, y_max)
    ax.set_ylabel(col, fontsize=11, fontweight='semibold', color='#334155')
    ax.set_xlabel('')
    ax.tick_params(colors='#1e293b', labelsize=9.5, rotation=25)
    ax.grid(True, linestyle='--', alpha=0.6, axis='y')
    
    # Value annotations on bars
    for container in ax.containers:
        ax.bar_label(container, fmt='%.3f' if col != 'FPR' else '%.4f', padding=2, fontsize=7.5, color='#0f172a', rotation=90)
        
    ax.legend(title='Thuật Toán', bbox_to_anchor=(1.01, 1), loc='upper left', frameon=True, facecolor='#f8fafc', edgecolor='#cbd5e1')

plt.tight_layout(rect=[0, 0, 0.88, 0.985])
out_chart1 = '/opt/airflow/dags/reports/hinh_3_17_so_sanh_3_thuat_toan_malware.png'
plt.savefig(out_chart1, dpi=300, bbox_inches='tight')
plt.close()
print("Saved:", out_chart1)

# ==============================================================
# HÌNH 2: BIỂU ĐỒ TỔNG THỂ VÀ PHÂN BỐ HIỆU NĂNG 5 LĨNH VỰC
# ==============================================================
# Define domains
domain_mapping = {
    'PE Executables': ['dataset_malwares.csv', 'PE_Header_MalwareData.csv', 'ClaMP_Integrated_PE_Malware.csv', 'ClaMP_Raw_PE_Malware.csv', 'Ransomware_PE_Headers.csv'],
    'Android & Mobile': ['Android_Malware_Syscalls.csv', 'drebin-215-dataset-5560malware-9476-benign.csv', 'Mobile_Smishing_Threats.csv'],
    'Network & DoS': ['NSL_KDD_Network_Intrusion.csv', 'APA_DDoS_Traffic.csv', 'CIC_MalMem2022_Obfuscated.csv', 'C2_Malicious_Domains.csv'],
    'Web & Injection': ['Phishing_Legitimate_URLs.csv', 'Phishing_Websites_Detection.csv', 'SQL_Injection_Payloads.csv', 'XSS_Attack_Vectors.csv'],
    'Ransomware & Adv': ['Ransomware_Multiclass_Dataset.csv', 'final(2).csv']
}

domain_records = []
for dom, dsets in domain_mapping.items():
    sub_df = df[df['Dataset'].isin(dsets)]
    for algo in ['XGBoost', 'Random Forest', 'MLP']:
        a_df = sub_df[sub_df['Thuật_Toán'] == algo]
        if not a_df.empty:
            domain_records.append({
                'Lĩnh_Vực': dom,
                'Thuật_Toán': algo,
                'Accuracy': a_df['Accuracy'].mean(),
                'F1_Score': a_df['F1_Score'].mean(),
                'FPR': a_df['FPR'].mean(),
                'ROC_AUC': a_df['ROC_AUC'].mean()
            })
domain_df = pd.DataFrame(domain_records)

fig2, (ax_dom1, ax_dom2) = plt.subplots(1, 2, figsize=(15, 6))

# Panel 1: F1-Score by Domain
sns.barplot(data=domain_df, x='Lĩnh_Vực', y='F1_Score', hue='Thuật_Toán', ax=ax_dom1, palette=palette, edgecolor='#334155')
ax_dom1.set_title('Điểm F1-Score Trung Bình Theo 5 Nhóm Lĩnh Vực An Ninh Mạng', fontsize=12, fontweight='bold', color='#0f172a', pad=10)
ax_dom1.set_ylim(0.80, 1.02)
ax_dom1.set_ylabel('F1-Score', fontsize=11, fontweight='semibold')
ax_dom1.set_xlabel('Lĩnh Vực An Ninh Mạng', fontsize=11, fontweight='semibold')
ax_dom1.tick_params(labelsize=10, rotation=15)
ax_dom1.grid(True, linestyle='--', alpha=0.6, axis='y')
for container in ax_dom1.containers:
    ax_dom1.bar_label(container, fmt='%.3f', padding=3, fontsize=8.5, color='#0f172a', fontweight='semibold')
ax_dom1.legend(title='Thuật Toán', loc='lower right')

# Panel 2: FPR by Domain (Lower is better!)
sns.barplot(data=domain_df, x='Lĩnh_Vực', y='FPR', hue='Thuật_Toán', ax=ax_dom2, palette=palette, edgecolor='#334155')
ax_dom2.set_title('Tỷ Lệ Báo Động Giả (FPR) Theo Lĩnh Vực (Càng Thấp Càng Tốt)', fontsize=12, fontweight='bold', color='#0f172a', pad=10)
ax_dom2.set_ylim(0, 0.045)
ax_dom2.set_ylabel('False Positive Rate (FPR)', fontsize=11, fontweight='semibold')
ax_dom2.set_xlabel('Lĩnh Vực An Ninh Mạng', fontsize=11, fontweight='semibold')
ax_dom2.tick_params(labelsize=10, rotation=15)
ax_dom2.grid(True, linestyle='--', alpha=0.6, axis='y')
for container in ax_dom2.containers:
    ax_dom2.bar_label(container, fmt='%.4f', padding=3, fontsize=8.5, color='#0f172a', fontweight='semibold')
ax_dom2.legend(title='Thuật Toán', loc='upper right')

plt.tight_layout()
out_chart2 = '/opt/airflow/dags/reports/hinh_3_17b_radar_so_sanh_mien_an_ninh.png'
plt.savefig(out_chart2, dpi=300, bbox_inches='tight')
plt.close()
print("Saved:", out_chart2)

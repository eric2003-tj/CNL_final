import os
import pandas as pd

# 設定資料夾根目錄（此資料夾下有多個子資料夾）
root_folder = "./new_dataset/new_cleaned_csv_simplelog_freq/"  # ← 請修改為你的實際資料夾路徑

# 準備儲存所有讀到的 DataFrame
df_list = []

# 遞迴讀取每個子資料夾裡的 CSV 檔案
for subdir, dirs, files in os.walk(root_folder):
    for file in files:
        if file.endswith(".csv"):
            file_path = os.path.join(subdir, file)
            try:
                df = pd.read_csv(file_path)
                df["source_file"] = file  # 可選：記錄檔名
                df["source_folder"] = os.path.basename(subdir)  # 可選：記錄資料夾名
                df_list.append(df)
            except Exception as e:
                print(f"⚠️ 無法讀取 {file_path}: {e}")

# 合併成一個總表
if df_list:
    combined_df = pd.concat(df_list, ignore_index=True)
    print(f"✅ 合併完成：共 {len(df_list)} 個檔案，{len(combined_df)} 筆資料")
else:
    print("⚠️ 沒有讀取到任何 CSV 檔案")

# 若要儲存成新檔：
# combined_df.to_csv("merged_all_data.csv", index=False)

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder

df = combined_df

# Handle missing values
df.fillna({
    "packet_count_2s_max": 0,
    "packet_count_2s_mean": 0,
    "packet_count_2s_std": 0,
    "unique_dst_ip_count": 0,
    "packet_count_total": 0,
    "log_src_ip_avg_freq": 0
}, inplace=True)

# Define features to use
feature_cols = [
    "packet_count_2s_max",
    "packet_count_2s_mean",
    "packet_count_2s_std",
    "unique_dst_ip_count",
    "packet_count_total",
    "log_src_ip_avg_freq"
]

# Extract feature matrix and normalize
X = df[feature_cols]
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train Isolation Forest
model = IsolationForest(contamination=0.1, random_state=42)
df["prediction"] = model.fit_predict(X_scaled)
df["anomaly"] = df["prediction"].apply(lambda x: 1 if x == -1 else 0)

import joblib  # for model saving
# Save model and scaler
joblib.dump(model, "isolation_forest_model.joblib")
joblib.dump(scaler, "feature_scaler.joblib")

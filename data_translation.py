import os
import pandas as pd
import numpy as np
from glob import glob

# 路徑設定
input_dir = "./new_dataset/cleaned_csv_simplelog_freq"
output_dir = "./new_dataset/new_cleaned_csv_simplelog_freq"
os.makedirs(output_dir, exist_ok=True)

# 處理每個 CSV 檔案
csv_files = glob(os.path.join(input_dir, "*.csv"))
for path in csv_files:
    try:
        df = pd.read_csv(path)

        if "timestamp" in df.columns and "src_ip" in df.columns:
            # 轉為 datetime，排序
            df["timestamp"] = pd.to_datetime(df["timestamp"], unit="s")
            df = df.sort_values("timestamp")

            # 計算 log frequency
            ip_stats = df.groupby("src_ip")["timestamp"].agg(["count", "min", "max"])
            ip_stats["duration"] = (ip_stats["max"] - ip_stats["min"]).dt.total_seconds().replace(0, 1)
            ip_stats["log_freq"] = np.log1p(ip_stats["count"] / ip_stats["duration"])
            ip_freq_dict = ip_stats["log_freq"].to_dict()

            # 映射回原資料
            df["log_src_ip_avg_freq"] = df["src_ip"].map(ip_freq_dict)

        # === 僅保留需要的欄位 ===
        keep_cols = ["src_ip_delta_time", "log_src_ip_avg_freq", "src_ip", "dst_ip"]
        df = df[[col for col in keep_cols if col in df.columns]]

        # 儲存
        filename = os.path.basename(path)
        df.to_csv(os.path.join(output_dir, filename), index=False)
        print(f"✅ 完成: {filename}")

    except Exception as e:
        print(f"⚠️ 無法處理 {path}: {e}")

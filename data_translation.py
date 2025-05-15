import os
import pandas as pd
import numpy as np
from glob import glob

# 設定資料夾路徑
input_dir = "./new_dataset/csv"
output_dir = "./new_dataset/new_cleaned_csv_simplelog_freq"
os.makedirs(output_dir, exist_ok=True)

# 處理每個 CSV 檔案
csv_files = glob(os.path.join(input_dir, "*.csv"))

for path in csv_files:
    try:
        df = pd.read_csv(path)

        if {"timestamp", "src_ip", "dst_ip"}.issubset(df.columns):
            # 處理 timestamp
            df["timestamp"] = pd.to_numeric(df["timestamp"], errors="coerce")
            df["timestamp"] = pd.to_datetime(df["timestamp"], unit="s", errors="coerce")
            df = df.dropna(subset=["timestamp", "src_ip", "dst_ip"])
            df = df.sort_values("timestamp").reset_index(drop=True)

            # 新增 timestamp_seconds 欄位供滑動計算
            df["timestamp_seconds"] = df["timestamp"].astype(np.int64) // 10**9
            df["packet_count_5s"] = 0

            # 滑動時間窗口計算 + 聚合統計
            stat_list = []

            for ip, group in df.groupby("src_ip"):
                times = group["timestamp_seconds"].values
                dst_ips = group["dst_ip"].values
                counts = np.zeros(len(times), dtype=int)
                left = 0
                for right in range(len(times)):
                    while times[right] - times[left] > 5:
                        left += 1
                    counts[right] = right - left + 1

                max_pc = counts.max()
                mean_pc = counts.mean()
                std_pc = counts.std()
                unique_dst = len(set(dst_ips))

                stat_list.append({
                    "src_ip": ip,
                    "packet_count_5s_max": max_pc,
                    "packet_count_5s_mean": mean_pc,
                    "packet_count_5s_std": std_pc,
                    "unique_dst_ip_count": unique_dst
                })

            stat_df = pd.DataFrame(stat_list)

            # 加上 log_src_ip_avg_freq
            ip_counts = df["src_ip"].value_counts()
            ip_min_time = df.groupby("src_ip")["timestamp"].min()
            ip_max_time = df.groupby("src_ip")["timestamp"].max()
            duration = (ip_max_time - ip_min_time).dt.total_seconds().replace(0, 1)
            log_freq = np.log1p(ip_counts / duration)
            stat_df["log_src_ip_avg_freq"] = stat_df["src_ip"].map(log_freq)

            # 選擇輸出欄位
            keep_cols = [
                "src_ip",
                "packet_count_5s_max",
                "packet_count_5s_mean",
                "packet_count_5s_std",
                "unique_dst_ip_count",
                "log_src_ip_avg_freq"
            ]
            stat_df = stat_df[keep_cols]

            # 儲存結果
            filename = os.path.basename(path)
            stat_df.to_csv(os.path.join(output_dir, filename), index=False)
            print(f"✅ 完成: {filename}")

    except Exception as e:
        print(f"⚠️ 無法處理 {path}: {e}")

import os
import glob
import time
import shutil
from scapy.all import rdpcap, IP
import pandas as pd
import numpy as np
import joblib
import subprocess
import socket

# === 初始化資料夾 ===
csv_output_path = "new_dataset/new_cleaned_csv_simplelog_freq"
processed_path = "processed"
os.makedirs(csv_output_path, exist_ok=True)
os.makedirs(processed_path, exist_ok=True)

# === 載入模型與標準化器 ===
model = joblib.load("isolation_forest_model.joblib")
scaler = joblib.load("feature_scaler.joblib")

# === 追蹤已處理過的 pcap 檔案 ===
processed_set = set(os.listdir("processed"))

# === 自動解封設定（秒） ===
UNBLOCK_AFTER_SECONDS = 600  # 10 分鐘

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # 向 Google DNS 建立一次連線，只為了取出本機 IP
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

local_ip = get_local_ip()

def count_files(directory):
    return sum(1 for entry in os.scandir(directory) if entry.is_file())

def auto_unblock():
    blocked_path = "blocked_ips.txt"
    if not os.path.exists(blocked_path):
        return
    with open(blocked_path, "r") as f:
        lines = f.read().splitlines()

    remaining = []
    unblocked = []

    for line in lines:
        if " " not in line:
            continue
        ip, ts_str = line.split()
        try:
            ts = int(ts_str)
            if time.time() - ts >= UNBLOCK_AFTER_SECONDS:
                print(f"🔓 自動解封 IP: {ip}")
                try:
                    subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                    unblocked.append(ip)
                except subprocess.CalledProcessError:
                    print(f"⚠️ 解封失敗: {ip}")
            else:
                remaining.append(line)
        except ValueError:
            continue

    with open(blocked_path, "w") as f:
        f.write("\n".join(remaining))

    if unblocked:
        print(f"✅ 自動解封完成，共移除 {len(unblocked)} 個 IP")

def process_pcap(pcap_file):
    print(f"\n📦 處理檔案: {pcap_file}")
    packets = rdpcap(pcap_file)
    data = []
    global_last_time = None
    last_seen_time = {}

    for i, pkt in enumerate(packets):
        if IP in pkt:
            t = pkt.time
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            data.append({
                "timestamp": t,
                "src_ip": src_ip,
                "dst_ip": dst_ip
            })

    if not data:
        print("⚠️ 無有效封包，略過")
        return

    df = pd.DataFrame(data)
    df["timestamp"] = pd.to_numeric(df["timestamp"], errors="coerce")
    df["timestamp"] = pd.to_datetime(df["timestamp"], unit="s", errors="coerce")
    df = df.dropna(subset=["timestamp", "src_ip", "dst_ip"])
    df = df.sort_values("timestamp").reset_index(drop=True)

    # 新增 timestamp_seconds 欄位供滑動計算
    df["timestamp_seconds"] = df["timestamp"].astype(np.int64) // 10**9
    df["packet_count_2s"] = 0

    # 滑動時間窗口計算 + 聚合統計
    stat_list = []

    for ip, group in df.groupby("src_ip"):
        times = group["timestamp_seconds"].values
        dst_ips = group["dst_ip"].values
        counts = np.zeros(len(times), dtype=int)
        left = 0
        for right in range(len(times)):
            while times[right] - times[left] > 2:
                left += 1
            counts[right] = right - left + 1

        max_pc = counts.max()
        mean_pc = counts.mean()
        std_pc = counts.std()
        unique_dst = len(set(dst_ips))
        total_count = len(times)

        stat_list.append({
            "src_ip": ip,
            "packet_count_2s_max": max_pc,
            "packet_count_2s_mean": mean_pc,
            "packet_count_2s_std": std_pc,
            "unique_dst_ip_count": unique_dst,
            "packet_count_total": total_count
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
        "packet_count_2s_max",
        "packet_count_2s_mean",
        "packet_count_2s_std",
        "unique_dst_ip_count",
        "packet_count_total",
        "log_src_ip_avg_freq"
    ]
    stat_df = stat_df[keep_cols]


    file_num = count_files(csv_output_path)
    csv_path = csv_output_path + f"/traffic_data{file_num}_new.csv"
    stat_df.to_csv(csv_path, index=False)
    print(f"✅ CSV 已儲存: {csv_path} ({len(stat_df)} 筆)")

    return csv_path

def predict_and_block(csv_path):
    df = pd.read_csv(csv_path)
    df.fillna({
        "packet_count_2s_max": 0,
        "packet_count_2s_mean": 0,
        "packet_count_2s_std": 0,
        "unique_dst_ip_count": 0,
        "packet_count_total": 0,
        "log_src_ip_avg_freq": 0
    }, inplace=True)

    features = [
        "packet_count_2s_max",
        "packet_count_2s_mean",
        "packet_count_2s_std",
        "unique_dst_ip_count",
        "packet_count_total",
        "log_src_ip_avg_freq"
    ]

    X = scaler.transform(df[features])
    df["score"] = model.decision_function(X)  # 越小越異常
    df["anomaly"] = (df["score"] < -0.2).astype(int)

    abnormal_df = df[df["anomaly"] == 1]
    ip_counts = abnormal_df["src_ip"].value_counts()
    to_block_ips = ip_counts.index.tolist()

    print(f"🚨 符合封鎖門檻的 IP 數：{len(to_block_ips)}")

    blocked_path = "blocked_ips.txt"
    already_blocked = set()
    if os.path.exists(blocked_path):
        with open(blocked_path, "r") as f:
            already_blocked = {line.split()[0] for line in f.read().splitlines() if line.strip()}

    new_blocked = []
    with open(blocked_path, "a") as f:
        now = int(time.time())
        for ip in to_block_ips:
            if ip != local_ip and ip not in already_blocked:
                try:
                    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                    new_blocked.append(ip)
                    f.write(f"{ip} {now}\n")
                    print(f"✅ 已封鎖: {ip}")
                except subprocess.CalledProcessError:
                    print(f"⚠️ 無法封鎖: {ip}")
    # for ip in to_block_ips:
    #     print(f"✅ 已封鎖: {ip}")

    if new_blocked:
        print(f"✅ 封鎖完成，共新增 {len(new_blocked)} IP")

# === 主迴圈（每 2 秒掃描新封包） ===
print("🛡️ 開始持續監控封包並封鎖異常 IP...\n")
while True:
    auto_unblock()
    pcap_files = sorted(glob.glob("new_dataset/*.pcap"))
    new_files = [f for f in pcap_files if os.path.basename(f) not in processed_set]

    for pcap in new_files:
        csv_path = process_pcap(pcap)
        if csv_path:
            predict_and_block(csv_path)
            shutil.move(pcap, os.path.join("processed", os.path.basename(pcap)))
            processed_set.add(os.path.basename(pcap))

    break
    time.sleep(2)

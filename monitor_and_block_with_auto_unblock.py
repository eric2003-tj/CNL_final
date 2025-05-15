
import os
import glob
import time
import shutil
from scapy.all import rdpcap, IP, TCP, UDP, Raw
import pandas as pd
import joblib
import subprocess

# === 初始化資料夾 ===
os.makedirs("new_dataset/csv", exist_ok=True)
os.makedirs("processed", exist_ok=True)

# === 載入模型與標準化器 ===
model = joblib.load("isolation_forest_model.joblib")
scaler = joblib.load("feature_scaler.joblib")

# === 追蹤已處理過的 pcap 檔案 ===
processed_set = set(os.listdir("processed"))

# === 自動解封設定 ===
UNBLOCK_AFTER_SECONDS = 600  # 10 分鐘

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

            global_delta = t - global_last_time if global_last_time else -10
            global_last_time = t

            ip_delta = t - last_seen_time[src_ip] if src_ip in last_seen_time else -10
            last_seen_time[src_ip] = t

            if ip_delta < 0 or global_delta < 0:
                continue

            proto = "Other"
            dst_port = None
            src_port = None
            flags = None
            ttl = pkt[IP].ttl
            payload_len = len(pkt[Raw].load) if Raw in pkt else 0
            tcp_window = pkt[TCP].window if TCP in pkt else None
            tcp_flags_int = pkt[TCP].flags.value if TCP in pkt else None

            if TCP in pkt:
                proto = "TCP"
                dst_port = pkt[TCP].dport
                src_port = pkt[TCP].sport
                flags = pkt[TCP].flags
            elif UDP in pkt:
                proto = "UDP"
                dst_port = pkt[UDP].dport
                src_port = pkt[UDP].sport

            data.append({
                "timestamp": t,
                "global_delta_time": global_delta,
                "src_ip_delta_time": ip_delta,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto,
                "packet_length": len(pkt),
                "payload_len": payload_len,
                "ttl": ttl,
                "tcp_flags": str(flags),
                "tcp_flags_int": tcp_flags_int,
                "tcp_window": tcp_window,
                "index": i
            })

    if not data:
        print("⚠️ 無有效封包，略過")
        return

    df = pd.DataFrame(data)
    file_num = count_files("new_dataset/csv")
    csv_path = f"new_dataset/csv/traffic_data{file_num}.csv"
    df.to_csv(csv_path, index=False)
    print(f"✅ CSV 已儲存: {csv_path} ({len(df)} 筆)")

    return csv_path

def predict_and_block(csv_path):
    df = pd.read_csv(csv_path)
    df.fillna({
    "src_ip_delta_time": 0,
    "src_port": -1,
    "dst_port": -1,
    "packet_length": 0,
    "payload_len": 0,
    "ttl": 0,
    "tcp_flags_int": 0,
    "tcp_window": 0,
    "log_src_ip_avg_freq": 0
}, inplace=True)

    df["protocol_encoded"] = pd.factorize(df["protocol"])[0]

    features = [
    "src_ip_delta_time",
    "src_port",
    "dst_port",
    "packet_length",
    "payload_len",
    "ttl",
    "tcp_flags_int",
    "tcp_window",
    "log_src_ip_avg_freq"
]
    X = scaler.transform(df[features])
    df["prediction"] = model.predict(X)
    df["anomaly"] = df["prediction"].apply(lambda x: 1 if x == -1 else 0)

    abnormal_df = df[df["anomaly"] == 1]
    ip_counts = abnormal_df["src_ip"].value_counts()
    to_block_ips = ip_counts[ip_counts >= 5].index.tolist()

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
            if ip not in already_blocked:
                try:
                    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                    new_blocked.append(ip)
                    f.write(f"{ip} {now}\n")
                    print(f"✅ 已封鎖: {ip}")
                except subprocess.CalledProcessError:
                    print(f"⚠️ 無法封鎖: {ip}")

    if new_blocked:
        print(f"✅ 封鎖完成，共新增 {len(new_blocked)} IP")

# === 主迴圈（每 30 秒掃描新封包） ===
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

    time.sleep(30)

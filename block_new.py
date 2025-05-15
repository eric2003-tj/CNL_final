import pandas as pd
import joblib
import subprocess
import os

# 讀取模型與 scaler
model = joblib.load("isolation_forest_model.joblib")
scaler = joblib.load("feature_scaler.joblib")

# 讀取新封包資料（請確保檔案存在）
df = pd.read_csv("new_packets.csv")

# 欄位補值處理
df.fillna({
    "protocol": "Other",
    "src_port": -1,
    "dst_port": -1,
    "packet_length": 0,
    "payload_len": 0,
    "ttl": 0,
    "tcp_flags_int": 0,
    "tcp_window": 0,
    "global_delta_time": 0,
    "src_ip_delta_time": 0
}, inplace=True)

# 協定編碼
df["protocol_encoded"] = pd.factorize(df["protocol"])[0]

# 特徵欄位
features = [
    "protocol_encoded",
    "src_port",
    "dst_port",
    "packet_length",
    "payload_len",
    "ttl",
    "tcp_flags_int",
    "tcp_window",
    "global_delta_time",
    "src_ip_delta_time"
]

# 特徵標準化
X = scaler.transform(df[features])

# 推論模型
df["prediction"] = model.predict(X)
df["anomaly"] = df["prediction"].apply(lambda x: 1 if x == -1 else 0)

# === 實務建議封鎖策略：同一 IP 若異常次數 >= 5，才封鎖 ===
abnormal_df = df[df["anomaly"] == 1]
ip_counts = abnormal_df["src_ip"].value_counts()
to_block_ips = ip_counts[ip_counts >= 5].index.tolist()

print(f"✅ 符合封鎖門檻的可疑 IP 數量：{len(to_block_ips)}")

# 載入已封鎖清單
blocked_path = "blocked_ips.txt"
if os.path.exists(blocked_path):
    with open(blocked_path, "r") as f:
        already_blocked = set(f.read().splitlines())
else:
    already_blocked = set()

# 執行封鎖
new_blocked = []
for ip in to_block_ips:
    if ip not in already_blocked:
        print(f"🚫 Blocking IP: {ip}")
        try:
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            new_blocked.append(ip)
        except subprocess.CalledProcessError:
            print(f"⚠️ Failed to block {ip}")

# 更新封鎖紀錄
if new_blocked:
    with open(blocked_path, "a") as f:
        f.writelines(ip + "\n" for ip in new_blocked)

print(f"✅ 封鎖作業完成，共封鎖 {len(new_blocked)} 個新 IP")

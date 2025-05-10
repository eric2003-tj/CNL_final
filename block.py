import pandas as pd
import joblib
import subprocess
import os

# 載入模型與 scaler
model = joblib.load("isolation_forest_model.joblib")
scaler = joblib.load("feature_scaler.joblib")

# 讀入新封包資料（請確認這個檔案存在）
df = pd.read_csv("new_packets.csv")

# 欄位與前訓練一致
df.fillna({
    "protocol": "Other",
    "src_port": -1,
    "dst_port": -1,
    "packet_length": 0,
    "payload_len": 0,
    "ttl": 0,
    "tcp_flags_int": 0,
    "tcp_window": 0
}, inplace=True)

# 編碼協定欄位
df["protocol_encoded"] = pd.factorize(df["protocol"])[0]

# 建立特徵矩陣
features = [
    "protocol_encoded", "src_port", "dst_port", "packet_length",
    "payload_len", "ttl", "tcp_flags_int", "tcp_window"
]
X = scaler.transform(df[features])

# 模型推論
df["prediction"] = model.predict(X)
df["anomaly"] = df["prediction"].apply(lambda x: 1 if x == -1 else 0)

# 擷取異常來源 IP
suspicious_ips = df[df["anomaly"] == 1]["src_ip"].unique()

# 載入已封鎖過的 IP
blocked_path = "blocked_ips.txt"
if os.path.exists(blocked_path):
    with open(blocked_path, "r") as f:
        already_blocked = set(f.read().splitlines())
else:
    already_blocked = set()

# 新增封鎖
new_blocked = []
for ip in suspicious_ips:
    if ip not in already_blocked:
        print(f"🚫 Blocking IP: {ip}")
        try:
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            new_blocked.append(ip)
        except subprocess.CalledProcessError:
            print(f"⚠️ Failed to block {ip}")

# 寫入封鎖紀錄
if new_blocked:
    with open(blocked_path, "a") as f:
        f.writelines(ip + "\n" for ip in new_blocked)

print(f"✅ 完成：共封鎖 {len(new_blocked)} 個新 IP")


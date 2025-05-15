from flask import Flask, jsonify, request
import pandas as pd
import subprocess
import os

app = Flask(__name__)

PACKET_FILE = "packets_with_anomaly.csv"
BLOCKED_LOG = "blocked_ips.txt"

@app.route("/api/packets", methods=["GET"])
def get_packets():
    try:
        df = pd.read_csv(PACKET_FILE)
        return df.to_json(orient="records")
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/unblock", methods=["POST"])
def unblock_ip():
    ip = request.json.get("ip")
    if not ip:
        return jsonify({"error": "No IP provided"}), 400
    try:
        # 執行 iptables 解封
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        
        # 更新封鎖紀錄檔
        if os.path.exists(BLOCKED_LOG):
            with open(BLOCKED_LOG, "r") as f:
                lines = f.read().splitlines()
            lines = [line for line in lines if line.strip() != ip]
            with open(BLOCKED_LOG, "w") as f:
                f.write("\n".join(lines))

        return jsonify({"status": "unblocked", "ip": ip}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to unblock {ip}: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(debug=True)


from flask import Flask, jsonify, request, render_template
import subprocess
import os
import time

app = Flask(__name__, template_folder="templates")
BLOCKED_PATH = "blocked_ips.txt"

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/api/blocked_ips", methods=["GET"])
def get_blocked_ips():
    if not os.path.exists(BLOCKED_PATH):
        return jsonify([])

    blocked_list = []
    with open(BLOCKED_PATH, "r") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) == 2:
                ip, ts = parts
                blocked_list.append({
                    "ip": ip,
                    "timestamp": int(ts),
                    "seconds_blocked": int(time.time()) - int(ts)
                })
    return jsonify(blocked_list)

@app.route("/api/unblock", methods=["POST"])
def unblock_ip():
    ip = request.json.get("ip")
    if not ip:
        return jsonify({"error": "Missing IP"}), 400

    try:
        result = subprocess.run(
            ["sudo", "/usr/bin/iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            check=True,
            capture_output=True,
            text=True
        )
        print(f"✅ 解封 IP: {ip}")
    except subprocess.CalledProcessError as e:
        print(f"❌ 解封失敗: {e.stderr}")
        return jsonify({"error": f"Failed to unblock {ip}: {e.stderr}"}), 500

    if os.path.exists(BLOCKED_PATH):
        with open(BLOCKED_PATH, "r") as f:
            lines = f.read().splitlines()
        lines = [line for line in lines if not line.startswith(ip + " ")]
        with open(BLOCKED_PATH, "w") as f:
            f.write("\n".join(lines) + "\n")

    return jsonify({"status": "unblocked", "ip": ip})

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False, host="0.0.0.0", port=5000)
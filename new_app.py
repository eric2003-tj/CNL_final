from flask import Flask, jsonify, request, render_template
import subprocess
import os
import time
import socket

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

@app.route("/api/block_ip", methods=["POST"])
def block_ip():
    data = request.get_json()
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "Missing IP"}), 400

    # Block in iptables
    try:
        subprocess.run(
            ["sudo", "/usr/sbin/iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True
        )
    except Exception as e:
        return jsonify({"error": f"iptables error: {str(e)}"}), 500

    # Write to file
    ts = int(time.time())
    with open(BLOCKED_PATH, "a") as f:
        f.write(f"{ip} {ts}\n")
    return jsonify({"status": "blocked", "ip": ip, "timestamp": ts})

@app.route("/api/machine_ip", methods=["GET"])
def machine_ip():
    # Get the local IP address of the current machine (eth0/wlan0)
    ip = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except:
        ip = "127.0.0.1"
    return jsonify({"ip": ip})

@app.route("/api/unblock", methods=["POST"])
def unblock_ip():
    ip = request.json.get("ip")
    if not ip:
        return jsonify({"error": "Missing IP"}), 400

    try:
        result = subprocess.run(
            ["sudo", "/usr/sbin/iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
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
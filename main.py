import os
import subprocess
import time
from datetime import datetime
import glob

# === Step 1: Run mo*.py (e.g., model launcher)
def run_model_once():
    mo_scripts = glob.glob("mo*.py")
    app_scripts = glob.glob("new_app.py")
    if not mo_scripts:
        print("❌ No script matching mo*.py found.")
        return False
    if not app_scripts:
        print("❌ No script matching new_app.py found.")
        return False
    mo_script = mo_scripts[0]
    app_script = app_scripts[0]
    print(f"🚀 Running script: {mo_script} & {app_script}")
    try:
        subprocess.run(["python3", mo_script], check=True)
    except subprocess.CalledProcessError as e:
        print(f"⚠️ Error while running {mo_script}: {e}")
        return False
    try:
        subprocess.run(["python3", app_script], check=True)
    except subprocess.CalledProcessError as e:
        print(f"⚠️ Error while running {app_script}: {e}")
        return False

# === Step 2: Repeated tcpdump -c 100000
def start_capture_loop():
    os.makedirs("new_dataset", exist_ok=True)
    print("📡 Starting packet capture loop (tcpdump -c 100000)...")
    while True:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_file = f"new_dataset/capture_{timestamp}.pcap"
        print(f"⏱️ Capturing packets to {pcap_file}")
        try:
            subprocess.run([
                "sudo", "tcpdump", "-c", "100000", "-w", pcap_file
            ], check=True)
            print(f"✅ Capture complete: {pcap_file}")
        except subprocess.CalledProcessError as e:
            print(f"⚠️ tcpdump failed: {e}")
        time.sleep(1)  # Optional: wait briefly before next loop

# === Main Execution ===
if __name__ == "__main__":
    if run_model_once():
        start_capture_loop()

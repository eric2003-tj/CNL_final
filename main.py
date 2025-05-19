import os
import subprocess
import time
from datetime import datetime
import glob
import signal

directory = "new_dataset/pcaps"
num = 10000

def count_files(directory):
    return sum(1 for entry in os.scandir(directory) if entry.is_file())

# === Step 1: Run mo*.py (e.g., model launcher)
def run_model_once():
    mo_scripts = glob.glob("mo*.py")
    app_scripts = glob.glob("new_app.py")

    mo_log = open("mo.log", "w")
    flask_log = open("flask.log", "w")

    mo_proc = False
    flask_proc = False

    if not mo_scripts:
        print("❌ No script matching mo*.py found.")
        return mo_proc, flask_proc
    if not app_scripts:
        print("❌ No script matching new_app.py found.")
        return mo_proc, flask_proc

    mo_script = mo_scripts[0]
    app_script = app_scripts[0]
    print(f"🚀 Running script: {mo_script} & {app_script}")

    try:
        mo_proc = subprocess.Popen(["python3", "-u", mo_script], stdout=mo_log, stderr=mo_log)
        print("🌐 Monitor started")
    except subprocess.CalledProcessError as e:
        print(f"⚠️ Error while running {mo_script}: {e}")
        return mo_proc, flask_proc

    try:
        flask_proc = subprocess.Popen(["python3", app_script], stdout=flask_log, stderr=flask_log)
        print("🌐 Flask started (logs in flask.log)")
        return mo_proc, flask_proc
    except subprocess.CalledProcessError as e:
        print(f"⚠️ Error while running {app_script}: {e}")
        return mo_proc, flask_proc

# === Step 2: Repeated tcpdump -c {num}
def start_capture_loop():
    os.makedirs("new_dataset", exist_ok=True)
    print("📡 Starting packet capture loop...")

    while True:
        file_num = count_files("processed")
        pcap_file = directory + f"/capture_{file_num}.pcap"
        print(f"⏱️ Capturing to {pcap_file} ...")

        try:
            subprocess.run(
                ["sudo", "/usr/bin/tcpdump", "-c", f"{num}", "-w", pcap_file],
                check=True
            )
            print(f"✅ Capture complete: {pcap_file}")
        except subprocess.CalledProcessError as e:
            print(f"⚠️ tcpdump failed: {e}")
            break

        # ✅ Count number of packets in pcap
        try:
            result = subprocess.run(
                ["tcpdump", "-r", pcap_file, "-nn", "-q"],
                capture_output=True,
                text=True
            )
            line_count = len(result.stdout.strip().split("\n"))
            print(f"📊 Packets captured in file: {line_count}")

            ready_file = pcap_file.replace(".pcap", "_ready.pcap")
            subprocess.run(["mv", pcap_file, ready_file], check=True)
                    
            if line_count < num:
                print(f"🛑 Capture was interrupted (packet count < {num}). Exiting loop.")
                break

        except Exception as e:
            print(f"❌ Failed to count packets in {pcap_file}: {e}")
            break

    print("👋 Packet capture loop exited.")

# === Main Execution ===
if __name__ == "__main__":
    try:
        subprocess.run(f"rm -rf {directory}/*", shell=True, check=True)
        mo_proc, flask_proc = run_model_once()
        start_capture_loop()
    finally:
        print("🧹 Cleaning up...")
        if mo_proc:
            mo_proc.terminate()
            print("❎ Mo* process terminated")
        if flask_proc:
            flask_proc.terminate()
            print("❎ Flask process terminated")

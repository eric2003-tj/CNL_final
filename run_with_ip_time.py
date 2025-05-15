from scapy.all import rdpcap, IP, TCP, UDP, Raw
import pandas as pd
import os
import glob

os.makedirs("./new_dataset./csv", exist_ok=True)
pcap_files = sorted(glob.glob("./new_dataset/*.pcap"))
def count_files(directory):
    return sum(1 for entry in os.scandir(directory) if entry.is_file())
for file_cnt, pcap_file in enumerate(pcap_files):
    print(f"📦 Processing: {pcap_file}")
    packets = rdpcap(pcap_file)
    data = []

    global_last_time = None
    last_seen_time = {}  # per src_ip

    for i, pkt in enumerate(packets):
        if IP in pkt:
            t = pkt.time
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

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
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "packet_length": len(pkt),
                "payload_len": payload_len,
                "ttl": ttl,
                "tcp_flags": str(flags),
                "tcp_flags_int": tcp_flags_int,
                "tcp_window": tcp_window,
            })
    df = pd.DataFrame(data)
    file_num = count_files("new_dataset/csv")
    out_file = f"new_dataset/csv/traffic_data{file_num}.csv"
    df.to_csv(out_file, index=False)
    print(f"✅ Saved: {out_file} ({len(df)} packets)")

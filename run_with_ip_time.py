from scapy.all import rdpcap, IP, TCP, UDP, Raw
import pandas as pd
import os
import glob

os.makedirs("mixed", exist_ok=True)
pcap_files = sorted(glob.glob("chunk_*.pcap"))

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

            # delta_time: global and per-IP
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

    df = pd.DataFrame(data)
    out_file = f"mixed/traffic_data{file_cnt}.csv"
    df.to_csv(out_file, index=False)
    print(f"✅ Saved: {out_file} ({len(df)} packets)")

"""
File: ips_engine.py
Deskripsi: Engine IPS Real-Time yang beroperasi di Gateway Linux.
           Menangkap paket jaringan, menghitung fitur statistik aliran,
           memprediksi anomali dengan ML (Random Forest), dan otomatis memblokir
           IP penyerang menggunakan perintah iptables di kernel Linux.
Penggunaan: sudo python3 ips_engine.py --interface eth0
"""

import os
import sys
import time
import json
import argparse
import numpy as np
import joblib

# Optional scapy import for environments without libpcap
try:
    from scapy.all import sniff, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "..", "models", "model_ips_rf.joblib")
SCALER_PATH = os.path.join(BASE_DIR, "..", "models", "scaler.joblib")
LOG_DIR = os.path.join(BASE_DIR, "..", "reports")

FLOW_CACHE = {}
BLOCKED_IPS = set()
ATTACK_EVENTS = []
FLOW_TIMEOUT = 5.0

class FlowStatistics:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto
        self.start_time = time.time()
        self.last_seen = self.start_time
        
        self.tot_fwd_pkts = 0
        self.tot_bwd_pkts = 0
        self.tot_fwd_bytes = 0
        self.tot_bwd_bytes = 0
        self.bwd_pkt_lengths = []
        self.packet_times = [self.start_time]
        
        self.syn_count = 0
        self.rst_count = 0
        self.ack_count = 0
        self.init_fwd_win = 0

    def update(self, packet, direction="FWD"):
        current_time = time.time()
        self.last_seen = current_time
        self.packet_times.append(current_time)
        pkt_len = len(packet)

        if direction == "FWD":
            self.tot_fwd_pkts += 1
            self.tot_fwd_bytes += pkt_len
            if hasattr(packet, "haslayer") and packet.haslayer(TCP) and self.init_fwd_win == 0:
                self.init_fwd_win = packet[TCP].window
        else:
            self.tot_bwd_pkts += 1
            self.tot_bwd_bytes += pkt_len
            self.bwd_pkt_lengths.append(pkt_len)

        if hasattr(packet, "haslayer") and packet.haslayer(TCP):
            flags = packet[TCP].flags
            if 'S' in flags: self.syn_count += 1
            if 'R' in flags: self.rst_count += 1
            if 'A' in flags: self.ack_count += 1

    def extract_features(self):
        duration = max(self.last_seen - self.start_time, 0.0001)
        tot_pkts = self.tot_fwd_pkts + self.tot_bwd_pkts
        tot_bytes = self.tot_fwd_bytes + self.tot_bwd_bytes

        flow_byts_s = tot_bytes / duration
        flow_pkts_s = tot_pkts / duration

        bwd_mean = float(np.mean(self.bwd_pkt_lengths)) if self.bwd_pkt_lengths else 0.0

        iats = np.diff(self.packet_times) if len(self.packet_times) > 1 else [0.0]
        flow_iat_mean = float(np.mean(iats))
        fwd_iat_tot = duration

        # Urutan 15 Fitur Standar
        feature_vector = np.array([
            self.dst_port,
            duration * 1e6,
            self.tot_fwd_pkts,
            self.tot_bwd_pkts,
            self.tot_fwd_bytes,
            self.tot_bwd_bytes,
            bwd_mean,
            flow_byts_s,
            flow_pkts_s,
            flow_iat_mean * 1e6,
            fwd_iat_tot * 1e6,
            self.syn_count,
            self.rst_count,
            self.ack_count,
            self.init_fwd_win
        ], dtype=float)

        return feature_vector.reshape(1, -1)

def block_ip_iptables(attacker_ip, attack_type="Anomali Aliran"):
    """
    Eksekusi Mitigasi Aktif:
    Menyuntikkan aturan pemblokiran ke kernel firewall Linux (iptables)
    """
    if attacker_ip in BLOCKED_IPS:
        return 0.0

    BLOCKED_IPS.add(attacker_ip)
    t_start = time.time()
    
    cmd_forward = f"iptables -I FORWARD -s {attacker_ip} -j DROP"
    cmd_input = f"iptables -I INPUT -s {attacker_ip} -j DROP"
    
    # Eksekusi sistem
    if os.name != 'nt':
        os.system(cmd_forward)
        os.system(cmd_input)
    
    injection_latency_ms = (time.time() - t_start) * 1000
    
    event = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "attacker_ip": attacker_ip,
        "attack_type": attack_type,
        "rule_executed": cmd_forward,
        "injection_latency_ms": round(injection_latency_ms, 3)
    }
    ATTACK_EVENTS.append(event)
    
    print("\n" + "!"*60)
    print(f"[!] [ACTION MITIGASI] SERANGAN TERDETEKSI!")
    print(f"[!] IP Penyerang Diblokir : {attacker_ip}")
    print(f"[!] Jenis Anomali          : {attack_type}")
    print(f"[!] Eksekusi Firewall Rule : {cmd_forward}")
    print(f"[!] Waktu Injeksi Aturan   : {injection_latency_ms:.2f} ms")
    print("!"*60 + "\n")

    # Simpan event log
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(os.path.join(LOG_DIR, "ips_blocked_events.json"), "w") as f:
        json.dump(ATTACK_EVENTS, f, indent=4)
        
    return injection_latency_ms

def process_packet(packet, model, scaler):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if src_ip in BLOCKED_IPS:
        return

    proto = packet[IP].proto
    src_port = 0
    dst_port = 0

    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    else:
        return

    flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
    reverse_key = (dst_ip, src_ip, dst_port, src_port, proto)

    if flow_key in FLOW_CACHE:
        flow = FLOW_CACHE[flow_key]
        flow.update(packet, direction="FWD")
    elif reverse_key in FLOW_CACHE:
        flow = FLOW_CACHE[reverse_key]
        flow.update(packet, direction="BWD")
    else:
        flow = FlowStatistics(src_ip, dst_ip, src_port, dst_port, proto)
        flow.update(packet, direction="FWD")
        FLOW_CACHE[flow_key] = flow

    if (flow.tot_fwd_pkts + flow.tot_bwd_pkts) >= 5:
        features = flow.extract_features()
        scaled_features = scaler.transform(features)
        
        t0 = time.time()
        prediction = model.predict(scaled_features)[0]
        infer_time = (time.time() - t0) * 1000

        if prediction == 1:
            print(f"[*] Alert: Aliran anomali terdeteksi dari {src_ip} -> {dst_ip}:{dst_port} (Inferensi ML: {infer_time:.2f} ms)")
            block_ip_iptables(src_ip, attack_type="DoS / PortScan Flooding")
            FLOW_CACHE.pop(flow_key, None)

def main():
    parser = argparse.ArgumentParser(description="IPS Engine Berbasis Machine Learning")
    parser.add_argument("--interface", default="eth0", help="Antarmuka jaringan yang dipantau (misal: eth0 / enp0s3)")
    args = parser.parse_args()

    if os.name != 'nt' and os.geteuid() != 0:
        sys.exit("[!] Error: Script IPS harus dijalankan dengan hak akses root (sudo).")

    print("[*] Memuat model Random Forest dan Scaler...")
    if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
        sys.exit(f"[!] Error: File model tidak ditemukan di {MODEL_PATH}. Jalankan train_model.py terlebih dahulu.")

    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    print("[+] Model dan Scaler berhasil dimuat.")
    print(f"[*] Memulai Packet Sniffing pada antarmuka: {args.interface}...")
    print("[*] Status: IPS Engine AKTIF dan siap memitigasi serangan.\n")

    if os.name != 'nt':
        os.system("iptables -F FORWARD")

    try:
        sniff(iface=args.interface, prn=lambda pkt: process_packet(pkt, model, scaler), store=False)
    except KeyboardInterrupt:
        print("\n[*] Menghentikan IPS Engine...")
        print(f"[*] Total IP yang telah diblokir selama sesi ini: {len(BLOCKED_IPS)}")

if __name__ == "__main__":
    main()

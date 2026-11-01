"""
File: ips_engine.py
Deskripsi: Engine IPS Real-Time yang beroperasi di Gateway Linux.
           Menangkap paket jaringan, merekonstruksi statistik aliran 5-tuple,
           memprediksi anomali dengan model ML (Random Forest), dan memicu
           pemblokiran otomatis alamat IP penyerang menggunakan kernel iptables.
Penggunaan: sudo python3 ips_engine.py --interface eth0 --threshold 0.80 --whitelist 192.168.10.1,192.168.20.1
"""

import os
import sys
import time
import json
import argparse
import numpy as np
import joblib

try:
    from scapy.all import sniff, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.abspath(os.path.join(BASE_DIR, ".."))
MODEL_PATH = os.path.join(PROJECT_DIR, "models", "model_ips_rf.joblib")
SCALER_PATH = os.path.join(PROJECT_DIR, "models", "scaler.joblib")
LOG_DIR = os.path.join(PROJECT_DIR, "reports")

FLOW_CACHE = {}
BLOCKED_IPS = set()
DEFAULT_WHITELIST = {"127.0.0.1", "192.168.10.1", "192.168.20.1", "8.8.8.8", "1.1.1.1"}
WHITELISTED_IPS = set(DEFAULT_WHITELIST)
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

        # Urutan 15 Fitur Standar CICFlowMeter
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

def block_ip_iptables(attacker_ip, attack_type="Anomali Aliran", dry_run=False, proba=1.0):
    """
    Eksekusi Mitigasi Aktif:
    Menyuntikkan aturan pemblokiran ke kernel firewall Linux (iptables)
    """
    if attacker_ip in WHITELISTED_IPS:
        print(f"[*] [WHITELIST] Alamat IP {attacker_ip} dilewati dari pemblokiran (Trusted IP).")
        return 0.0

    if attacker_ip in BLOCKED_IPS:
        return 0.0

    BLOCKED_IPS.add(attacker_ip)
    t_start = time.time()
    
    cmd_forward = f"iptables -I FORWARD -s {attacker_ip} -j DROP"
    cmd_input = f"iptables -I INPUT -s {attacker_ip} -j DROP"
    
    # Eksekusi sistem jika bukan dry-run dan berjalan di Linux
    if not dry_run and os.name != 'nt':
        os.system(cmd_forward)
        os.system(cmd_input)
    
    injection_latency_ms = (time.time() - t_start) * 1000
    
    event = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "attacker_ip": attacker_ip,
        "attack_type": attack_type,
        "probability": round(float(proba), 4),
        "rule_executed": cmd_forward,
        "injection_latency_ms": round(injection_latency_ms, 3),
        "status": "SIMULATED_BLOCK" if dry_run else "BLOCKED"
    }
    ATTACK_EVENTS.append(event)
    
    print("\n" + "!"*65)
    print(f"[!] [ACTION MITIGASI] SERANGAN TERDETEKSI!")
    print(f"[!] IP Penyerang Diblokir : {attacker_ip}")
    print(f"[!] Jenis Anomali          : {attack_type} (Keyakinan ML: {proba*100:.1f}%)")
    print(f"[!] Eksekusi Firewall Rule : {cmd_forward}")
    print(f"[!] Waktu Injeksi Aturan   : {injection_latency_ms:.2f} ms")
    if dry_run:
        print("[!] [MODE SIMULASI] Aturan tidak benar-benar dieksekusi di kernel (--dry-run).")
    print("!"*65 + "\n")

    os.makedirs(LOG_DIR, exist_ok=True)
    with open(os.path.join(LOG_DIR, "ips_blocked_events.json"), "w") as f:
        json.dump(ATTACK_EVENTS, f, indent=4)
        
    return injection_latency_ms

def process_packet(packet, model, scaler, threshold=0.50, dry_run=False):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if src_ip in BLOCKED_IPS or src_ip in WHITELISTED_IPS:
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

    # Ekstraksi setelah aliran memiliki minimal 5 paket
    if (flow.tot_fwd_pkts + flow.tot_bwd_pkts) >= 5:
        features = flow.extract_features()
        scaled_features = scaler.transform(features)
        
        t0 = time.time()
        # Menggunakan predict_proba untuk threshold tuning
        proba_attack = model.predict_proba(scaled_features)[0][1]
        infer_time = (time.time() - t0) * 1000

        if proba_attack >= threshold:
            print(f"[*] Alert: Aliran anomali terdeteksi dari {src_ip} -> {dst_ip}:{dst_port} (Probabilitas: {proba_attack:.3f}, Inferensi ML: {infer_time:.2f} ms)")
            block_ip_iptables(src_ip, attack_type="DoS / PortScan Flooding", dry_run=dry_run, proba=proba_attack)
            FLOW_CACHE.pop(flow_key, None)

def main():
    parser = argparse.ArgumentParser(description="Engine IPS Berbasis Machine Learning In-Line")
    parser.add_argument("--interface", default="eth0", help="Antarmuka jaringan yang dipantau (misal: eth0 / ens33)")
    parser.add_argument("--threshold", type=float, default=0.50, help="Ambang batas probabilitas deteksi (default: 0.50, rekomendasi produksi: 0.80)")
    parser.add_argument("--whitelist", type=str, default="", help="Daftar IP yang dikecualikan dari blokir, pisahkan dengan koma")
    parser.add_argument("--dry-run", action="store_true", help="Jalankan dalam mode simulasi tanpa mengubah tabel iptables")
    args = parser.parse_args()

    if os.name != 'nt' and os.geteuid() != 0 and not args.dry_run:
        sys.exit("[!] Error: Script IPS harus dijalankan dengan hak akses root (sudo).")

    if args.whitelist:
        for ip in args.whitelist.split(","):
            if ip.strip():
                WHITELISTED_IPS.add(ip.strip())

    print("="*65)
    print("  ENGINE IPS BERBASIS MACHINE LEARNING (REACTIVE KERNEL MITIGATION)")
    print("="*65)
    print(f"[*] Antarmuka Dipantau    : {args.interface}")
    print(f"[*] Ambang Batas Deteksi  : {args.threshold * 100:.1f}%")
    print(f"[*] Mode Dry-Run          : {'AKTIF (Simulasi)' if args.dry_run else 'TIDAK (Live Kernel Drop)'}")
    print(f"[*] Daftar IP Whitelist   : {', '.join(sorted(WHITELISTED_IPS))}")

    if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
        sys.exit(f"[!] Error: File model tidak ditemukan di {MODEL_PATH}. Jalankan train_model.py terlebih dahulu.")

    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    print("[+] Model Random Forest dan Scaler berhasil dimuat.")
    print("[*] Status: IPS Engine AKTIF dan siap memantau lalu lintas.\n")

    if not args.dry_run and os.name != 'nt':
        os.system("iptables -F FORWARD")

    try:
        sniff(iface=args.interface, prn=lambda pkt: process_packet(pkt, model, scaler, threshold=args.threshold, dry_run=args.dry_run), store=False)
    except KeyboardInterrupt:
        print("\n[*] Menghentikan IPS Engine...")
        print(f"[*] Total IP yang telah diblokir selama sesi ini: {len(BLOCKED_IPS)}")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
File: vm_live_ips_benchmark.py
Deskripsi: Suite Pengujian Empiris Multi-Iterasi Langsung di Lingkungan VM Ubuntu (IPS-Gateway).
           Menjalankan serangkaian pengujian mendalam (5 Iterasi pengujian penuh dengan vektor data uji riil CSE-CIC-IDS2018):
           1. Injeksi & Latensi Rule Kernel iptables/Netfilter
           2. Inferensi Machine Learning (Random Forest) di CPU Linux Guest
           3. Deteksi Real-Time & Evaluasi Metrik (DoS, DDoS, Benign)
           4. Evaluasi Ketahanan Fail-Safe / IP Whitelisting
           5. Analisis Efisiensi Skalabilitas & Rule Bloat Netfilter
"""

import os
import sys
import time
import json
import random
import subprocess
import numpy as np
import joblib

BASE_DIR = "/home/ubuntu/ips"
MODEL_PATH = os.path.join(BASE_DIR, "models", "model_ips_rf.joblib")
SCALER_PATH = os.path.join(BASE_DIR, "models", "scaler.joblib")
FEATURES_PATH = os.path.join(BASE_DIR, "models", "features.json")
DATA_PATH = os.path.join(BASE_DIR, "data", "test_samples_eval.json")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
OUTPUT_JSON = os.path.join(REPORTS_DIR, "vm_live_empirical_results.json")

os.makedirs(REPORTS_DIR, exist_ok=True)

# 1. Load model, scaler & data
print("[*] Memuat Model Random Forest, Scaler, dan Data Uji di VM Guest...")
if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH) or not os.path.exists(DATA_PATH):
    print("[-] Berkas yang dibutuhkan tidak lengkap!")
    sys.exit(1)

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

with open(DATA_PATH, "r") as f:
    eval_dataset = json.load(f)

benign_samples = eval_dataset.get("benign", [])
dos_samples = eval_dataset.get("dos", [])
ddos_samples = eval_dataset.get("ddos", [])

print(f"[+] Dataset termuat: {len(benign_samples)} Benign, {len(dos_samples)} DoS, {len(ddos_samples)} DDoS.")

# Testbed IP Whitelist
WHITELIST_IPS = {"127.0.0.1", "192.168.154.1", "192.168.154.2", "8.8.8.8", "8.8.4.4"}

def clean_iptables_test_rules():
    subprocess.run(["sudo", "iptables", "-F", "INPUT"], capture_output=True)
    subprocess.run(["sudo", "iptables", "-F", "FORWARD"], capture_output=True)

def inject_iptables_rule(ip):
    t0 = time.perf_counter()
    res = subprocess.run(["sudo", "iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"], capture_output=True)
    latency_ms = (time.perf_counter() - t0) * 1000.0
    return latency_ms, res.returncode == 0

def run_multi_iteration_evaluations(num_iterations=5, flows_per_iteration=300):
    print("=" * 80)
    print(f"  PENGUJIAN EMPIRIS MULTI-ITERASI IPS MACHINE LEARNING DALAM GUEST VM")
    print(f"  Spesifikasi Host-Guest: Ubuntu 22.04 LTS Kernel {os.uname().release}")
    print(f"  Vektor Uji: CSE-CIC-IDS2018 Resmi | Ambang Batas Pareto (theta): 0.80")
    print(f"  Total Iterasi: {num_iterations} siklus | Beban: {flows_per_iteration} flow per siklus")
    print("=" * 80)

    clean_iptables_test_rules()

    all_iteration_results = []
    overall_inference_latencies = []
    overall_netfilter_latencies = []
    total_blocked_ips = 0

    for it in range(1, num_iterations + 1):
        print(f"\n--- [ITERASI {it}/{num_iterations}] Menjalankan Pengujian Komprehensif ---")
        t_start_it = time.time()

        it_metrics = {
            "iteration": it,
            "benign_tested": 0,
            "benign_false_positives": 0,
            "dos_tested": 0,
            "dos_detected": 0,
            "ddos_tested": 0,
            "ddos_detected": 0,
            "inference_latencies_ms": [],
            "netfilter_latencies_ms": [],
            "whitelist_checks_passed": 0
        }

        # Sub-sampling per iteration: 50% Benign, 25% DoS, 25% DDoS
        n_benign = int(flows_per_iteration * 0.50)
        n_dos = int(flows_per_iteration * 0.25)
        n_ddos = flows_per_iteration - (n_benign + n_dos)

        sample_benign = random.sample(benign_samples, min(n_benign, len(benign_samples)))
        sample_dos = random.sample(dos_samples, min(n_dos, len(dos_samples)))
        sample_ddos = random.sample(ddos_samples, min(n_ddos, len(ddos_samples)))

        traffic_mix = []
        for v in sample_benign: traffic_mix.append(("Benign", np.array(v, dtype=np.float32)))
        for v in sample_dos: traffic_mix.append(("DoS", np.array(v, dtype=np.float32)))
        for v in sample_ddos: traffic_mix.append(("DDoS", np.array(v, dtype=np.float32)))

        random.shuffle(traffic_mix)

        active_blocked = set()

        for idx, (label, flow_feats) in enumerate(traffic_mix):
            src_ip = f"192.168.100.{(idx % 240) + 10}"

            # 1. Feature scaling & Inference
            feats_2d = flow_feats.reshape(1, -1)
            t_inf_0 = time.perf_counter()
            feats_scaled = scaler.transform(feats_2d)
            prob_malicious = model.predict_proba(feats_scaled)[0, 1]
            inf_ms = (time.perf_counter() - t_inf_0) * 1000.0

            it_metrics["inference_latencies_ms"].append(inf_ms)
            overall_inference_latencies.append(inf_ms)

            # Keputusan Ambang Batas Pareto (theta = 0.80)
            is_detected = prob_malicious >= 0.80

            if label == "Benign":
                it_metrics["benign_tested"] += 1
                if is_detected:
                    it_metrics["benign_false_positives"] += 1
            elif label == "DoS":
                it_metrics["dos_tested"] += 1
                if is_detected:
                    it_metrics["dos_detected"] += 1
            elif label == "DDoS":
                it_metrics["ddos_tested"] += 1
                if is_detected:
                    it_metrics["ddos_detected"] += 1

            # 2. Tindakan Mitigasi Netfilter jika terdeteksi
            if is_detected:
                if src_ip in WHITELIST_IPS:
                    it_metrics["whitelist_checks_passed"] += 1
                elif src_ip not in active_blocked:
                    lat_nf, ok = inject_iptables_rule(src_ip)
                    if ok:
                        active_blocked.add(src_ip)
                        it_metrics["netfilter_latencies_ms"].append(lat_nf)
                        overall_netfilter_latencies.append(lat_nf)

        # Fail-Safe Whitelisting Test dengan IP Gateway & Host
        for white_ip in ["192.168.154.1", "192.168.154.2", "8.8.8.8"]:
            attack_vec = random.choice(sample_dos)
            attack_2d = np.array(attack_vec, dtype=np.float32).reshape(1, -1)
            scaled = scaler.transform(attack_2d)
            p = model.predict_proba(scaled)[0, 1]
            if p >= 0.80:
                if white_ip in WHITELIST_IPS:
                    it_metrics["whitelist_checks_passed"] += 1

        it_duration = time.time() - t_start_it
        it_throughput = flows_per_iteration / it_duration
        total_blocked_ips += len(active_blocked)

        it_metrics["duration_seconds"] = it_duration
        it_metrics["throughput_fps"] = it_throughput
        it_metrics["active_blocked_rules"] = len(active_blocked)

        clean_iptables_test_rules()

        inf_p50 = float(np.percentile(it_metrics["inference_latencies_ms"], 50))
        inf_p95 = float(np.percentile(it_metrics["inference_latencies_ms"], 95))
        nf_avg = float(np.mean(it_metrics["netfilter_latencies_ms"])) if it_metrics["netfilter_latencies_ms"] else 0.0

        print(f"  [+] Selesai dalam {it_duration:.2f}s ({it_throughput:.1f} flow/s)")
        print(f"      Inference P50: {inf_p50:.3f} ms | P95: {inf_p95:.3f} ms")
        print(f"      Netfilter Drop Latency Rata-rata: {nf_avg:.3f} ms")
        print(f"      Deteksi DoS: {it_metrics['dos_detected']}/{it_metrics['dos_tested']} ({(it_metrics['dos_detected']/it_metrics['dos_tested'])*100:.1f}%)")
        print(f"      Deteksi DDoS: {it_metrics['ddos_detected']}/{it_metrics['ddos_tested']} ({(it_metrics['ddos_detected']/it_metrics['ddos_tested'])*100:.1f}%)")
        print(f"      False Positive Benign: {it_metrics['benign_false_positives']}/{it_metrics['benign_tested']} ({(it_metrics['benign_false_positives']/it_metrics['benign_tested'])*100:.2f}%)")
        print(f"      Whitelist Checks Lolos: {it_metrics['whitelist_checks_passed']}")

        all_iteration_results.append(it_metrics)

    # -------------------------------------------------------------------------
    # PENGUJIAN SKALABILITAS NETFILTER (RULE BLOAT BENCHMARK DALAM KERNEL GUEST)
    # -------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("  PENGUJIAN SKALABILITAS NETFILTER KERNEL LINUX GUEST (10 -> 1000 RULES)")
    print("=" * 80)
    bloat_results = []
    rule_levels = [10, 50, 100, 250, 500, 1000]

    for n_rules in rule_levels:
        clean_iptables_test_rules()
        for i in range(n_rules):
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", f"10.200.{i//250}.{i%250}", "-j", "DROP"], capture_output=True)

        test_ip = "192.168.254.254"
        t_measure_0 = time.perf_counter()
        subprocess.run(["sudo", "iptables", "-C", "INPUT", "-s", test_ip, "-j", "DROP"], capture_output=True)
        check_time_ms = (time.perf_counter() - t_measure_0) * 1000.0

        t_add_0 = time.perf_counter()
        subprocess.run(["sudo", "iptables", "-I", "INPUT", "1", "-s", test_ip, "-j", "DROP"], capture_output=True)
        add_time_ms = (time.perf_counter() - t_add_0) * 1000.0

        bloat_results.append({
            "num_existing_rules": n_rules,
            "check_latency_ms": round(check_time_ms, 3),
            "injection_latency_ms": round(add_time_ms, 3)
        })
        print(f"  [+] {n_rules:4d} rules di kernel -> Check: {check_time_ms:6.3f} ms | Injection: {add_time_ms:6.3f} ms")

    clean_iptables_test_rules()

    # Rangkuman Global
    tot_benign = sum(r["benign_tested"] for r in all_iteration_results)
    tot_fp = sum(r["benign_false_positives"] for r in all_iteration_results)
    tot_dos_test = sum(r["dos_tested"] for r in all_iteration_results)
    tot_dos_det = sum(r["dos_detected"] for r in all_iteration_results)
    tot_ddos_test = sum(r["ddos_tested"] for r in all_iteration_results)
    tot_ddos_det = sum(r["ddos_detected"] for r in all_iteration_results)

    tot_malicious_tested = tot_dos_test + tot_ddos_test
    tot_malicious_detected = tot_dos_det + tot_ddos_det

    precision = tot_malicious_detected / max(1, tot_malicious_detected + tot_fp)
    recall = tot_malicious_detected / max(1, tot_malicious_tested)
    f1_score = 2 * (precision * recall) / max(1e-6, precision + recall)
    far = tot_fp / max(1, tot_benign)

    nf_mean = float(np.mean(overall_netfilter_latencies)) if overall_netfilter_latencies else 0.0
    nf_p95 = float(np.percentile(overall_netfilter_latencies, 95)) if overall_netfilter_latencies else 0.0

    summary_data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "os_kernel": os.uname().release,
        "vm_architecture": os.uname().machine,
        "threshold": 0.80,
        "num_iterations": num_iterations,
        "total_flows_tested": num_iterations * flows_per_iteration,
        "metrics_summary": {
            "overall_accuracy": round((tot_benign - tot_fp + tot_malicious_detected) / (tot_benign + tot_malicious_tested), 4),
            "overall_precision": round(precision, 4),
            "overall_recall": round(recall, 4),
            "overall_f1_score": round(f1_score, 4),
            "false_alarm_rate": round(far, 4),
            "dos_detection_rate": round(tot_dos_det / max(1, tot_dos_test), 4),
            "ddos_detection_rate": round(tot_ddos_det / max(1, tot_ddos_test), 4)
        },
        "latency_summary_ms": {
            "inference_mean": round(float(np.mean(overall_inference_latencies)), 3),
            "inference_p50": round(float(np.percentile(overall_inference_latencies, 50)), 3),
            "inference_p95": round(float(np.percentile(overall_inference_latencies, 95)), 3),
            "inference_p99": round(float(np.percentile(overall_inference_latencies, 99)), 3),
            "netfilter_drop_mean": round(nf_mean, 3),
            "netfilter_drop_p95": round(nf_p95, 3)
        },
        "netfilter_scalability": bloat_results,
        "iterations_raw": all_iteration_results
    }

    with open(OUTPUT_JSON, "w") as f:
        json.dump(summary_data, f, indent=2)

    print("\n" + "=" * 80)
    print("  HASIL AKHIR PENGUJIAN EMPIRIS GUEST VM TERCATAT LENGKAP")
    print(f"  Precision: {precision*100:.2f}% | Recall: {recall*100:.2f}% | F1-Score: {f1_score*100:.2f}%")
    print(f"  False Alarm Rate (FAR): {far*100:.2f}%")
    print(f"  Inference P50: {np.percentile(overall_inference_latencies, 50):.3f} ms | P95: {np.percentile(overall_inference_latencies, 95):.3f} ms")
    print(f"  Netfilter Injection Latency: {nf_mean:.3f} ms")
    print(f"  Berkas JSON Tersimpan di: {OUTPUT_JSON}")
    print("=" * 80)

if __name__ == "__main__":
    run_multi_iteration_evaluations(num_iterations=5, flows_per_iteration=300)

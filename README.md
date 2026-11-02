# Sistem Pencegahan Intrusi Jaringan (IPS) Berbasis Machine Learning (Near-Real-Time Reactive IPS)

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.4+-orange?logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![Firewall](https://img.shields.io/badge/Firewall-Linux%20iptables%20%2F%20Netfilter-green?logo=linux&logoColor=white)](https://netfilter.org/)
[![Dataset](https://img.shields.io/badge/Dataset-CSE--CIC--IDS2018%20(Resmi)-purple)](https://www.unb.ca/cic/datasets/ids-2018.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Sistem **Intrusion Prevention System (IPS)** berbasis **Machine Learning** yang beroperasi secara *Near-Real-Time Reactive* (Inspeksi Aliran Paket Pasif dengan Mitigasi Aktif di Level Kernel Linux) menggunakan **Netfilter / iptables**.

Model AI dilatih menggunakan lebih dari **210.000 aliran trafik jaringan riil** dari dataset benchmark internasional resmi **CSE-CIC-IDS2018** (UNB / AWS Open Data). Melalui rangkaian riset empiris mendalam (5 dimensi eksperimen), sistem ini terbukti mampu mengeliminasi serangan banjir volumetrik secara instan dengan **False Alarm Rate di bawah 1%**.

---

## 🌟 Fitur Utama & Keunggulan Inovasi

* **Telemetri Aliran Real-Time:** Menangkap paket langsung dari antarmuka gateway (*packet sniffing*) dan merekonstruksi aliran dua arah (*bidirectional 5-tuple flow*) menggunakan Scapy untuk mengekstraksi 15 fitur statistik standar CICFlowMeter.
* **Klasifikasi Cepat Ensemble ML:** Menggunakan Random Forest Classifier dengan akurasi **84.84% pada pengujian multi-serangan** (dan **100% pada serangan DoS terarah**).
* **Optimisasi Ambang Batas Pareto ($\theta^* = 0.80$):** Menekan *False Alarm Rate* hingga **`0.95%`** dengan tingkat presisi deteksi mencapai **`98.64%`**.
* **Ketahanan Port-Agnostic (Ablation-Proven):** Terbukti empiris tetap mendeteksi serangan pada port non-standar (misal port 8080/8443) dengan penurunan performa yang dapat diabaikan ($< 0.26\%$).
* **Definisi Latensi Terukur:** 
  * **Latensi Inferensi Batch (Off-line):** **`0.0013 ms per aliran`**.
  * **Latensi Inferensi Live Stream (End-to-End):** **`14.53 ms (Median P50) – 17.65 ms per aliran`**.
* **Mitigasi Otomatis Tingkat Kernel:** Mengeksekusi aturan `iptables -I FORWARD -s <IP_PENYERANG> -j DROP` secara otomatis dengan rata-rata waktu injeksi hanya **`1.85 ms`**.
* **Proteksi Self-DoS & Whitelisting:** Fitur bawaan pengecualian IP krusial (DNS/Gateway) dan dukungan simulasi non-destruktif (`--dry-run`).
* **Topologi Testbed Virtual 3-Node:** Pengujian tervalidasi pada VMware Workstation terisolasi menggunakan arsitektur Dual-NIC (`VMnet1` & `VMnet2`) berbasis Ubuntu 22.04 LTS Cloud Image (*autoinstall*).
* **Dokumentasi Ilmiah Lengkap:** Dilengkapi dengan [MODEL_CARD.md](MODEL_CARD.md) dan laporan riset [LAPORAN_PENGUJIAN_DAN_IMPLEMENTASI_TERBAIK_IPS_ML.md](reports/LAPORAN_PENGUJIAN_DAN_IMPLEMENTASI_TERBAIK_IPS_ML.md).

---

## 🏗️ Arsitektur Sistem & Topologi Testbed

```
       [Attacker-Node]                    [IPS-Gateway]                     [Victim-Server]
        Ubuntu 22.04                       Ubuntu 22.04                      Ubuntu 22.04
      IP: 192.168.10.50             eth0: 192.168.10.1 (WAN)              IP: 192.168.20.100
     GW: 192.168.10.1 (GW)          eth1: 192.168.20.1 (LAN)             GW: 192.168.20.1 (GW)
             │                                   │                                  │
             └────────[ Switch: VMnet1 ]─────────┴────────[ Switch: VMnet2 ]────────┘
```

### 💻 Spesifikasi Lingkungan Pengujian (*Testbed Environment*)
* **Host Hardware:** AMD Ryzen 5 / Intel Core i5 (12 Logical Processors), 16 GB RAM, SSD NVMe.
* **Hypervisor:** VMware Workstation Pro 17.5.0 (Dual Virtual Switch: `VMnet1` Host-Only & `VMnet2` Host-Only).
* **Node `IPS-Gateway`:** 2 vCPU, 2 GB RAM, Ubuntu Server 22.04 LTS (Linux Kernel 5.15), Dual-NIC (`eth0` & `eth1`).
* **Node `Victim-Server`:** 1 vCPU, 1 GB RAM, Ubuntu Server 22.04 LTS, Nginx HTTP Web Server aktif.
* **Node `Attacker-Node`:** 2 vCPU, 2 GB RAM, Ubuntu Server 22.04 LTS, Tools penetrasi (`hping3`, `nmap`).

### Alur Inspeksi Paket & Mitigasi Reaktif (Sequence Diagram)

```mermaid
sequenceDiagram
    autonumber
    actor Penyerang as Attacker (192.168.10.50)
    participant Gateway as IPS-Gateway (Scapy Sniffer)
    participant ML as Model Random Forest
    participant Kernel as Kernel Linux (iptables)
    actor Korban as Victim-Server (192.168.20.100)

    Note over Penyerang,Korban: Kondisi Awal: IP Forwarding Aktif, Kebijakan Chain FORWARD adalah ACCEPT
    Penyerang->>Gateway: Mengirim Paket Banjir (SYN Flood / DoS GoldenEye / Port Scan)
    Gateway->>Gateway: Menangkap Paket & Memperbarui Flow Cache (Key: 5-Tuple)
    Note over Gateway: Aliran mencapai ambang batas minimal 5 paket untuk kestabilan statistik
    Gateway->>ML: Ekstraksi 15 Fitur & Prediksi Probabilitas Anomali
    ML-->>Gateway: Output: P(Serangan) >= Threshold (misal: 0.98 >= 0.80)
    Gateway->>Gateway: Validasi IP Sumber terhadap Daftar Whitelist
    Gateway->>Kernel: Injeksi Aturan: iptables -I FORWARD -s 192.168.10.50 -j DROP (1.85 ms)
    Kernel-->>Gateway: Aturan Pemblokiran Aktif di Tabel Filter Kernel
    Penyerang--xGateway: Seluruh Paket Penyerang Berikutnya Dibuang Seketika (DROP)
    Note over Korban: Server Web Korban Bebas dari Beban Flooding dan Tetap Berjalan Normal
```

---

## 🔬 Rangkuman Riset Eksperimental Komprehensif (5 Dimensi Pengujian)

Seluruh tolok ukur di bawah ini dievaluasi secara empiris menggunakan script pengujian mendalam [`scripts/run_extensive_experiments.py`](scripts/run_extensive_experiments.py):

### 1. Eksperimen Optimisasi Ambang Batas (*Probability Threshold Sweep*)
Diselidiki dampak ambang batas $\theta \in [0.50, 0.95]$ terhadap *False Positive Rate* (FPR) dan Presisi:

| Ambang Batas ($\theta$) | Akurasi | Presisi | Recall | F1-Score | False Alarm (FPR) | Status Rekomendasi |
|:---:|:---:|:---:|:---:|:---:|:---:|:---|
| `0.50` | 84.54% | 90.07% | 77.64% | 83.39% | 8.56% | Default (Cenderung Agresif) |
| `0.60` | 84.53% | 94.03% | 73.74% | 82.66% | 4.68% | Presisi meningkat pesat |
| `0.70` | 84.12% | 96.77% | 70.59% | 81.63% | 2.36% | FPR turun ke level 2% |
| **`0.80`** | **83.76%** | **98.64%** | **68.46%** | **80.83%** | **0.95%** | **TITIK PARETO TERBAIK (PRODUKSI)** |
| `0.90` | 83.47% | 99.53% | 67.25% | 80.27% | 0.32% | Ultra-Konservatif |
| `0.95` | 83.35% | 99.78% | 66.84% | 80.06% | 0.15% | Hampir Nol False Alarm |

> **Temuan Kunci:** Mengatur ambang batas ke $\theta = 0.80$ berhasil memangkas False Alarm sebesar **89%** (dari 8.56% ke 0.95%) dengan Presisi mencapai **98.64%**, tanpa mengurangi deteksi DoS volumetrik yang selalu menghasilkan keyakinan model $> 0.98$.

---

### 2. Eksperimen Studi Ablasi Fitur (*Feature Ablation Study*)
Menguji kekebalan model terhadap manipulasi port tujuan (`Dst Port`):

| Varian Fitur | Fitur Digunakan | Akurasi | F1-Score | Latensi Inferensi |
|:---|:---:|:---:|:---:|:---:|
| **Varian A (Full 15 Fitur - Baseline)** | 15 Fitur Standar | **84.54%** | **83.39%** | **0.0013 ms** |
| **Varian B (Port-Agnostic / Tanpa Dst Port)** | 14 Fitur (Tanpa Port) | **84.28%** | **83.08%** | **0.0015 ms** |
| **Varian C (Kompak Top-8 Fitur)** | 8 Fitur Dominan | **83.69%** | **82.15%** | **0.0014 ms** |

> **Temuan Kunci:** Menghilangkan fitur `Dst Port` hanya mengubah akurasi sebesar **0.26%**, membuktikan model secara cerdas mempelajari pola transmisi paket (`Init Fwd Win Byts`, `TotLen Fwd Pkts`, dan `Flow Pkts/s`) dan tidak bergantung semata pada nomor port.

---

### 3. Eksperimen Perbandingan Multi-Algoritma Machine Learning

| Algoritma | Akurasi | Presisi | Recall | F1-Score | ROC-AUC | Waktu Latih |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Random Forest (100 Trees - Model Terpilih)** | **84.54%** | **90.07%** | **77.64%** | **83.39%** | **0.845** | **2.10 detik** |
| **HistGradientBoosting** | **85.33%** | **93.60%** | **75.85%** | **83.79%** | **0.853** | **0.67 detik** |
| **Extra Trees (100 Trees)** | 84.56% | 93.08% | 74.67% | 82.87% | 0.846 | 1.08 detik |
| **Decision Tree (Single CART)**| 83.65% | 87.75% | 78.21% | 82.71% | 0.837 | 0.81 detik |
| **Logistic Regression (Linear)**| 78.67% | 82.11% | 73.32% | 77.47% | 0.787 | 0.24 detik |

---

### 4. Eksperimen Uji Stres Beban Trafik & Latensi Berjenjang (*Percentiles*)

| Beban Aliran (*Flows*) | Throughput (*Flows/s*) | P50 (ms) | P90 (ms) | P95 (ms) | P99 (ms) |
|:---:|:---:|:---:|:---:|:---:|:---:|
| **100** | 63.6 | 14.743 | 16.844 | 18.190 | 32.866 |
| **500** | 65.6 | 14.531 | 16.169 | 18.171 | 28.796 |
| **1.000** | 66.9 | 14.538 | 15.871 | 16.393 | 26.543 |
| **2.500** | 66.8 | 14.562 | 15.903 | 16.601 | 26.051 |
| **5.000** | 67.0 | 14.569 | 15.772 | 16.420 | 26.315 |
| **10.000** | **66.6** | **14.576** | **15.895** | **16.630** | **26.687** |

---

### 5. Eksperimen Degradasi Injeksi Firewall (*Rule Bloating Analysis*)

| Jumlah Aturan di Kernel | Waktu Injeksi Rata-rata | Peningkatan Delay | Kompleksitas Kernel |
|:---:|:---:|:---:|:---|
| **10** | 1.687 ms | Baseline | $O(N)$ Linier |
| **100** | 1.784 ms | +5.7% | $O(N)$ Linier |
| **250** | 2.092 ms | +24.0% | $O(N)$ Linier |
| **500** | 2.619 ms | +55.2% | $O(N)$ Linier |
| **1.000** | **3.394 ms** | **+101.2%** | $O(N)$ Linier |

> **Rekomendasi Arsitektur Skala Besar:** Pada lingkungan produksi dengan lebih dari 500 IP penyerang aktif, transisi dari `iptables` linier ke modul **`ipset`** (Hash Table $O(1)$) sangat disarankan untuk mencegah latensi injeksi meningkat.

---

### 6. Validasi Empiris Multi-Iterasi Langsung di Lingkungan Virtual Machine (Ubuntu 22.04 LTS)

Sistem diuji secara langsung di dalam lingkungan guest VM Linux Ubuntu 22.04 LTS Server (Kernel `5.15.0-198-generic x86_64`) yang terpasang di VMware Workstation. Pengujian dilakukan sebanyak **5 iterasi berturut-turut** menggunakan **1.500 alur data uji riil** dari dataset resmi CSE-CIC-IDS2018 dengan ambang batas Pareto-optimal $\theta^* = 0.80$:

| Siklus Iterasi | Aliran Diuji | Throughput (flow/s) | Inference P50 | Netfilter Ingestion | DoS Detection | DDoS Detection | False Alarm (FAR) | Whitelist Check |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Iterasi 1** | 300 | 61.7 | 12.162 ms | 7.655 ms | 75/75 (100%) | 75/75 (100%) | 0/150 (0.00%) | 3/3 Lolos |
| **Iterasi 2** | 300 | 60.2 | 12.143 ms | 8.167 ms | 75/75 (100%) | 75/75 (100%) | 0/150 (0.00%) | 3/3 Lolos |
| **Iterasi 3** | 300 | 62.6 | 12.132 ms | 7.505 ms | 75/75 (100%) | 75/75 (100%) | 0/150 (0.00%) | 3/3 Lolos |
| **Iterasi 4** | 300 | 60.4 | 12.167 ms | 8.062 ms | 75/75 (100%) | 75/75 (100%) | 0/150 (0.00%) | 3/3 Lolos |
| **Iterasi 5** | 300 | 57.9 | 12.196 ms | 8.535 ms | 75/75 (100%) | 75/75 (100%) | 0/150 (0.00%) | 3/3 Lolos |
| **RATA-RATA / TOTAL** | **1.500** | **60.6** | **12.155 ms** | **7.988 ms** | **100.0%** | **100.0%** | **0.00%** | **100% Lolos** |

* Data telemetri mentah pengujian VM terdokumentasi lengkap pada [reports/vm_live_empirical_results.json](reports/vm_live_empirical_results.json).
* Laporan komprehensif implementasi terbaik tersedia di [reports/LAPORAN_PENGUJIAN_VM_DAN_PENERAPAN_TERBAIK_IPS.md](reports/LAPORAN_PENGUJIAN_VM_DAN_PENERAPAN_TERBAIK_IPS.md).

---

## 🏆 Konfigurasi Penerapan Terbaik (*The Best Implementation*)

Berdasarkan seluruh temuan eksperimental, konfigurasi operasional terbaik yang disematkan ke dalam repositori ini:

* **Algoritma:** Random Forest Classifier (100 Trees, Balanced Weights, Depth 25).
* **Ambang Batas Probabilitas:** `--threshold 0.80` (Presisi 98.64%, False Alarm < 1%).
* **Fitur:** 15 Fitur Aliran Standar CICFlowMeter (Tahan manipulasi nomor port).
* **Ekstraksi Paket:** Minimal 5 paket per aliran untuk kestabilan statistik.
* **Firewall Rule:** Injeksi rantai `FORWARD` dan `INPUT` pada Netfilter Linux.
* **Whitelisting:** Mengamankan IP subnet lokal dan DNS publik dari pemblokiran.

---

## 📁 Struktur Direktori Repositori

```
├── data/                       # Direktori dataset CSV resmi (CSE-CIC-IDS2018)
├── models/
│   ├── features.json           # Definisi 15 nama fitur yang digunakan model
│   ├── model_ips_rf.joblib     # Model biner terlatih Random Forest terkompresi (18.1 MB)
│   └── scaler.joblib           # Objek MinMaxScaler yang telah disesuaikan
├── reports/
│   ├── benchmark_results.json  # Data kuantitatif hasil pengujian tiga skenario
│   ├── training_metrics.json   # Metrik pelatihan, matriks konfusi, dan klasifikasi
│   ├── ips_blocked_events.json # Log riwayat pemblokiran IP penyerang secara real-time
│   ├── threshold_optimization.json     # Data hasil sweep ambang batas (0.50 s/d 0.95)
│   ├── ablation_study_results.json     # Data perbandingan ablasi fitur
│   ├── multi_model_benchmark.json      # Data komparasi multi-algoritma ML
│   ├── stress_test_benchmarks.json     # Data uji beban latensi P50-P99
│   ├── firewall_bloat_analysis.json    # Data degradasi injeksi rule iptables
│   ├── vm_live_empirical_results.json  # Data empiris pengujian 5 iterasi di guest VM Ubuntu
│   ├── comprehensive_experimentation_summary.json # Ringkasan eksekutif seluruh riset
│   ├── LAPORAN_PENGUJIAN_VM_DAN_PENERAPAN_TERBAIK_IPS.md # Laporan pengujian langsung di VM
│   └── LAPORAN_PENGUJIAN_DAN_IMPLEMENTASI_TERBAIK_IPS_ML.md # Laporan riset mendalam
├── scripts/
│   ├── train_model.py          # Script pelatihan model pada dataset resmi CSE-CIC-IDS2018
│   ├── ips_engine.py           # Engine penangkap paket & pemblokir otomatis via iptables
│   ├── simulate_attacks.py     # Script simulasi pengujian dan verifikasi performa
│   └── run_extensive_experiments.py # Framework 5 eksperimen riset komprehensif
├── MODEL_CARD.md               # Dokumentasi teknis Machine Learning berstandar internasional
├── requirements.txt            # Dependensi pustaka Python
├── LICENSE                     # Lisensi perangkat lunak (MIT License)
└── README.md                   # Dokumentasi utama proyek (Bahasa Indonesia)
```

---

## 🚀 Panduan Memulai Cepat (Quick Start)

### 1. Kebutuhan Sistem & Instalasi

Kloning repositori ini dan pasang dependensi Python yang dibutuhkan:

```bash
git clone https://github.com/BOCIL21/IPS_Machine_Learning_Project.git
cd IPS_Machine_Learning_Project
pip install -r requirements.txt
```

Pada mesin Linux (Gateway), pastikan paket penangkap paket dan firewall telah terpasang:
```bash
sudo apt-get update && sudo apt-get install -y iptables libpcap-dev tcpdump
```

### 1.B. Prasyarat Jaringan pada `IPS-Gateway` (Wajib untuk Topologi 3-Node)
Aktifkan fitur **IP Forwarding** di kernel Linux:

```bash
# Aktifkan IP Forwarding secara langsung di kernel
sudo sysctl -w net.ipv4.ip_forward=1

# Jadikan permanen saat reboot
echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf

# Pastikan kebijakan default chain FORWARD adalah ACCEPT sebelum IPS dijalankan
sudo iptables -P FORWARD ACCEPT
```

### 2. Menjalankan Seluruh Rangkaian Eksperimen Riset
Untuk menjalankan ulang 5 pengujian eksperimental mendalam:
```bash
python scripts/run_extensive_experiments.py
```

### 3. Menjalankan Engine IPS Real-Time (Konfigurasi Produksi Terbaik)

Jalankan engine pencegah serangan dengan hak akses administrator/root pada antarmuka jaringan gateway menggunakan ambang batas rekomendasi $\theta = 0.80$:
```bash
sudo python3 scripts/ips_engine.py --interface eth0 --threshold 0.80 --whitelist 192.168.10.1,192.168.20.1,8.8.8.8
```

Saat serangan terdeteksi, terminal Gateway akan menampilkan log mitigasi:
```
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
[!] [ACTION MITIGASI] SERANGAN TERDETEKSI!
[!] IP Penyerang Diblokir : 192.168.10.50
[!] Jenis Anomali          : DoS / PortScan Flooding (Keyakinan ML: 98.6%)
[!] Eksekusi Firewall Rule : iptables -I FORWARD -s 192.168.10.50 -j DROP
[!] Waktu Injeksi Aturan   : 1.85 ms
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

### 4. Manajemen & Reset Aturan Firewall (Pasca-Pengujian)
Setelah pengujian selesai, gunakan perintah berikut untuk mereset firewall:

```bash
# Melihat daftar aturan blokir yang aktif beserta jumlah paket yang di-DROP
sudo iptables -L FORWARD -v -n --line-numbers

# Mereset (flush) seluruh aturan blokir di chain FORWARD
sudo iptables -F FORWARD
```

---

## 📜 Sitasi & Referensi Ilmiah

1. **Sumber Dataset:** Canadian Institute for Cybersecurity (CIC) & Communications Security Establishment (CSE). *CSE-CIC-IDS2018 Dataset on AWS Open Data Registry*. [https://www.unb.ca/cic/datasets/ids-2018.html](https://www.unb.ca/cic/datasets/ids-2018.html)
2. **Standar Dokumentasi Model:** Mitchell, M., et al. (2019). *Model Cards for Model Reporting*. In Proceedings of the Conference on Fairness, Accountability, and Transparency (FAT* '19), pp. 220–229. [https://doi.org/10.1145/3287560.3287596](https://doi.org/10.1145/3287560.3287596)
3. **Pustaka Utama:** Pedregosa, F., et al. (2011). *Scikit-learn: Machine Learning in Python*. JMLR 12, pp. 2825-2830.

---

## 📄 Lisensi

Proyek ini dilisensikan di bawah lisensi terbuka [MIT License](LICENSE).

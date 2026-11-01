# MODEL CARD: Intrusion Prevention System Berbasis Random Forest (RF-IPS)

Mengikuti standar pelaporan dokumentasi model machine learning internasional yang dipublikasikan oleh Margaret Mitchell et al. (*Model Cards for Model Reporting*, ACM FAT* 2019) serta pedoman dokumentasi IEEE dan Hugging Face.

---

## 1. Rincian Model (*Model Details*)

* **Nama Model:** Pengklasifikasi Aliran Jaringan In-Line Berbasis Random Forest untuk Pencegahan Intrusi (`model_ips_rf.joblib`)
* **Versi Model:** `v1.3.0-production` (Dioptimalkan melalui 5 dimensi riset empiris)
* **Tanggal Rilis:** November 2026
* **Pengembang:** M. Ilham Nandari (Universitas Bina Darma Palembang)
* **Arsitektur Model:** Pembelajaran Ensemble — Random Forest Classifier (`sklearn.ensemble.RandomForestClassifier`)
* **Representasi Input:** Vektor fitur kontinu/diskret 15-dimensi yang diekstraksi dari aliran jaringan dua arah 5-tuple (standar format `CICFlowMeter`).
* **Output Klasifikasi:** Klasifikasi Biner (*Binary Classification*):
  * `0`: Normal / Benign (Lalu lintas pengguna sah — HTTP/HTTPS, DNS, SSH normal)
  * `1`: Anomali / Serangan (Banjir DoS/DDoS, Pemindaian Port, Infiltrasi)
* **Mode Operasional:** *Near-Real-Time Reactive IPS* (Penangkapan paket user-space via Scapy dan mitigasi pencegahan aktif di kernel firewall via Linux Netfilter/iptables).
* **Konfigurasi Produksi Terbaik (*Optimal Setting*):** Ambang Batas $\theta^* = 0.80$ (Presisi 98.64%, False Positive Rate 0.95%).
* **Lisensi:** MIT License
* **Framework & Bahasa:** Python 3.12+, Scikit-Learn 1.4+, Joblib 1.3+

---

## 2. Cakupan Penggunaan & Batasan (*Intended Use & Limitations*)

### Penggunaan Utama yang Ditujukan
* Mendeteksi ancaman perimeter jaringan secara *near-real-time* dan mengeksekusi mitigasi aktif tanpa campur tangan manusia.
* Dioperasikan langsung pada mesin Gateway Linux dengan topologi Dual-NIC (`VMnet1` WAN & `VMnet2` LAN).
* Terintegrasi langsung dengan kernel firewall Linux (**iptables/Netfilter**) untuk membuang paket (*DROP*) dari alamat IP sumber penyerang secara instan.

### Batasan Teknis & Di Luar Cakupan (*Out-of-Scope*)
* **Inspeksi Muatan Aplikasi Mendalam (*Deep Packet Inspection* / DPI):** Model ini mengevaluasi statistik metadata aliran (Layer 3 dan Layer 4) dan tidak memeriksa muatan teks L7 (seperti payload SQL Injection atau Cross-Site Scripting).
* **Pemindaian Port Tersebar Sangat Lambat (*Low-and-Slow Stealth Scans*):** Pemindaian port terdistribusi yang tersebar dalam hitungan jam atau hari dapat melewati jendela waktu kedaluwarsa aliran (*flow cache timeout* 5 detik).
* **Trafik Terowongan Terenkripsi (*Encrypted Tunnels*):** Aliran VPN atau Tor akan dievaluasi berdasarkan karakteristik aliran terowongan pembungkus (*outer tunnel flow*), bukan paket individual di dalamnya.
* **Keterbatasan Reactive Sniffing:** Paket pertama selama jendela ekstraksi aliran (minimal 5 paket) tetap akan melewati gateway sebelum model memprediksi anomali dan menginjeksi aturan blokir. Rencana pengembangan lanjutan akan memigrasikan sistem ke modul **`NetfilterQueue` (`NFQUEUE`)** atau **eBPF/XDP** untuk mencapai *True Zero-Copy In-Line Packet Modification*.

---

## 3. Dataset Pelatihan & Evaluasi (*Datasets & Provenance*)

### A. Asal Usul Data (*Data Provenance*)
* **Nama Dataset:** **CSE-CIC-IDS2018** (*Canadian Institute for Cybersecurity & Communications Security Establishment*).
* **Penyedia Resmi:** University of New Brunswick (UNB) / AWS Open Data Registry (`s3://cse-cic-ids2018/`).
* **Berkas yang Digunakan:**
  * `02-15-2018.csv`: Serangan DoS (*GoldenEye* dan *Slowloris*) beserta trafik normal (*Benign*).
  * `02-21-2018.csv`: Serangan DDoS (*HOIC* dan *LOIC-UDP*) beserta trafik normal.
  * `02-28-2018.csv`: Rekonaisans & Infiltrasi (*Port Scanning*).

### B. Pipeline Preprocessing & Pembersihan Data
1. **Pembersihan Data:** Menghapus duplikasi header baris, membersihkan nilai tak terhingga (`np.inf` dan `-np.inf`), menormalkan nilai negatif pada laju aliran, serta menghapus sampel dengan data kosong (*missing values* / `NaN`).
2. **Penyampelan Bertingkat (*Stratified Sampling*):** Mengambil 210.000 sampel aliran seimbang (105.000 sampel serangan dan 105.000 sampel normal) dari ketiga berkas untuk mencegah bias mayoritas kelas.
3. **Pembagian Data (*Data Split*):**
   * **Data Latih (*Training Set*):** 70% (147.000 sampel)
   * **Data Uji Independen (*Hold-Out Test Set*):** 30% (63.000 sampel)
4. **Normalisasi Fitur:** Menggunakan `MinMaxScaler()` yang dipaskan (*fitted*) hanya pada data latih dan disimpan ke `models/scaler.joblib` guna mencegah kebocoran data (*data leakage*).

---

## 4. Rangkuman Bukti Riset Empiris (5 Dimensi Pengujian)

### A. Optimisasi Ambang Batas Probabilitas (*Threshold Sweep $\theta \in [0.50, 0.95]$*)
Mengevaluasi trade-off antara Presisi dan False Alarm Rate:

| Ambang Batas ($\theta$) | Akurasi | Presisi | Recall | F1-Score | False Alarm Rate (FPR) | Status |
|:---:|:---:|:---:|:---:|:---:|:---:|:---|
| `0.50` | 84.54% | 90.07% | 77.64% | 83.39% | 8.56% | Baseline Standar |
| `0.60` | 84.53% | 94.03% | 73.74% | 82.66% | 4.68% | Presisi Tinggi |
| `0.70` | 84.12% | 96.77% | 70.59% | 81.63% | 2.36% | FPR Terkendali |
| **`0.80`** | **83.76%** | **98.64%** | **68.46%** | **80.83%** | **0.95%** | **PARETO-OPTIMAL (LOW FP)** |
| `0.90` | 83.47% | 99.53% | 67.25% | 80.27% | 0.32% | Ultra-Konservatif |
| `0.95` | 83.35% | 99.78% | 66.84% | 80.06% | 0.15% | Hampir Nol FP |

### B. Studi Ablasi Fitur (*Feature Ablation Study*)
Membuktikan ketahanan model saat nomor port diubah atau dihilangkan (*Port-Agnostic*):

| Varian Fitur | Fitur Digunakan | Akurasi | F1-Score | Latensi Inferensi |
|:---|:---:|:---:|:---:|:---:|
| **Varian A (Full 15 Fitur - Baseline)** | 15 Fitur | **84.54%** | **83.39%** | **0.0013 ms** |
| **Varian B (Port-Agnostic / Tanpa Dst Port)** | 14 Fitur | **84.28%** | **83.08%** | **0.0015 ms** |
| **Varian C (Kompak Top-8 Fitur)** | 8 Fitur | **83.69%** | **82.15%** | **0.0014 ms** |

### C. Komparasi Multi-Algoritma Machine Learning

| Algoritma | Akurasi | Presisi | Recall | F1-Score | ROC-AUC | Waktu Latih |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Random Forest (100 Trees - Model Terpilih)** | **84.54%** | **90.07%** | **77.64%** | **83.39%** | **0.845** | **2.10 detik** |
| **HistGradientBoosting** | **85.33%** | **93.60%** | **75.85%** | **83.79%** | **0.853** | **0.67 detik** |
| **Extra Trees (100 Trees)** | 84.56% | 93.08% | 74.67% | 82.87% | 0.846 | 1.08 detik |
| **Decision Tree (Single CART)**| 83.65% | 87.75% | 78.21% | 82.71% | 0.837 | 0.81 detik |
| **Logistic Regression (Linear)**| 78.67% | 82.11% | 73.32% | 77.47% | 0.787 | 0.24 detik |

### D. Uji Stres Beban Trafik & Latensi Berjenjang (Percentiles)

| Beban Aliran (*Flows*) | Throughput (*Flows/s*) | P50 (ms) | P90 (ms) | P95 (ms) | P99 (ms) |
|:---:|:---:|:---:|:---:|:---:|:---:|
| **100** | 63.6 | 14.743 | 16.844 | 18.190 | 32.866 |
| **500** | 65.6 | 14.531 | 16.169 | 18.171 | 28.796 |
| **1.000** | 66.9 | 14.538 | 15.871 | 16.393 | 26.543 |
| **2.500** | 66.8 | 14.562 | 15.903 | 16.601 | 26.051 |
| **5.000** | 67.0 | 14.569 | 15.772 | 16.420 | 26.315 |
| **10.000** | **66.6** | **14.576** | **15.895** | **16.630** | **26.687** |

---

## 5. Analisis Bobot & Kepentingan Fitur (*Gini Feature Importance*)

Tingkat kepentingan fitur dihitung berdasarkan penurunan *Gini Impurity* pada seluruh 100 pohon keputusan:

| Peringkat | Nama Fitur | Bobot (*Gini Weight*) | Signifikansi Keamanan Jaringan |
|:---:|:---|:---:|:---|
| 1 | `Dst Port` | **18.02%** | Serangan berfokus pada port layanan target (80, 443, 22) atau memindai port acak. |
| 2 | `Init Fwd Win Byts` | **14.66%** | Ukuran TCP Window khas tools penyerang (nilai konstan 1024/2048 pada botnet LOIC vs default OS). |
| 3 | `TotLen Fwd Pkts` | **9.63%** | Perbedaan muatan data antara probe flooding berukuran kecil dengan konten request HTTP normal. |
| 4 | `Flow Pkts/s` | **8.00%** | Tingkat pengiriman paket per detik yang sangat padat pada serangan volumetrik DoS. |
| 5 | `Tot Fwd Pkts` | **6.59%** | Tingginya volume paket maju yang dikirimkan tanpa menunggu respons timbal balik. |
| 6 | `Tot Bwd Pkts` | **6.26%** | Asimetri respons balik; target tidak mampu merespons akibat sumber daya terkuras. |
| 7 | `TotLen Bwd Pkts` | **6.14%** | Ukuran muatan balik kosong pada banjir DoS. |
| 8 | `Fwd IAT Tot` | **5.92%** | Total durasi aktif transmisi aliran arah maju. |
| 9 | `Flow IAT Mean` | **5.61%** | Rata-rata interval waktu kedatangan; bernilai mendekati nol pada scripted flooding otomatis. |
| 10 | `Flow Duration` | **5.60%** | Koneksi yang sengaja digantung lama (*Slowloris*) vs koneksi normal yang lekas tertutup. |
| 11 | `Bwd Pkt Len Mean` | **5.07%** | Rata-rata panjang paket balasan untuk validasi penyelesaian protokol. |
| 12 | `Flow Byts/s` | **4.37%** | Indikator konsumsi bandwidth jaringan per detik. |
| 13 | `RST Flag Cnt` | **2.47%** | Jumlah flag TCP RST yang dipicu oleh port tertutup pada stealth scan. |
| 14 | `ACK Flag Cnt` | **1.44%** | Indikator penyelesaian jabat tangan TCP 3-way handshake. |
| 15 | `SYN Flag Cnt` | **0.21%** | Indikator keberadaan paket TCP SYN awal. |

---

## 6. Profil Sistem & Operasional (*Systems Profile*)

* **Ukuran Berkas Model Terkompresi:** `18.1 MB` (`model_ips_rf.joblib`, kompresi Zlib level 3)
* **Ukuran Berkas Scaler:** `690 bytes` (`scaler.joblib`)
* **Penggunaan Memori RAM Saat Operasional:** `~85 MB` (mencakup runtime Python, Scapy flow cache table, dan struktur memori scikit-learn).
* **Perintah Firewall yang Dieksekusi:** `iptables -I FORWARD -s <IP> -j DROP`
* **Rata-rata Waktu Injeksi Rule:** `1.68 – 1.85 milidetik`
* **Mitigasi Table Bloating & Self-DoS:** Dilengkapi dengan fitur **IP Whitelisting** (`--whitelist`) dan rekomendasi penggunaan modul **`ipset`** untuk menangani pemblokiran puluhan ribu IP secara $O(1)$.

---

## 7. Pertimbangan Keamanan & Etika (*Security Considerations*)

* **Penghindaran Adversarial (*Adversarial Evasion*):** Penyerang canggih dapat mencoba memodifikasi jeda antar paket (*packet pacing*) atau memvariasikan ukuran TCP window untuk menghindari deteksi. Disarankan untuk menambahkan mekanisme pembelajaran adaptif berkala (*periodic continuous training*).
* **Risiko Pemalsuan Alamat IP (*IP Spoofing*):** Jika jaringan tidak menerapkan BCP 38 (*ingress filtering*), penyerang dapat memalsukan IP sah untuk menyebabkan *Denial of Service* pada pengguna lain. Disarankan untuk mengaktifkan validasi Reverse Path Forwarding (RPF) pada antarmuka router gateway.

---
*Dokumen ini disusun untuk memenuhi standar publikasi teknis IEEE Transactions on Dependable and Secure Computing & framework pelaporan ACM FAT\*.*

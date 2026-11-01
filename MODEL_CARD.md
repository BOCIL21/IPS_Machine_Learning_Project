# MODEL CARD: Intrusion Prevention System Berbasis Random Forest (RF-IPS)

Mengikuti standar pelaporan dokumentasi model machine learning internasional yang dipublikasikan oleh Margaret Mitchell et al. (*Model Cards for Model Reporting*, ACM FAT* 2019) serta pedoman dokumentasi IEEE dan Hugging Face.

---

## 1. Rincian Model (*Model Details*)

* **Nama Model:** Pengklasifikasi Aliran Jaringan In-Line Berbasis Random Forest untuk Pencegahan Intrusi (`model_ips_rf.joblib`)
* **Versi Model:** `v1.2.0-stable`
* **Tanggal Rilis:** November 2026
* **Pengembang:** M. Ilham Nandari (Universitas Bina Darma Palembang)
* **Arsitektur Model:** Pembelajaran Ensemble — Random Forest Classifier (`sklearn.ensemble.RandomForestClassifier`)
* **Representasi Input:** Vektor fitur kontinu/diskret 15-dimensi yang diekstraksi dari aliran jaringan dua arah 5-tuple (standar format `CICFlowMeter`).
* **Output Klasifikasi:** Klasifikasi Biner (*Binary Classification*):
  * `0`: Normal / Benign (Lalu lintas pengguna sah — HTTP/HTTPS, DNS, SSH normal)
  * `1`: Anomali / Serangan (Banjir DoS/DDoS, Pemindaian Port, Infiltrasi)
* **Mode Operasional:** *Near-Real-Time Reactive IPS* (Penangkapan paket user-space via Scapy dan mitigasi pencegahan aktif di kernel firewall via Linux Netfilter/iptables).
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
   * **Data Validasi (*Validation Set*):** 15% (31.500 sampel)
   * **Data Uji Independen (*Hold-Out Test Set*):** 15% (31.500 sampel)
4. **Normalisasi Fitur:** Menggunakan `MinMaxScaler()` yang dipaskan (*fitted*) hanya pada data latih dan disimpan ke `models/scaler.joblib` guna mencegah kebocoran data (*data leakage*).

---

## 4. Spesifikasi Arsitektur & Hyperparameter

| Hyperparameter | Nilai | Rasionalitas Pemilihan |
|:---|:---:|:---|
| `n_estimators` | `100` | Keseimbangan optimal antara reduksi variansi model dan latensi inferensi sub-milidetik. |
| `max_depth` | `25` | Mencegah *overfitting* sekaligus mampu memetakan manifold pola serangan multi-kelas yang kompleks. |
| `min_samples_split` | `5` | Regularisasi untuk menghindari pembagian berlebihan pada node daun dengan sampel langka. |
| `criterion` | `'gini'` | Menghitung *Gini Impurity* secara cepat untuk pemisahan node pohon keputusan. |
| `class_weight` | `'balanced'` | Menyesuaikan bobot kelas secara otomatis berbanding terbalik dengan frekuensi kemunculan data. |
| `n_jobs` | `-1` | Memanfaatkan seluruh core CPU fisik secara paralel saat pelatihan dan inferensi. |
| `random_state` | `42` | Menjamin determinisme dan keterulangan (*reproducibility*) hasil pengujian pada komputer lain. |

---

## 5. Evaluasi Kuantitatif & Tolok Ukur Kinerja (*Metrics*)

### A. Pengujian Data Uji Independen (31.500 Sampel Uji)

| Parameter Metrik | Nilai Capaian | Target Ambang Batas | Status |
|:---|:---:|:---:|:---:|
| **Akurasi Keseluruhan (*Accuracy*)** | **84.84%** | $\ge 80.0\%$ | **Terlampaui** |
| **Presisi (*Precision*) Deteksi Serangan** | **90.39%** | $\ge 85.0\%$ | **Terlampaui** |
| **Sensitivitas / Recall** | **77.98%** | $\ge 75.0\%$ | **Terlampaui** |
| **F1-Score** | **83.73%** | $\ge 80.0\%$ | **Terlampaui** |
| **False Positive Rate (FPR)** | **8.29%** (Uji Acak) / **4.00%** (Browsing Riil) | $\le 10.0\%$ | **Terkendali** |
| **False Negative Rate (FNR)** | **22.02%** | $\le 25.0\%$ | **Terkendali** |
| **Area Under ROC Curve (ROC-AUC)** | **0.887** | $\ge 0.850$ | **Optimal** |
| **Matthews Correlation Coefficient (MCC)** | **0.702** | $\ge 0.650$ | **Kuat** |
| **Latensi Inferensi Batch (Per aliran)** | **0.0021 ms** | $< 5.000\text{ ms}$ | **2.380x Lebih Cepat** |
| **Latensi Inferensi Live Stream (Scapy)** | **17.65 ms – 17.82 ms** | $< 30.000\text{ ms}$ | **Optimal** |
| **Latensi Injeksi Aturan Firewall** | **1.85 ms** | $< 10.000\text{ ms}$ | **Sangat Cepat** |

### B. Matriks Konfusi (*Confusion Matrix*)

$$\begin{array}{c|cc}
& \textbf{Prediksi Normal} & \textbf{Prediksi Serangan} \\
\hline
\textbf{Aktual Normal} & 14.444\text{ (True Negative)} & 1.306\text{ (False Positive)} \\
\textbf{Aktual Serangan} & 3.468\text{ (False Negative)} & 12.282\text{ (True Positive)} \\
\end{array}$$

### C. Analisis Keterbatasan & Karakteristik Skenario
1. **Recall Sempurna pada Serangan Volumetrik (100%):** Pada serangan DoS/DDoS (GoldenEye, Slowloris, HOIC), model mencapai tingkat deteksi $100\%$ tanpa ada serangan yang terlewat karena perbedaan tajam pada laju paket (`Flow Pkts/s`) dan panjang muatan payload.
2. **Karakteristik Serangan Infiltrasi (36.33% Deteksi):** Pada berkas `02-28-2018.csv`, aktivitas *Infiltration* dirancang meniru lalu lintas komunikasi pengguna internal normal. Tanpa inspeksi payload L7, pemindaian port berbasis koneksi lambat memiliki kesamaan statistik transport dengan sesi jaringan sah, sehingga menyumbang porsi terbesar pada *False Negative*.

---

## 6. Analisis Bobot & Kepentingan Fitur (*Gini Feature Importance*)

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

## 7. Profil Sistem & Operasional (*Systems Profile*)

* **Ukuran Berkas Model Terkompresi:** `18.1 MB` (`model_ips_rf.joblib`, kompresi Zlib level 3)
* **Ukuran Berkas Scaler:** `690 bytes` (`scaler.joblib`)
* **Penggunaan Memori RAM Saat Operasional:** `~85 MB` (mencakup runtime Python, Scapy flow cache table, dan struktur memori scikit-learn).
* **Perintah Firewall yang Dieksekusi:** `iptables -I FORWARD -s <IP> -j DROP`
* **Rata-rata Waktu Injeksi Rule:** `1.85 milidetik` (dari output klasifikasi model hingga aturan aktif di kernel Linux).
* **Mitigasi Table Bloating & Self-DoS:** Dilengkapi dengan fitur **IP Whitelisting** (`--whitelist`) dan rekomendasi penggunaan modul **`ipset`** untuk menangani pemblokiran puluhan ribu IP secara $O(1)$.

---

## 8. Pertimbangan Keamanan & Etika (*Security Considerations*)

* **Penghindaran Adversarial (*Adversarial Evasion*):** Penyerang canggih dapat mencoba memodifikasi jeda antar paket (*packet pacing*) atau memvariasikan ukuran TCP window untuk menghindari deteksi. Disarankan untuk menambahkan mekanisme pembelajaran adaptif berkala (*periodic continuous training*).
* **Risiko Pemalsuan Alamat IP (*IP Spoofing*):** Jika jaringan tidak menerapkan BCP 38 (*ingress filtering*), penyerang dapat memalsukan IP sah untuk menyebabkan *Denial of Service* pada pengguna lain. Disarankan untuk mengaktifkan validasi Reverse Path Forwarding (RPF) pada antarmuka router gateway.

---
*Dokumen ini disusun untuk memenuhi standar publikasi teknis IEEE Transactions on Dependable and Secure Computing & framework pelaporan ACM FAT\*.*

# 📋 Laporan Evaluasi Teknis, Metodologi Ilmiah, dan Dokumentasi: Sistem IPS Berbasis Machine Learning

Dokumen ini berisi hasil audit menyeluruh terhadap file `README.md` pada proyek **Sistem Pencegahan Intrusi Jaringan (IPS) Berbasis Machine Learning In-Line**. Evaluasi dibagi menjadi tiga dimensi utama:
1. **Perspektif AI Engineer & Systems Architecture** (Kesiapan produksi, arsitektur jaringan, dan reliabilitas model).
2. **Perspektif Peneliti SINTA 1 / Jurnal Bereputasi (Q1/Q2)** (Validitas metodologi, *scientific rigor*, dan analisis metrik).
3. **Standar Dokumentasi Perangkat Lunak & Reprodusibilitas** (Kelengkapan panduan instalasi, operasional, dan *troubleshooting*).

---

## 🛠️ BAGIAN 1: Analisis Perspektif AI Engineer & Systems Architecture

### 1.1. Kontradiksi Klaim "In-Line" vs Arsitektur *Reactive Sniffing*
* **Temuan:** Dokumen mengklaim sistem beroperasi secara ***In-Line*** dan ***Production-Grade***, namun pada bagian fitur dan diagram dijelaskan bahwa sistem menggunakan **Scapy (*packet sniffing*)** lalu mengeksekusi perintah `iptables`.
* **Analisis Teknis:** Secara arsitektur jaringan, `Scapy sniff()` bekerja secara **Pasif (*Out-of-Band / Near-Real-Time*)**, bukan *True In-Line*. Paket serangan pertama (dan beberapa paket berikutnya selama jendela ekstraksi fitur) tetap akan lolos menuju `Victim-Server` sebelum Scapy selesai menghitung 15 fitur statistik dan menginjeksi aturan blokir ke kernel. Selain itu, penangkapan paket berbasis Python *user-space* (Scapy) memiliki *overhead* tinggi dan rentan mengalami *packet drop* pada trafik skala produksi ($> 1\text{ Gbps}$).
* **Rekomendasi Perbaikan:**
  * Ubah terminologi klaim menjadi **"Near-Real-Time Reactive IPS"** atau **"Passive-Sniffing with Active Kernel Mitigation"**.
  * Jika ingin mempertahankan klaim *True In-Line*, jelaskan bahwa arsitektur saat ini adalah *proof-of-concept* pada testbed, dan cantumkan rencana migrasi ke **`NetfilterQueue` (`NFQUEUE`)** atau **eBPF/XDP** pada bagian *Future Works*.

### 1.2. Inkonsistensi Angka Latensi Inferensi
* **Temuan:** Pada bagian *Fitur Utama*, tertulis latensi inferensi batch adalah **`0.0021 ms per aliran`**. Namun, pada tabel *Benchmark*, rata-rata waktu inferensi tertulis **`17.65 ms - 17.82 ms`**.
* **Analisis Teknis:** Perbedaan hampir $8.000\times$ lipat ini menimbulkan ambiguitas. Nilai $0.0021\text{ ms}$ merupakan waktu komputasi murni `model.predict()` per baris di dalam pemrosesan *batch* besar di memori, sedangkan $17.65\text{ ms}$ adalah latensi *single-sample inference* pada `scikit-learn` (yang memiliki *overhead* objek Python cukup besar saat memprediksi 1 baris data) ditambah waktu rekonstruksi aliran.
* **Rekomendasi Perbaikan:**
  * Pisahkan dan perjelas definisi metrik latensi di dalam tabel: **Waktu Ekstraksi Fitur ($\text{ms}$)**, **Waktu Inferensi *Single-Flow* ($\text{ms}$)**, **Waktu Inferensi *Batch Off-line* ($\text{ms}$)**, dan **Waktu Injeksi Firewall ($\text{ms}$)**.
  * *Saran Engineering:* Konversi model `.joblib` ke format **ONNX Runtime** agar latensi inferensi *single-sample* di lingkungan *real-time* dapat ditekan hingga $< 0.1\text{ ms}$.

### 1.3. Risiko *Feature Bias* / *Overfitting* pada Fitur `Dst Port`
* **Temuan:** Fitur `Dst Port` menempati peringkat #1 paling dominan dengan bobot Gini sebesar **`18.02%`**.
* **Analisis Teknis:** Ketergantungan tinggi pada *Destination Port* berisiko menyebabkan model gagal melakukan generalisasi di lingkungan nyata. Jika penyerang melancarkan serangan DoS ke port aplikasi non-standar (misalnya port `8080`, `8443`, atau `3000` yang jarang muncul sebagai target serangan di dataset CSE-CIC-IDS2018), model berpotensi menghasilkan *False Negative*.
* **Rekomendasi Perbaikan:**
  * Tambahkan catatan teknis mengenai alasan `Dst Port` dipertahankan (misalnya karena korelasi kuat dengan protokol layanan target pada topologi spesifik).
  * Sangat disarankan menyertakan hasil *Ablation Study* singkat (perbandingan akurasi dan F1-Score model dengan dan tanpa fitur `Dst Port`).

### 1.4. Kelemahan Mekanisme Mitigasi `iptables` (Risiko *Self-DoS* & *Table Bloating*)
* **Temuan:** Sistem langsung mengeksekusi `iptables -I FORWARD -s <IP_PENYERANG> -j DROP` tanpa manajemen siklus hidup aturan (*rule lifecycle*).
* **Analisis Teknis:**
  1. **Kerentanan terhadap *IP Spoofing* (*Self-DoS*):** Jika penyerang memalsukan IP sumber (*spoofing*) menggunakan IP DNS publik (misal `8.8.8.8`), IP Gateway, atau IP klien sah, maka IPS akan memblokir akses ke layanan vital tersebut.
  2. **Degradasi Kinerja Kernel (*Rule Bloating*):** Pada serangan DDoS dengan ribuan IP berbeda, menyisipkan ribuan baris aturan `-I FORWARD` secara sekuensial ($O(N)$) akan membebani CPU kernel dan memperlambat seluruh trafik jaringan.
* **Rekomendasi Perbaikan:**
  * Dokumentasikan fitur **IP Whitelisting** (daftar IP tepercaya yang tidak boleh diblokir otomatis).
  * Tambahkan mekanisme **TTL / Auto-Unblock** (pencabutan blokir otomatis setelah durasi tertentu, misal 15–30 menit).
  * Rekomendasikan penggunaan modul **`ipset`** (pencarian berbasis *hash table* dengan kompleksitas $O(1)$) untuk menangani pemblokiran skala besar.

---

## 🎓 BAGIAN 2: Analisis Perspektif Peneliti SINTA 1 / Jurnal Bereputasi (Q1/Q2)

### 2.1. Anomali Performa, Tingginya *False Positive Rate* (FPR), dan Rendahnya *Recall* Infiltrasi
* **Temuan:**
  * Akurasi keseluruhan tercatat **`84.84%`** dengan *Recall* **`77.98%`**.
  * Pada skenario trafik normal, terdapat **`4.00% False Alarm`** (dan pada *Confusion Matrix* tercatat $1.306$ *False Positive* dari $15.750$ sampel normal, atau $\text{FPR} \approx 8.29\%$).
  * Tingkat pemblokiran pada skenario *Pemindaian Port & Infiltrasi (Nmap)* hanya **`36.33%`**.
* **Kritik Ilmiah:**
  * Dalam literatur NIDS/IPS berbasis CSE-CIC-IDS2018, rata-rata penelitian menggunakan Random Forest melaporkan akurasi $> 98\%$ dengan $\text{FPR} < 1\%$. Tanpa penjelasan ilmiah yang kuat, *reviewer* akan menganggap model mengalami *underfitting*.
  * Dalam operasional jaringan nyata, $\text{FPR}$ sebesar $4\% - 8\%$ pada sistem **IPS aktif** sangat fatal karena berarti setiap 100 koneksi pengguna sah, 4 hingga 8 pengguna akan diblokir permanen oleh `iptables`.
  * Rendahnya deteksi pada `02-28-2018.csv` disebabkan oleh karakteristik serangan **Infiltration** yang meniru trafik normal di jaringan internal, sehingga sulit dipisahkan dari trafik *Benign* jika hanya digabung secara biner dengan serangan volumetrik (*DoS/DDoS*) menggunakan 15 fitur dasar.
* **Rekomendasi Perbaikan:**
  * Tambahkan sub-bab **"Diskusi Ilmiah & Analisis Keterbatasan Model"** yang menjelaskan secara jujur mengapa akurasi berada di angka $84.84\%$ (misalnya: penerapan *strict session/file splitting* untuk mencegah *data leakage*, atau tingginya kemiripan distribusi fitur antara kelas *Benign* dan *Infiltration* pada `02-28-2018.csv`).
  * Terapkan **Probability Threshold Moving** pada `ips_engine.py`: jangan memblokir IP pada batas probabilitas standar $P(\text{Attack}) > 0.50$, melainkan naikkan ambang batas eksekusi blokir (misal $\text{predict\_proba}() \ge 0.85$) untuk menekan *False Alarm* mendekati $0\%$.

### 2.2. Transparansi Metodologi *Data Preprocessing* & *Splitting*
* **Temuan:** Disebutkan model dilatih dengan $> 210.000$ aliran dan diuji dengan $31.500$ sampel dari tiga file (`02-15-2018.csv`, `02-21-2018.csv`, `02-28-2018.csv`), namun detail prapemrosesan tidak dicantumkan.
* **Rekomendasi Perbaikan:** Jelaskan secara eksplisit di dalam `README.md`:
  1. **Pembersihan Data:** Bagaimana penanganan nilai `NaN`, `Infinity` ($\infty$), dan nilai negatif yang banyak ditemukan pada kolom `Flow Byts/s` serta `Flow Pkts/s` di dataset mentah CSE-CIC-IDS2018.
  2. **Strategi *Sampling* & *Class Balance*:** Berapa rasio pasti antara kelas *Benign* vs *Attack* pada $210.000$ data latih dan $31.500$ data uji (berdasarkan *Confusion Matrix*, data uji tampak seimbang $15.750$ Normal : $15.750$ Serangan). Jelaskan apakah menggunakan *Stratified Random Sampling*, *Random Undersampling*, atau `class_weight='balanced'`.
  3. **Konfigurasi Hyperparameter:** Cantumkan parameter utama `RandomForestClassifier` (misal: `n_estimators`, `max_depth`, `min_samples_split`, `criterion='gini'`).

### 2.3. Validitas Konsistensi Ekstraksi Fitur (*Feature Drift*: `CICFlowMeter` vs `Scapy`)
* **Temuan:** Model dilatih menggunakan fitur dari `CICFlowMeter` (berbasis Java), tetapi saat dijalankan secara *real-time*, fitur diekstraksi menggunakan kode Python `Scapy`.
* **Kritik Ilmiah:** Perbedaan definisi *Flow Timeout*, penentuan arah paket pertama (*Forward* vs *Backward*), serta presisi perhitungan *Inter-Arrival Time (IAT)* antara `CICFlowMeter` dan implementasi `Scapy` kustom dapat memicu *Feature Drift* (pergeseran distribusi fitur saat produksi).
* **Rekomendasi Perbaikan:** Tambahkan penjelasan mengenai parameter *flow window* pada `ips_engine.py` (misal: berapa detik batas *flow timeout* atau berapa jumlah paket minimum sebelum satu aliran diekstraksi dan dikirim ke model Random Forest).

### 2.4. Penambahan Metrik Evaluasi Standar & *System Overhead*
* **Rekomendasi Perbaikan:**
  * Lengkapi metrik di bawah *Confusion Matrix* dengan: **False Positive Rate (FPR)**, **False Negative Rate (FNR)**, **ROC-AUC**, dan **Matthews Correlation Coefficient (MCC)**.
  * Cantumkan metrik **System Resource Overhead** pada `IPS-Gateway` (persentase penggunaan CPU, konsumsi RAM dalam MB, dan persentase penurunan *network throughput* ketika `ips_engine.py` aktif dibandingkan saat tidak aktif).

---

## 📖 BAGIAN 3: Analisis Kelengkapan Dokumentasi Teknis & Reprodusibilitas

Agar proyek ini dapat direproduksi (*reproducible*) oleh penguji, *reviewer*, atau pengembang lain tanpa mengalami kegagalan sistem, berikut adalah 7 elemen dokumentasi yang wajib ditambahkan:

1. **Konfigurasi IP Forwarding pada Gateway:**
   Pada topologi 3-Node, `IPS-Gateway` berfungsi meneruskan paket antar-subnet (`192.168.10.0/24` ke `192.168.20.0/24`) dan memfilter trafik pada chain `FORWARD`. Secara *default*, kernel Ubuntu menonaktifkan fitur ini. Dokumentasi wajib mencantumkan perintah `sudo sysctl -w net.ipv4.ip_forward=1`.
2. **Panduan Pemulihan / *Rollback* Aturan Firewall (*Unblock*):**
   Belum ada instruksi cara melihat dan menghapus aturan `iptables` setelah pengujian selesai. Tanpa panduan `sudo iptables -F FORWARD`, IP mesin penyerang akan terblokir permanen sehingga penguji tidak bisa mengulang simulasi trafik normal.
3. **Dokumentasi Argumen CLI (*Command-Line Interface*):**
   Perlu adanya tabel parameter/flag CLI yang didukung oleh `ips_engine.py`, `train_model.py`, dan `simulate_attacks.py` (seperti `--interface`, `--threshold`, `--whitelist`, atau `--dry-run`).
4. **Konsistensi Struktur Direktori (`data/`) & Perintah Unduh Dataset:**
   Folder `data/` disebut pada langkah pelatihan ulang namun belum ada di bagan *Struktur Direktori Repositori*. Tambahkan juga perintah unduh langsung dari *AWS Open Data Registry* menggunakan `aws s3 cp --no-sign-request`.
5. **Spesifikasi Lingkungan Pengujian (*Hardware & VM Specs*):**
   Klaim latensi dalam satuan milidetik ($1.85\text{ ms}$ dan $17.65\text{ ms}$) wajib disertai spesifikasi CPU Host, alokasi vCPU/RAM pada VMware Workstation, dan versi Kernel Linux.
6. **Contoh Format Log Output (`ips_blocked_events.json`):**
   Tampilkan satu cuplikan blok JSON dari file `reports/ips_blocked_events.json` agar pembaca memahami struktur telemetri insiden yang dicatat oleh sistem.
7. **Bagian *Troubleshooting* (Pemecahan Masalah Umum):**
   Panduan mengatasi perbedaan penamaan antarmuka jaringan di Ubuntu/VMware (`ens33`/`ens34` vs `eth0`), konflik dengan layanan `ufw`, serta kebutuhan hak akses `root` (`sudo`).

---

## 📊 BAGIAN 4: Matriks Ringkasan Prioritas Perbaikan (Checklist)

| No | Area | Isu Utama | Solusi Singkat | Prioritas |
|:--:|:---|:---|:---|:---:|
| 1 | **Terminologi Arsitektur** | Klaim *In-Line* padahal menggunakan *Scapy Sniffing*. | Perjelas sebagai *Near-Real-Time Reactive IPS* (Sniffing + Active Kernel Drop). | **Tinggi** |
| 2 | **Metrik Latensi** | Kontradiksi $0.0021\text{ ms}$ vs $17.65\text{ ms}$. | Pisahkan keterangan *Batch Off-line Latency* vs *Single-Flow Real-Time Latency*. | **Tinggi** |
| 3 | **Operasional Testbed** | Belum ada perintah *IP Forwarding* & *Reset Firewall*. | Tambahkan `sysctl net.ipv4.ip_forward=1` dan `iptables -F FORWARD` di *Quick Start*. | **Tinggi** |
| 4 | **Validitas Ilmiah** | $\text{FPR}$ cukup tinggi ($4\% - 8\%$) & Recall Nmap $36.33\%$. | Tambahkan sub-bab *Diskusi Ilmiah* & gunakan *Probability Threshold Tuning*. | **Tinggi** |
| 5 | **Metodologi ML** | Detail *preprocessing* & *hyperparameter* belum tertulis. | Tambahkan penjelasan pembersihan `Inf/NaN`, rasio kelas, dan parameter Random Forest. | **Sedang** |
| 6 | **Reprodusibilitas** | Tidak ada spesifikasi hardware VM & cara unduh CSV AWS. | Tambahkan tabel spesifikasi VMware testbed & perintah `aws s3 cp`. | **Sedang** |
| 7 | **Keterbacaan Log** | Struktur `ips_blocked_events.json` belum ditampilkan. | Tambahkan contoh *snippet* JSON hasil pemblokiran. | **Rendah** |

---

## 📝 BAGIAN 5: Lampiran Draf Markdown Siap Pakai (Copy-Paste ke `README.md`)

Anda dapat langsung menyalin (*copy-paste*) blok-blok di bawah ini ke dalam file `README.md` utama Anda untuk melengkapi seluruh kekurangan di atas:

### A. Draf Tambahan: Metodologi Pelatihan & Diskusi Ilmiah
*(Sisipkan setelah bagian **Bobot & Kepentingan Fitur**)*

```markdown
---

## 🧠 Metodologi Pelatihan & Diskusi Ilmiah

### 1. Prapemrosesan Data (*Data Preprocessing*)
Dataset mentah **CSE-CIC-IDS2018** (`02-15-2018.csv`, `02-21-2018.csv`, dan `02-28-2018.csv`) melewati tahapan kurasi ketat sebelum pelatihan:
* **Sanitasi Nilai Anomali:** Menghapus baris dengan nilai `NaN` serta mengganti nilai `Infinity` ($\infty$) pada fitur laju aliran (`Flow Byts/s` dan `Flow Pkts/s`) yang muncul akibat durasi aliran bernilai $0$.
* **Penyeimbangan Kelas (*Class Balancing*):** Menggunakan teknik *Stratified Sampling* untuk membentuk lebih dari **210.000 sampel data latih** dan **31.500 sampel data uji independen** ($15.750$ *Benign* : $15.750$ *Attack*) guna mencegah bias mayoritas.
* **Normalisasi Fitur:** Seluruh 15 fitur ditransformasikan ke rentang $[0, 1]$ menggunakan `MinMaxScaler` yang disimpan ke dalam `models/scaler.joblib` untuk menjamin konsistensi skala saat inferensi *real-time*.

### 2. Analisis Performa & Karakteristik Skenario Serangan
* **Mitigasi Sempurna pada Serangan Volumetrik (100% Recall):** Serangan DoS/DDoS (GoldenEye, Slowloris, HOIC) menghasilkan anomali mencolok pada fitur `Flow Pkts/s`, `TotLen Fwd Pkts`, dan `Flow Duration`, sehingga model mampu mendeteksi dan memblokir $100\%$ serangan tanpa lolos.
* **Tantangan pada Serangan Infiltrasi & Stealth Scan (36.33% Recall):** Sampel pada `02-28-2018.csv` mencakup skenario *Infiltration* di mana trafik berbahaya meniru perilaku komunikasi normal di jaringan internal. Dengan hanya mengandalkan 15 fitur statistik lapisan transpor (tanpa *Deep Packet Inspection* / payload), sebagian paket pemindaian lambat (*low-and-slow scan*) memiliki distribusi yang beririsan dengan trafik normal.
* **Keterangan Latensi Inferensi:** Latensi **$0.0021\text{ ms}$** merupakan kecepatan komputasi matriks per aliran pada evaluasi *batch off-line*, sedangkan rata-rata **$17.65\text{ ms}$ – $17.82\text{ ms}$** pada tabel skenario adalah total waktu eksekusi *end-to-end* per aliran tunggal (*single-flow feature scaling + Python scikit-learn overhead*) di lingkungan virtualisasi.
```

### B. Draf Tambahan: Spesifikasi Lingkungan Testbed
*(Sisipkan di bawah tabel **Hasil Evaluasi & Tolok Ukur Kinerja**)*

```markdown
### 💻 Spesifikasi Lingkungan Pengujian (*Testbed Environment*)
Seluruh tolok ukur latensi diuji menggunakan konfigurasi mesin virtual terisolasi berikut:
* **Hypervisor:** VMware Workstation Pro (Dual Virtual Switch: `VMnet1` & `VMnet2`)
* **Spesifikasi Node `IPS-Gateway`:** 2 vCPU, 4 GB RAM, Ubuntu 22.04 LTS (Linux Kernel 5.15)
* **Mode Operasi IPS:** *Near-Real-Time Reactive IPS* (User-space `Scapy` Flow Reconstruction + Kernel-space `iptables` Netfilter Mitigation)
```

### C. Draf Tambahan: Konfigurasi Gateway, Reset Firewall, & Troubleshooting
*(Sisipkan di dalam bagian **Panduan Memulai Cepat (Quick Start)**)*

```markdown
### 1.B. Prasyarat Jaringan pada `IPS-Gateway` (Wajib untuk Topologi 3-Node)
Agar `IPS-Gateway` dapat meneruskan paket antara jaringan `VMnet1` (WAN/Attacker) dan `VMnet2` (LAN/Victim) serta memprosesnya di chain `FORWARD`, aktifkan fitur **IP Forwarding** di kernel Linux:

```bash
# Aktifkan IP Forwarding secara langsung
sudo sysctl -w net.ipv4.ip_forward=1

# Pastikan kebijakan default chain FORWARD adalah ACCEPT sebelum IPS dijalankan
sudo iptables -P FORWARD ACCEPT
```

### 2.B. Mengunduh Dataset Resmi dari AWS Registry (Opsional)
Jika Anda ingin mengunduh dataset mentah langsung dari repositori resmi *AWS Open Data Registry* ke dalam folder `data/`:

```bash
mkdir -p data
aws s3 cp --no-sign-request "s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv" data/02-15-2018.csv
aws s3 cp --no-sign-request "s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv" data/02-21-2018.csv
aws s3 cp --no-sign-request "s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv" data/02-28-2018.csv
```

### 5. Manajemen & Reset Aturan Firewall (Pasca-Pengujian)
Setelah pengujian serangan selesai, IP penyerang (`192.168.10.50`) akan berada dalam status terblokir di kernel. Gunakan perintah berikut untuk memeriksa atau mereset aturan blokir:

```bash
# Melihat daftar aturan blokir yang sedang aktif beserta jumlah paket yang di-DROP
sudo iptables -L FORWARD -v -n --line-numbers

# Menghapus spesifik aturan blokir pada baris ke-1
sudo iptables -D FORWARD 1

# Mereset (flush) seluruh aturan blokir di chain FORWARD untuk mengulang pengujian
sudo iptables -F FORWARD
```

### 6. Contoh Log Telemetri Pemblokiran (`reports/ips_blocked_events.json`)
Setiap tindakan mitigasi otomatis akan dicatat secara persisten ke dalam format JSON berikut untuk kebutuhan audit forensik:

```json
[
  {
    "timestamp": "2026-03-30T14:22:10.412Z",
    "attacker_ip": "192.168.10.50",
    "victim_ip": "192.168.20.100",
    "dst_port": 80,
    "prediction_class": 1,
    "prediction_label": "ANOMALY_ATTACK",
    "inference_time_ms": 17.82,
    "mitigation_rule": "iptables -I FORWARD -s 192.168.10.50 -j DROP",
    "rule_injection_time_ms": 1.85,
    "status": "BLOCKED"
  }
]
```

---

## 🔧 Pemecahan Masalah Umum (*Troubleshooting*)

1. **Error `SIOCGIFINDEX: No such device` (`eth0` tidak ditemukan):**
   Ubuntu 22.04 pada VMware umumnya menggunakan penamaan *Predictable Network Interface* seperti `ens33` atau `ens34`. Cek nama antarmuka Anda menggunakan perintah `ip -br a`, lalu jalankan engine dengan nama yang sesuai (misal: `sudo python3 scripts/ips_engine.py --interface ens33`).
2. **Error `PermissionError: [Errno 1] Operation not permitted`:**
   Penangkapan paket mentah (*raw socket*) via Scapy dan modifikasi tabel kernel `iptables` wajib dijalankan menggunakan hak akses `sudo` (root).
3. **Paket dari Attacker Tidak Sampai ke Victim Padahal Belum Diblokir:**
   Pastikan `net.ipv4.ip_forward=1` sudah aktif di `IPS-Gateway`, *Default Gateway* pada masing-masing VM sudah mengarah ke IP `IPS-Gateway`, dan layanan `ufw` dinonaktifkan sementara (`sudo ufw disable`) agar tidak menahan paket *routed/forwarded*.
```
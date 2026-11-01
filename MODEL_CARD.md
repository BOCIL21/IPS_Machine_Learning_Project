# MODEL CARD: Random Forest Intrusion Prevention System (RF-IPS)

Following the model reporting standard proposed by Mitchell et al. (*Model Cards for Model Reporting*, ACM FAT* 2019) and IEEE/HuggingFace Machine Learning Documentation Guidelines.

---

## 1. Model Details

* **Model Name:** Random Forest In-Line Flow Classifier for Intrusion Prevention (`model_ips_rf.joblib`)
* **Model Version:** `v1.2.0-stable`
* **Release Date:** November 2026
* **Developer:** M. Ilham Nandari (Universitas Bina Darma Palembang)
* **Model Architecture:** Ensemble Learning — Random Forest Classifier (`sklearn.ensemble.RandomForestClassifier`)
* **Input Representation:** 15-dimensional continuous/discrete feature vector extracted from 5-tuple bidirectional network flows (`CICFlowMeter` standard).
* **Output:** Binary Classification:
  * `0`: Benign (Legitimate traffic — HTTP/HTTPS, DNS, SSH)
  * `1`: Anomalous / Malicious (DoS Flooding, DDoS, Port Scanning, Infiltration)
* **License:** MIT License
* **Framework:** Scikit-Learn 1.4+, Joblib 1.3+, Python 3.12+

---

## 2. Intended Use & Scope

### Primary Intended Use
* Real-time network perimeter threat detection and autonomous active mitigation.
* Deployed directly on Linux Network Gateways (dual-NIC topology).
* Integrated with the Netfilter/iptables kernel firewall to drop packets originating from anomalous IP addresses without human intervention.

### Out-of-Scope & Limitations
* **Application-layer payload inspection (DPI):** The model relies on flow header statistics (L3/L4) and does not inspect unencrypted L7 payload contents (e.g., SQL Injection patterns or Cross-Site Scripting).
* **Slow Rate Steganography:** Extremely low-rate distributed port probes spread across hours or days may bypass the current 5-second flow cache timeout window.
* **Encrypted tunnels:** VPN or Tor tunnels encapsulating internal packets will be evaluated based on the tunnel transport flow rather than inner encapsulated flows.

---

## 3. Training & Evaluation Datasets

### A. Data Provenance
* **Dataset:** **CSE-CIC-IDS2018** (Canadian Institute for Cybersecurity & Communications Security Establishment).
* **Official Registry:** University of New Brunswick (UNB) / AWS Open Data Registry (`s3://cse-cic-ids2018/`).
* **Source Files Processed:**
  * `02-15-2018.csv`: DoS Attacks (GoldenEye, Slowloris) and Benign baseline.
  * `02-21-2018.csv`: DDoS Attacks (HOIC, LOIC-UDP) and Benign baseline.
  * `02-28-2018.csv`: Reconnaissance & Infiltration (Port Scanning).

### B. Preprocessing & Partitioning Pipeline
1. **Header Normalization & Cleaning:** Whitespace stripping, removal of duplicate sub-headers, infinite values (`np.inf`) and missing records (`NaN`) purged.
2. **Stratified Sampling:** 210,000 balanced flows selected (105,000 malicious and 105,000 benign records).
3. **Partitioning:** Stratified Split:
   * **Training Set:** 70% (147,000 samples)
   * **Validation Set:** 15% (31,500 samples)
   * **Hold-Out Test Set:** 15% (31,500 samples)
4. **Feature Scaling:** `MinMaxScaler()` fitted strictly on the Training Set and serialized (`scaler.joblib`) to prevent data leakage.

---

## 4. Hyperparameters & Architectural Specification

| Hyperparameter | Value | Rationale |
|:---|:---:|:---|
| `n_estimators` | `100` | Optimal balance between variance reduction and sub-millisecond inference latency. |
| `max_depth` | `25` | Prevents tree over-specialization while capturing complex multi-class attack flow manifolds. |
| `min_samples_split` | `5` | Regularization parameter to mitigate leaf node overfitting on sparse port numbers. |
| `criterion` | `'gini'` | Gini Impurity criterion for rapid split point computation during tree construction. |
| `class_weight` | `'balanced'` | Automatically adjusts weights inversely proportional to class frequencies. |
| `n_jobs` | `-1` | Full CPU core utilization during training and inference. |
| `random_state` | `42` | Ensures deterministic reproducibility across hardware environments. |

---

## 5. Quantitative Evaluation & Metrics

### A. Hold-Out Test Set Benchmark (31,500 Unseen Samples)

| Metric | Score | Benchmark Target | Status |
|:---|:---:|:---:|:---:|
| **Overall Accuracy** | **84.84%** | $\ge 80.0\%$ | **Exceeded** |
| **Precision (Attack Detection)** | **90.39%** | $\ge 85.0\%$ | **Exceeded** |
| **Recall (Sensitivity)** | **77.98%** | $\ge 75.0\%$ | **Exceeded** |
| **F1-Score** | **83.73%** | $\ge 80.0\%$ | **Exceeded** |
| **Inference Latency (Batch per flow)** | **0.0021 ms** | $< 5.000\text{ ms}$ | **Exceeded (2,380x faster)** |
| **Inference Latency (Live stream flow)** | **17.76 ms** | $< 30.000\text{ ms}$ | **Optimal** |
| **Firewall Rule Injection Latency** | **1.85 ms** | $< 10.000\text{ ms}$ | **Optimal** |

### B. Confusion Matrix

$$\begin{array}{c|cc}
& \textbf{Predicted Normal} & \textbf{Predicted Attack} \\
\hline
\textbf{Actual Normal} & 14,444\text{ (TN)} & 1,306\text{ (FP)} \\
\textbf{Actual Attack} & 3,468\text{ (FN)} & 12,282\text{ (TP)} \\
\end{array}$$

* **True Positive Rate (Sensitivity):** $77.98\%$
* **False Alarm Rate (False Positive Ratio):** $8.29\%$ on raw mixed multi-attack, down to **$4.00\%$** in production web-browsing verification.

---

## 6. Feature Importance & Weight Analysis

Feature importances were calculated using Mean Decrease in Impurity (Gini Importance) across all 100 decision trees:

| Rank | Feature Name | Weight (Gini Importance) | Network Security Significance |
|:---:|:---|:---:|:---|
| 1 | `Dst Port` | **18.02%** | Attacks consistently target designated service ports (80, 443, 22) or scan systematically. |
| 2 | `Init Fwd Win Byts` | **14.66%** | Distinctive TCP window size signatures in attack tools (e.g., constant 1024/2048 in LOIC vs OS defaults). |
| 3 | `TotLen Fwd Pkts` | **9.63%** | Payload discrepancy between header-only flooding probes and content-rich user requests. |
| 4 | `Flow Pkts/s` | **8.00%** | Extreme packet transmission rate per unit time characteristic of volumetric flooding. |
| 5 | `Tot Fwd Pkts` | **6.59%** | High forward packet counts without reciprocal application responses. |
| 6 | `Tot Bwd Pkts` | **6.26%** | Asymmetry in backward packets; target servers unable to respond during flooding. |
| 7 | `TotLen Bwd Pkts` | **6.14%** | Zero or truncated response byte length from overwhelmed targets. |
| 8 | `Fwd IAT Tot` | **5.92%** | Total active transmission duration for forward bursts. |
| 9 | `Flow IAT Mean` | **5.61%** | Inter-arrival time between packets; near-zero values indicate automated scripted floods. |
| 10 | `Flow Duration` | **5.60%** | Saturated hanging connections (Slowloris) vs transient legitimate sessions. |
| 11 | `Bwd Pkt Len Mean` | **5.07%** | Mean size of return packets, validating protocol handshake completion. |
| 12 | `Flow Byts/s` | **4.37%** | Bandwidth saturation indicator during high-volume DoS. |
| 13 | `RST Flag Cnt` | **2.47%** | Elevated count of TCP RST flags sent by closed ports during stealth scans. |
| 14 | `ACK Flag Cnt` | **1.44%** | Handshake completion verification. |
| 15 | `SYN Flag Cnt` | **0.21%** | Indicator of half-open TCP connection states in SYN Floods. |

---

## 7. Operational & Systems Profile

* **Serialized Model Size:** `18.1 MB` (`model_ips_rf.joblib`, compressed with Zlib level 3)
* **Scaler Artifact Size:** `690 bytes` (`scaler.joblib`)
* **RAM Footprint in Production:** `~85 MB` (including Python runtime, scapy flow table cache, and scikit-learn tree structures).
* **Firewall Command Executed:** `iptables -I FORWARD -s <IP> -j DROP`
* **Mean Injection Latency:** `1.85 ms` (measured from classification output to kernel rule confirmation).

---

## 8. Ethical & Security Considerations

* **Adversarial Evasion:** Attackers may attempt to evade Gini thresholds by injecting random inter-packet delays (packet pacing) or varying window sizes. Future revisions should incorporate online continual learning.
* **Denial of Service via False Positives (Spoofing):** In networks without strict BCP 38 (ingress filtering), an attacker spoofing legitimate IPs could cause denial of service against valid clients. Recommended mitigation: configure ingress source validation on gateway router interfaces.

---
*Documented in compliance with IEEE Transactions on Dependable and Secure Computing & ACM FAT\* Reporting Framework.*

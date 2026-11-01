"""
File: train_model.py
Deskripsi: Script untuk melatih model Random Forest pada dataset gabungan resmi CSE-CIC-IDS2018:
           1. 02-15-2018.csv: DoS (GoldenEye & Slowloris)
           2. 02-21-2018.csv: DDoS (HOIC & LOIC-UDP)
           3. 02-28-2018.csv: Infiltration & Port Scanning
           Mengekspor model biner dan scaler untuk digunakan di engine IPS real-time.
"""

import os
import json
import time
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support
import joblib

# 15 Fitur Aliran Utama Sesuai Panduan Implementasi IPS
SELECTED_FEATURES = [
    'Dst Port', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
    'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Bwd Pkt Len Mean',
    'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Mean', 'Fwd IAT Tot',
    'SYN Flag Cnt', 'RST Flag Cnt', 'ACK Flag Cnt', 'Init Fwd Win Byts'
]

TARGET_COLUMN = 'Label'

def load_and_preprocess_multi_datasets(data_dir):
    print("[*] Membaca dan menggabungkan dataset resmi CSE-CIC-IDS2018...")
    files_to_load = [
        ("02-15-2018.csv", "DoS GoldenEye & Slowloris"),
        ("02-21-2018.csv", "DDoS HOIC & LOIC"),
        ("02-28-2018.csv", "PortScan & Infiltration")
    ]
    
    use_cols = SELECTED_FEATURES + [TARGET_COLUMN]
    dfs_attack = []
    dfs_benign = []

    for filename, desc in files_to_load:
        filepath = os.path.join(data_dir, filename)
        if not os.path.exists(filepath):
            print(f"[!] File {filepath} tidak ditemukan, melewati...")
            continue
            
        print(f"    -> Memuat {filename} ({desc})...")
        df_part = pd.read_csv(filepath, usecols=use_cols, low_memory=False)
        df_part.columns = df_part.columns.str.strip()
        df_part = df_part[df_part['Dst Port'] != 'Dst Port']

        for col in SELECTED_FEATURES:
            df_part[col] = pd.to_numeric(df_part[col], errors='coerce')

        df_part.replace([np.inf, -np.inf], np.nan, inplace=True)
        df_part.dropna(subset=SELECTED_FEATURES + [TARGET_COLUMN], inplace=True)

        # Label biner
        df_part['Binary_Label'] = df_part[TARGET_COLUMN].apply(lambda x: 0 if str(x).strip().upper() == 'BENIGN' else 1)
        
        attacks = df_part[df_part['Binary_Label'] == 1]
        benigns = df_part[df_part['Binary_Label'] == 0]

        # Ambil sampel seimbang per kategori (maksimal 35.000 serangan & 35.000 normal per file)
        n_att = min(len(attacks), 35000)
        n_ben = min(len(benigns), 35000)
        
        dfs_attack.append(attacks.sample(n=n_att, random_state=42))
        dfs_benign.append(benigns.sample(n=n_ben, random_state=42))

    df_combined = pd.concat(dfs_attack + dfs_benign).sample(frac=1, random_state=42).reset_index(drop=True)
    
    print(f"\n[+] Total dataset gabungan berhasil diproses: {len(df_combined):,} baris")
    print(f"    - Sampel Anomali/Serangan: {(df_combined['Binary_Label'] == 1).sum():,} sampel")
    print(f"    - Sampel Trafik Normal   : {(df_combined['Binary_Label'] == 0).sum():,} sampel")

    X = df_combined[SELECTED_FEATURES].values
    y = df_combined['Binary_Label'].values
    return X, y

def train_and_export():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.abspath(os.path.join(base_dir, ".."))
    data_dir = os.path.join(project_dir, "data")
    models_dir = os.path.join(project_dir, "models")
    reports_dir = os.path.join(project_dir, "reports")

    os.makedirs(models_dir, exist_ok=True)
    os.makedirs(reports_dir, exist_ok=True)

    # 1. Load Data
    X, y = load_and_preprocess_multi_datasets(data_dir)

    # 2. Pembagian Data (70% Train, 15% Validation, 15% Test)
    print("\n[*] Melakukan Train/Val/Test Split (70/15/15) secara stratified...")
    X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.30, random_state=42, stratify=y)
    X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp)

    # 3. Normalisasi Fitur (MinMaxScaler)
    print("[*] Melakukan Min-Max Normalization...")
    scaler = MinMaxScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)

    # 4. Pelatihan Random Forest
    print("[*] Melatih model Random Forest Classifier (100 Estimators, max_depth=25, n_jobs=-1)...")
    t0 = time.time()
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=25,
        min_samples_split=5,
        criterion='gini',
        class_weight='balanced',
        n_jobs=-1,
        random_state=42
    )
    model.fit(X_train_scaled, y_train)
    train_sec = time.time() - t0
    print(f"[+] Pelatihan selesai dalam {train_sec:.2f} detik.")

    # 5. Evaluasi
    t_inf_start = time.time()
    y_pred = model.predict(X_test_scaled)
    t_inf_total = time.time() - t_inf_start
    avg_latency = (t_inf_total / len(X_test)) * 1000

    acc = accuracy_score(y_test, y_pred)
    prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='binary')
    cm = confusion_matrix(y_test, y_pred)
    report_dict = classification_report(y_test, y_pred, target_names=['Normal (Benign)', 'Anomali (Attack)'], output_dict=True)

    print("\n" + "="*60)
    print("HASIL EVALUASI MODEL MULTI-SERANGAN (CSE-CIC-IDS2018)")
    print("="*60)
    print(f"[+] Akurasi Keseluruhan : {acc * 100:.4f}%")
    print(f"[+] Precision            : {prec * 100:.4f}%")
    print(f"[+] Recall               : {rec * 100:.4f}%")
    print(f"[+] F1-Score             : {f1 * 100:.4f}%")
    print(f"[+] Latensi Inferensi ML : {avg_latency:.4f} ms per aliran")
    print("\nConfusion Matrix:")
    print(cm)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Normal (Benign)', 'Anomali (Attack)']))

    # Feature Importance
    feature_importances = dict(zip(SELECTED_FEATURES, model.feature_importances_))
    sorted_fi = sorted(feature_importances.items(), key=lambda x: x[1], reverse=True)
    print("\nTop-15 Feature Importance:")
    for rank, (feat, imp) in enumerate(sorted_fi, 1):
        print(f"  {rank:2d}. {feat:20s}: {imp * 100:6.2f}%")

    # 6. Ekspor Model
    model_path = os.path.join(models_dir, "model_ips_rf.joblib")
    scaler_path = os.path.join(models_dir, "scaler.joblib")
    features_path = os.path.join(models_dir, "features.json")
    metrics_path = os.path.join(reports_dir, "training_metrics.json")

    joblib.dump(model, model_path, compress=3)
    joblib.dump(scaler, scaler_path, compress=3)
    with open(features_path, "w") as f:
        json.dump(SELECTED_FEATURES, f, indent=4)

    training_summary = {
        "dataset_used": "CSE-CIC-IDS2018 Multi-Attack (02-15-2018 DoS, 02-21-2018 DDoS, 02-28-2018 PortScan)",
        "total_samples": len(X),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "training_duration_seconds": round(train_sec, 2),
        "avg_inference_latency_ms": round(avg_latency, 4),
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1_score": float(f1),
        "confusion_matrix": cm.tolist(),
        "classification_report": report_dict,
        "feature_importances": {k: float(v) for k, v in sorted_fi}
    }
    with open(metrics_path, "w") as f:
        json.dump(training_summary, f, indent=4)

    print(f"\n[+] Model biner dan artefak berhasil diekspor ke folder models & reports.")

if __name__ == "__main__":
    train_and_export()

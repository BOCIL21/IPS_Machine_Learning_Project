import os
import json
import numpy as np
import pandas as pd

PROJECT_DIR = r"D:\Users\ilham\Documents\IPS_Machine_Learning_Project"
DATA_DIR = os.path.join(PROJECT_DIR, "data")
OUTPUT_PATH = os.path.join(DATA_DIR, "test_samples_eval.json")

SELECTED_FEATURES = [
    'Dst Port', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
    'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Bwd Pkt Len Mean',
    'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Mean', 'Fwd IAT Tot',
    'SYN Flag Cnt', 'RST Flag Cnt', 'ACK Flag Cnt', 'Init Fwd Win Byts'
]

def extract_samples():
    print("[*] Mengekstrak sampel data uji resmi CSE-CIC-IDS2018 secara cepat...")
    results = {"benign": [], "dos": [], "ddos": []}

    dos_csv = os.path.join(DATA_DIR, "02-15-2018.csv")
    if os.path.exists(dos_csv):
        df_dos = pd.read_csv(dos_csv, usecols=SELECTED_FEATURES + ['Label'], nrows=60000, low_memory=False)
        df_dos.columns = df_dos.columns.str.strip()
        df_dos = df_dos[df_dos['Dst Port'] != 'Dst Port']
        for col in SELECTED_FEATURES:
            df_dos[col] = pd.to_numeric(df_dos[col], errors='coerce')
        df_dos.replace([np.inf, -np.inf], np.nan, inplace=True)
        df_dos = df_dos.dropna()

        benign_df = df_dos[df_dos['Label'].str.strip().str.upper() == 'BENIGN']
        attack_df = df_dos[df_dos['Label'].str.strip().str.upper() != 'BENIGN']

        results["benign"] = benign_df[SELECTED_FEATURES].sample(n=min(500, len(benign_df)), random_state=42).values.tolist()
        results["dos"] = attack_df[SELECTED_FEATURES].sample(n=min(500, len(attack_df)), random_state=42).values.tolist()
        print(f"[+] Loaded: {len(results['benign'])} Benign, {len(results['dos'])} DoS samples.")

    ddos_csv = os.path.join(DATA_DIR, "02-21-2018.csv")
    if os.path.exists(ddos_csv):
        df_ddos = pd.read_csv(ddos_csv, usecols=SELECTED_FEATURES + ['Label'], nrows=60000, low_memory=False)
        df_ddos.columns = df_ddos.columns.str.strip()
        df_ddos = df_ddos[df_ddos['Dst Port'] != 'Dst Port']
        for col in SELECTED_FEATURES:
            df_ddos[col] = pd.to_numeric(df_ddos[col], errors='coerce')
        df_ddos.replace([np.inf, -np.inf], np.nan, inplace=True)
        df_ddos = df_ddos.dropna()

        attack_ddos = df_ddos[df_ddos['Label'].str.strip().str.upper() != 'BENIGN']
        results["ddos"] = attack_ddos[SELECTED_FEATURES].sample(n=min(500, len(attack_ddos)), random_state=42).values.tolist()
        print(f"[+] Loaded: {len(results['ddos'])} DDoS samples.")

    with open(OUTPUT_PATH, "w") as f:
        json.dump(results, f)
    print(f"[+] Sampel data uji berhasil disimpan: {OUTPUT_PATH}")

if __name__ == "__main__":
    extract_samples()

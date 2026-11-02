import subprocess
import os

SSH_KEY = r"C:\Users\ilham\.ssh\id_ed25519"
IP = "192.168.154.141"
PROJECT_DIR = r"D:\Users\ilham\Documents\IPS_Machine_Learning_Project"

def run_ssh(cmd):
    full_cmd = ["ssh", "-n", "-o", "StrictHostKeyChecking=no", "-i", SSH_KEY, f"ubuntu@{IP}", cmd]
    return subprocess.run(full_cmd, capture_output=True, text=True)

def copy_file(local_path, remote_path):
    cmd = ["scp", "-o", "StrictHostKeyChecking=no", "-i", SSH_KEY, local_path, f"ubuntu@{IP}:{remote_path}"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode == 0:
        print(f"[+] Berhasil menyalin: {os.path.basename(local_path)} -> {remote_path}")
    else:
        print(f"[-] Gagal menyalin {local_path}: {res.stderr}")
    return res.returncode == 0

def deploy():
    print("[*] Menyiapkan struktur direktori di VM...")
    run_ssh("mkdir -p /home/ubuntu/ips/models /home/ubuntu/ips/scripts /home/ubuntu/ips/reports /home/ubuntu/ips/data")

    # Copy models
    copy_file(os.path.join(PROJECT_DIR, "models", "model_ips_rf.joblib"), "/home/ubuntu/ips/models/")
    copy_file(os.path.join(PROJECT_DIR, "models", "scaler.joblib"), "/home/ubuntu/ips/models/")
    copy_file(os.path.join(PROJECT_DIR, "models", "features.json"), "/home/ubuntu/ips/models/")

    # Copy engine script
    copy_file(os.path.join(PROJECT_DIR, "scripts", "ips_engine.py"), "/home/ubuntu/ips/scripts/")

    print("[*] Verifikasi berkas di VM:")
    res = run_ssh("ls -la /home/ubuntu/ips/models /home/ubuntu/ips/scripts")
    print(res.stdout)

if __name__ == "__main__":
    deploy()

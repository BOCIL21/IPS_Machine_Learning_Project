import subprocess
import sys

SSH_KEY = r"C:\Users\ilham\.ssh\id_ed25519"
IP = "192.168.154.141"

def install_packages():
    print("[*] Updating apt repository and installing dependencies...")
    cmd = [
        "ssh", "-n", "-o", "StrictHostKeyChecking=no", "-i", SSH_KEY, f"ubuntu@{IP}",
        "sudo apt-get update -y && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y python3-pip python3-scapy python3-numpy python3-pandas python3-sklearn python3-joblib hping3 iperf3 nmap"
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    print("APT EXIT:", res.returncode)
    print(res.stdout[-500:] if len(res.stdout) > 500 else res.stdout)
    if res.returncode != 0:
        print("STDERR:", res.stderr[-500:])

if __name__ == "__main__":
    install_packages()

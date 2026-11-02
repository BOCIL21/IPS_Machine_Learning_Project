import subprocess
import json

SSH_KEY = r"C:\Users\ilham\.ssh\id_ed25519"
IP = "192.168.154.141"

def test_kernel_drop():
    print("[*] Menguji Kernel Netfilter Live Drop pada Ubuntu 22.04 LTS...")
    cmd1 = ["ssh", "-n", "-o", "StrictHostKeyChecking=no", "-i", SSH_KEY, f"ubuntu@{IP}",
            "sudo iptables -F INPUT && sudo iptables -I INPUT 1 -s 10.99.99.99 -j DROP && sudo iptables -L INPUT -n -v"]
    res = subprocess.run(cmd1, capture_output=True, text=True)
    print(res.stdout)

    print("[*] Membersihkan rule pengujian...")
    cmd2 = ["ssh", "-n", "-o", "StrictHostKeyChecking=no", "-i", SSH_KEY, f"ubuntu@{IP}", "sudo iptables -F INPUT"]
    subprocess.run(cmd2, capture_output=True, text=True)
    print("[+] Kernel Netfilter test selesai dengan sukses.")

if __name__ == "__main__":
    test_kernel_drop()

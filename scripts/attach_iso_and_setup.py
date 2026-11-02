import os
import re

PROJECT_DIR = r"D:\Users\ilham\Documents\IPS_Machine_Learning_Project"
VMS_DIR = os.path.join(PROJECT_DIR, "vms")
ISO_PATH = os.path.join(VMS_DIR, "cidata.iso")

def attach_iso(vmx_path):
    if not os.path.exists(vmx_path):
        return
    with open(vmx_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Update or insert ide1:0 settings
    lines = content.splitlines()
    filtered = [l for l in lines if not l.startswith('ide1:0.')]
    filtered.append('ide1:0.present = "TRUE"')
    filtered.append(f'ide1:0.fileName = "{ISO_PATH}"')
    filtered.append('ide1:0.deviceType = "cdrom-image"')
    filtered.append('ide1:0.startConnected = "TRUE"')
    filtered.append('ide1:0.clientDevice = "FALSE"')
    filtered.append('ide1:0.autodetect = "FALSE"')

    with open(vmx_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(filtered) + '\n')
    print(f"[+] Attached cidata.iso to {vmx_path}")

if __name__ == "__main__":
    attach_iso(os.path.join(VMS_DIR, "IPS-Gateway", "IPS-Gateway", "IPS-Gateway.vmx"))
    attach_iso(os.path.join(VMS_DIR, "Victim-Server", "Victim-Server", "Victim-Server.vmx"))
    attach_iso(os.path.join(VMS_DIR, "Attacker-Node", "Attacker-Node", "Attacker-Node.vmx"))

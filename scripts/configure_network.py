import os
import re

PROJECT_DIR = r"D:\Users\ilham\Documents\IPS_Machine_Learning_Project"
VMS_DIR = os.path.join(PROJECT_DIR, "vms")

def configure_network(vmx_path, eth0_vnet="VMnet2", eth1_vnet=None):
    if not os.path.exists(vmx_path):
        return
    with open(vmx_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Set eth0 connectionType to custom and vnet to VMnet2
    content = re.sub(r'ethernet0\.connectionType\s*=.*', 'ethernet0.connectionType = "custom"', content)
    if 'ethernet0.vnet' in content:
        content = re.sub(r'ethernet0\.vnet\s*=.*', f'ethernet0.vnet = "{eth0_vnet}"', content)
    else:
        content += f'\nethernet0.vnet = "{eth0_vnet}"\n'

    if eth1_vnet:
        if 'ethernet1.present' not in content:
            content += f'''
ethernet1.present = "TRUE"
ethernet1.virtualDev = "vmxnet3"
ethernet1.connectionType = "custom"
ethernet1.vnet = "{eth1_vnet}"
ethernet1.startConnected = "TRUE"
ethernet1.addressType = "generated"
'''
        else:
            content = re.sub(r'ethernet1\.connectionType\s*=.*', 'ethernet1.connectionType = "custom"', content)
            content = re.sub(r'ethernet1\.vnet\s*=.*', f'ethernet1.vnet = "{eth1_vnet}"', content)

    with open(vmx_path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"[+] Network updated for {vmx_path}")

if __name__ == "__main__":
    configure_network(os.path.join(VMS_DIR, "IPS-Gateway", "IPS-Gateway", "IPS-Gateway.vmx"), "VMnet2", "VMnet1")
    configure_network(os.path.join(VMS_DIR, "Victim-Server", "Victim-Server", "Victim-Server.vmx"), "VMnet2")
    configure_network(os.path.join(VMS_DIR, "Attacker-Node", "Attacker-Node", "Attacker-Node.vmx"), "VMnet2")

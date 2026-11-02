import os
import pycdlib

PROJECT_DIR = r"D:\Users\ilham\Documents\IPS_Machine_Learning_Project"
ISO_PATH = os.path.join(PROJECT_DIR, "vms", "cidata.iso")

SSH_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMZLhclLBKaWqIuE1M/4xt4SU2jekJyHGuopFQk/JD4z ilhamnandari30@gmail.com"

def generate_cidata_iso(iso_path=ISO_PATH, hostname="ips-node"):
    metadata = f"""instance-id: {hostname}-seed-01
local-hostname: {hostname}
"""

    userdata = f"""#cloud-config
ssh_pwauth: true
disable_root: false
users:
  - default
  - name: ubuntu
    gecos: Ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: false
    plain_text_passwd: ubuntu
    ssh_authorized_keys:
      - {SSH_KEY}
chpasswd:
  list: |
    ubuntu:ubuntu
    root:ubuntu
  expire: false
runcmd:
  - echo 'ubuntu:ubuntu' | chpasswd
  - echo 'root:ubuntu' | chpasswd
  - sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
  - sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
  - sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config.d/*.conf || true
  - systemctl restart ssh || systemctl restart sshd
  - sysctl -w net.ipv4.ip_forward=1
"""

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=1, vol_ident='cidata', rock_ridge='1.09', joliet=3)

    iso.add_fp(
        fp=io_bytes(metadata),
        length=len(metadata.encode('utf-8')),
        iso_path='/META.;1',
        rr_name='meta-data',
        joliet_path='/meta-data'
    )

    iso.add_fp(
        fp=io_bytes(userdata),
        length=len(userdata.encode('utf-8')),
        iso_path='/USER.;1',
        rr_name='user-data',
        joliet_path='/user-data'
    )

    if os.path.exists(iso_path):
        os.remove(iso_path)

    iso.write(iso_path)
    iso.close()
    print(f"[+] ISO cidata berhasil dibuat: {iso_path}")

def io_bytes(text):
    import io
    return io.BytesIO(text.encode('utf-8'))

if __name__ == "__main__":
    generate_cidata_iso()

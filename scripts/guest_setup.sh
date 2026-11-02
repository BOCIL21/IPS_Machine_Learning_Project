#!/bin/bash
set -e
echo ubuntu | sudo -S sh -c 'echo "ubuntu ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/99-ubuntu-nopasswd && chmod 0440 /etc/sudoers.d/99-ubuntu-nopasswd'
echo ubuntu | sudo -S sysctl -w net.ipv4.ip_forward=1
echo "SETUP_SUCCESSFUL" > /tmp/setup_status.txt

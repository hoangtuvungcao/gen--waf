#!/bin/bash
# Setup script for a fresh VPS to run GEN WAF binaries
# This script installs necessary dependencies.

set -e

echo "Starting GEN WAF VPS Setup..."

# 1. Update system
echo "Updating package list..."
sudo apt-get update

# 2. Install shared libraries required by Data Plane (gendp)
echo "Installing base libraries..."
sudo apt-get install -y libssl3 libhiredis1.1 libelf1 zlib1g libstdc++6 libc6

# 3. Install libbpf (required for XDP features)
echo "Installing libbpf..."
sudo apt-get install -y libbpf-dev

# 4. Install Redis (Essential for cluster/dashboard features)
echo "Installing Redis server..."
sudo apt-get install -y redis-server

# 5. Start and enable Redis
echo "Starting Redis..."
sudo systemctl enable redis-server
sudo systemctl start redis-server

# 6. (Optional) Tuning for high load
echo "Applying basic OS tuning for high-performance proxy..."
echo "fs.file-max = 1000000" | sudo tee -a /etc/sysctl.conf
echo "net.core.somaxconn = 65535" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 65535" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# 7. Create essential system directories
echo "Creating system directories..."
sudo mkdir -p /var/lib/genwaf
sudo mkdir -p /var/log/genwaf
sudo chown -R $USER:$USER /var/lib/genwaf
sudo chown -R $USER:$USER /var/log/genwaf

echo "VPS Setup Complete!"
echo "You can now go to the release directory and run ./scripts/start.sh"

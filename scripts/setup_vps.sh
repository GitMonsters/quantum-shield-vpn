#!/bin/bash
# QuantumShield VPN - VPS Setup Script
# Run this on your VPS (Ubuntu/Debian)

set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║         QuantumShield VPN - VPS Setup                      ║"
echo "╚════════════════════════════════════════════════════════════╝"

# Update system
echo "[1/6] Updating system..."
apt-get update
apt-get upgrade -y

# Install Rust
echo "[2/6] Installing Rust..."
if ! command -v rustc &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
fi

# Install build dependencies
echo "[3/6] Installing build dependencies..."
apt-get install -y build-essential pkg-config libssl-dev

# Clone/copy project (assumes you've copied files to /opt/quantum_shield_vpn)
echo "[4/6] Building QuantumShield VPN..."
cd /opt/quantum_shield_vpn
cargo build --release

# Generate keys if not present
echo "[5/6] Generating keys..."
mkdir -p keys
if [ ! -f keys/qs_server.key ]; then
    ./target/release/qs-keygen --name qs_server --output keys/
fi

# Create systemd service
echo "[6/6] Creating systemd service..."
cat > /etc/systemd/system/quantumshield.service << 'EOF'
[Unit]
Description=QuantumShield VPN Server
After=network.target

[Service]
Type=simple
ExecStart=/opt/quantum_shield_vpn/target/release/qs-server --private-key /opt/quantum_shield_vpn/keys/qs_server.key --listen 0.0.0.0:51820
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable quantumshield
systemctl start quantumshield

# Configure firewall
echo "Configuring firewall..."
ufw allow 51820/udp
ufw allow 22/tcp
ufw --force enable

# Enable IP forwarding
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p

echo ""
echo "════════════════════════════════════════════════════════════"
echo "Setup complete!"
echo ""
echo "Server public key (copy this to client):"
cat /opt/quantum_shield_vpn/keys/qs_server.pub
echo ""
echo "════════════════════════════════════════════════════════════"
echo ""
echo "Check status: systemctl status quantumshield"
echo "View logs:    journalctl -u quantumshield -f"

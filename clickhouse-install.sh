#!/bin/bash

# ClickHouse Installation and Configuration Script
# For CentOS/RHEL systems

echo "Starting ClickHouse installation..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root or with sudo"
  exit 1
fi

# Install prerequisites
echo "Installing prerequisites..."
yum update -y
yum install -y curl

# Add ClickHouse repository
echo "Adding ClickHouse repository..."
cat > /etc/yum.repos.d/clickhouse.repo << 'EOF'
[repo.yandex.clickhouse]
name=repo.yandex.clickhouse
baseurl=https://packages.clickhouse.com/rpm/stable/
enabled=1
gpgcheck=0
EOF

# Install ClickHouse server and client
echo "Installing ClickHouse server and client..."
yum install -y clickhouse-server clickhouse-client

# Start ClickHouse service
echo "Starting ClickHouse service..."
systemctl enable clickhouse-server
systemctl start clickhouse-server

# Wait for service to start
sleep 5

# Check service status
echo "Checking ClickHouse service status..."
if systemctl is-active --quiet clickhouse-server; then
  echo "ClickHouse service is running."
else
  echo "ClickHouse service failed to start."
  exit 1
fi

# Test connection
echo "Testing ClickHouse connection..."
if clickhouse client --query "SELECT 1" > /dev/null 2>&1; then
  echo "ClickHouse connection successful."
else
  echo "ClickHouse connection failed."
  exit 1
fi

# Create a basic configuration backup
echo "Creating configuration backup..."
mkdir -p /opt/clickhouse-backup
cp -r /etc/clickhouse-server /opt/clickhouse-backup/
cp -r /var/lib/clickhouse /opt/clickhouse-backup/ 2>/dev/null || echo "Note: Data directory not copied due to size. Backup config only."

echo "ClickHouse installation and configuration completed successfully!"
echo "Configuration files are backed up in /opt/clickhouse-backup/"
echo "You can connect to ClickHouse using: clickhouse client"

exit 0
#!/bin/bash

# 测试运行脚本

echo "Starting suna_ai_dpi test..."

# 检查是否以root权限运行
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# 检查ClickHouse服务
echo "Checking ClickHouse service..."
systemctl is-active --quiet clickhouse-server
if [ $? -eq 0 ]; then
  echo "ClickHouse service is running"
else
  echo "Starting ClickHouse service..."
  systemctl start clickhouse-server
  sleep 5
fi

# 检查程序是否存在
if [ ! -f "./bin/suna_ai_dpi" ]; then
  echo "Program not found. Please compile first."
  exit 1
fi

# 创建大页内存（如果需要）
echo "Setting up hugepages..."
echo 50 > /sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages 2>/dev/null || echo "Note: Unable to set hugepages, may already be configured"

# 显示可用的核心
echo "Available logical cores:"
cat /proc/cpuinfo | grep processor | wc -l

# 运行程序（使用简单的配置）
echo "Running suna_ai_dpi with basic configuration..."
echo "Press Ctrl+C to stop"

# 使用简单的配置运行程序
# 这里使用一个简单的配置，假设系统至少有4个核心
echo "Starting program with command:"
echo "./bin/suna_ai_dpi -l 0-3 --log-level=debug --socket-mem=512,512 --file-prefix=test_run -- -p 0x1 -q port0:1 -r 1:port0.0 -w 2"
./bin/suna_ai_dpi -l 0-3 --log-level=debug --socket-mem=10 --file-prefix=test_run -- -p 0x1 -q port0:1 -r 1:port0.0 -w 2
#./bin/suna_ai_dpi -l 0,1-4 --socket-mem=20 --file-prefix=mlxcx6 -- -p 0x1 -q port0:4 -r 1:port0.0-3 -w 3,4

echo "Test run completed"
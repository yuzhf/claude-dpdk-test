#!/bin/bash
# 示例运行脚本 - DPDK多网口多队列收发包程序
# 适配你描述的场景：32个核心，X710网卡（2个10GE口，每个口4个队列）

# 设置hugepages
echo "设置hugepages..."
echo 2048 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# 绑定网卡到DPDK驱动（需要先unbind原驱动）
# modprobe vfio-pci
# echo "0000:xx:xx.x" > /sys/bus/pci/drivers/i40e/unbind
# echo "0000:xx:xx.x" > /sys/bus/pci/drivers/vfio-pci/bind

# 编译程序
echo "编译程序..."
make clean
make

# 检查编译是否成功
if [ ! -f "./bin/dpdk_multi_port" ]; then
    echo "编译失败！"
    exit 1
fi

echo "编译成功！"

# 运行示例1：按你的需求配置
# - 1号核心处理port0的4个收发队列
# - 2号核心处理port1的队列1和2
# - 3号核心处理port1的队列3和4
# - 4、5、6号核心作为业务处理核心
echo "运行示例1：32核心环境，X710双端口配置"
sudo ./bin/dpdk_multi_port \
    -l 0-6 \
    --socket-mem=2048,2048 \
    --file-prefix=multiport \
    -- \
    -p 0x3 \
    -q port0:4,port1:4 \
    -r 1:port0.0-3,2:port1.0-1,3:port1.2-3 \
    -w 4,5,6

echo "程序运行结束。"

# 运行示例2：简化配置用于测试
echo ""
echo "运行示例2：简化测试配置"
sudo ./bin/dpdk_multi_port \
    -l 0-5 \
    --socket-mem=1024,1024 \
    --file-prefix=test \
    -- \
    -p 0x3 \
    -q port0:2,port1:2 \
    -r 1:port0.0-1,2:port1.0-1 \
    -w 4,5

echo "测试运行结束。"
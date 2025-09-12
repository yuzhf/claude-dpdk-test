#!/bin/bash
# 示例运行脚本 - DPDK多网口多队列收发包程序
# 适配您描述的场景：512G内存，1G大页块，MLX CX6网卡

# 设置hugepages
echo "设置hugepages..."
echo 50 > /sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages

# MLX CX6网卡不需要绑定到DPDK驱动，使用默认驱动即可

# 编译程序
echo "编译程序..."
make clean
make

# 检查编译是否成功
if [ ! -f "./bin/suna_ai_dpi" ]; then
    echo "编译失败！"
    exit 1
fi

echo "编译成功！"

# 运行配置：
# - 1号核心处理port0的4个收发队列
# - 2,3号核心作为业务处理核心
echo "运行程序：512G内存，1G大页块，MLX CX6网卡配置"
./bin/suna_ai_dpi -l 0,1-3 --socket-mem=20 --file-prefix=mlxcx6 -- -p 0x1 -q port0:4 -r 1:port0.0-3 -w 2,3

echo "程序运行结束。"
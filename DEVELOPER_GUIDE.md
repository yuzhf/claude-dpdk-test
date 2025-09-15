# suna_ai_dpi 开发者指南

## 1. 程序概述

`suna_ai_dpi` 是一个基于 DPDK 的高性能网络流量分析程序，具备以下核心功能：

### 1.1 主要功能模块

1. **高性能包处理**：基于 DPDK 实现零拷贝包处理，支持多端口、多队列并行处理
2. **流表管理**：维护五元组流表，支持流超时和统计信息收集
3. **协议识别**：支持常见网络协议的识别和分类
4. **应用识别**：基于 Hyperscan 正则表达式引擎实现应用识别
5. **多维度统计**：提供详细的流量统计信息，包括包大小、速率、TCP 状态等
6. **ClickHouse 集成**：将统计结果实时导出到 ClickHouse 数据库
7. **实时统计线程**：独立的统计线程将实时状态信息输出到文件

### 1.2 技术架构

- 使用 DPDK 实现高性能包处理
- 采用多核心生产者-消费者模型
- 基于 rte_ring 无锁队列实现核心间数据传输
- 使用 Hyperscan 进行高性能应用识别
- 集成 ClickHouse 客户端实现实时数据导出
- 独立的实时统计线程，周期性将统计信息写入文件

## 2. 编译说明

### 2.1 编译环境要求

- CentOS/RHEL 8.x 或更高版本
- GCC 7.0 或更高版本
- DPDK 21.11 或更高版本（已包含在项目中）
- ClickHouse 21.0 或更高版本

### 2.2 编译步骤

1. 进入项目根目录：
   ```bash
   cd /path/to/suna_ai_dpi
   ```

2. 清理旧的编译文件（可选）：
   ```bash
   make clean
   ```

3. 编译程序：
   ```bash
   make
   ```

4. 编译成功后，可执行文件位于：
   ```
   bin/suna_ai_dpi
   ```

### 2.3 编译配置

项目使用 Makefile 进行编译配置，主要配置项包括：

- 编译器：gcc
- 优化选项：-O3 -march=znver1
- 包含路径：./include, ./dpdk-include, 外部库头文件等
- 链接库：DPDK 静态库、cJSON、libzmq、Hyperscan 等

## 3. 配置说明

### 3.1 系统配置要求

1. **大页内存配置**：
   ```bash
   echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
   mkdir -p /mnt/huge
   mount -t hugetlbfs nodev /mnt/huge
   ```

2. **绑定网卡到 DPDK**：
   ```bash
   # 使用 dpdk-devbind.py 绑定网卡
   dpdk-devbind.py -b vfio-pci 0000:xx:yy.z
   ```

### 3.2 程序配置参数

程序支持以下命令行参数：

```
-p, --portmask PORTMASK: 端口掩码 (默认: 0x3)
-q, --queues QUEUES: 队列配置，格式: port0:4,port1:4
-r, --rx-cores CORES: 接收核心配置，格式: 1:port0.0-3,2:port1.0-1,3:port1.2-3
-w, --worker-cores CORES: 工作核心配置，格式: 4,5,6
-h, --help: 显示帮助信息
```

### 3.3 实时统计配置

实时统计线程的配置在 `src/dpdk_multi_port.h` 中定义：

```c
#define DEFAULT_STATS_REFRESH_INTERVAL  1  /* 默认统计刷新间隔(秒) */
#define STATS_OUTPUT_FILE               "traffic_analysis.s"  /* 实时统计输出文件 */
```

如需修改，请在编译前修改这些宏定义。

### 3.4 ClickHouse 配置

ClickHouse 连接配置在 `src/dpdk_multi_port.h` 中定义：

```c
#define CLICKHOUSE_HOST     "127.0.0.1"
#define CLICKHOUSE_PORT     9000
#define CLICKHOUSE_DB       "traffic_analysis"
#define CLICKHOUSE_TABLE    "flow_stats"
```

如需修改，请在编译前修改这些宏定义。

## 4. 调试运行

### 4.1 基本运行步骤

1. 启动 ClickHouse 服务：
   ```bash
   sudo systemctl start clickhouse-server
   ```

2. 配置系统环境（大页内存、绑定网卡等）

3. 运行程序：
   ```bash
   sudo ./bin/suna_ai_dpi -l 0-6 -- -p 0x3 -q port0:4,port1:4 -r 1:port0.0-3,2:port1.0-1,3:port1.2-3 -w 4,5,6
   ```

### 4.2 运行参数示例

典型的运行命令：
```bash
sudo ./bin/suna_ai_dpi -l 0-6 -- -p 0x3 -q port0:4,port1:4 -r 1:port0.0-3,2:port1.0-1,3:port1.2-3 -w 4,5,6
```

参数说明：
- `-l 0-6`：使用逻辑核心 0-6
- `-p 0x3`：启用端口 0 和 1
- `-q port0:4,port1:4`：每个端口配置 4 个队列
- `-r 1:port0.0-3,2:port1.0-1,3:port1.2-3`：配置接收核心及其队列映射
- `-w 4,5,6`：配置工作核心

### 4.3 实时统计线程

程序包含一个独立的实时统计线程，周期性地将统计信息写入文件：

- **输出文件**：`traffic_analysis.s`（默认位于程序运行目录）
- **刷新间隔**：默认1秒刷新一次（可通过修改代码中的 `DEFAULT_STATS_REFRESH_INTERVAL` 常量调整）
- **文件内容**：包含所有统计信息，格式与终端输出相同
- **线程启动**：在程序初始化完成后自动启动统计线程
- **线程控制**：通过 `force_quit` 标志控制线程的启停

### 4.4 调试技巧

1. **查看日志**：程序使用 DPDK 日志系统，可通过设置日志级别查看详细信息
2. **性能监控**：程序会定期打印统计信息，可用于性能分析
3. **信号处理**：程序支持 SIGINT 和 SIGTERM 信号，用于优雅退出
4. **实时统计**：通过查看 `traffic_analysis.s` 文件可以实时监控程序状态

## 5. ClickHouse 数据库连接使用

### 5.1 数据库初始化

程序启动时会自动完成以下初始化操作：

1. 连接到 ClickHouse 服务器
2. 创建数据库 `traffic_analysis`（如果不存在）
3. 创建表 `flow_stats`（如果不存在）

### 5.2 数据表结构

`flow_stats` 表包含以下字段：

```sql
CREATE TABLE traffic_analysis.flow_stats (
    timestamp UInt64,           -- 记录时间戳
    src_ip String,              -- 源IP地址
    dst_ip String,              -- 目的IP地址
    src_port UInt16,            -- 源端口
    dst_port UInt16,            -- 目的端口
    protocol UInt8,             -- 协议类型
    total_packets UInt64,       -- 总包数
    total_bytes UInt64,         -- 总字节数
    up_packets UInt64,          -- 上行包数
    up_bytes UInt64,            -- 上行字节数
    down_packets UInt64,        -- 下行包数
    down_bytes UInt64,          -- 下行字节数
    duration UInt64,            -- 流持续时间
    avg_pps Float64,            -- 平均包速率
    avg_bps Float64,            -- 平均字节速率
    min_packet_size UInt32,     -- 最小包大小
    max_packet_size UInt32,     -- 最大包大小
    avg_packet_size UInt32,     -- 平均包大小
    protocol_name String,       -- 协议名称
    protocol_confidence UInt8,  -- 协议识别置信度
    app_name String,            -- 应用名称
    app_confidence UInt8,       -- 应用识别置信度
    matched_domain String,      -- 匹配的域名
    first_seen UInt64,          -- 首次发现时间
    last_seen UInt64,           -- 最后发现时间
    tcp_flags UInt32,           -- TCP标志位
    retransmissions UInt32,     -- 重传次数
    out_of_order UInt32,        -- 乱序包数
    lost_packets UInt32         -- 丢包数
) ENGINE = MergeTree()
ORDER BY (timestamp, src_ip, dst_ip)
SETTINGS index_granularity = 8192
```

### 5.3 数据导出机制

程序采用批量导出机制：

1. 在内存中缓存统计数据（默认缓存 1000 条记录）
2. 当缓存满或定期刷新时，将数据批量导出到 ClickHouse
3. 如果导出失败，数据会写入本地 CSV 文件作为备份

### 5.4 查询示例

以下是一些常用的查询示例：

1. 查询总记录数：
   ```sql
   SELECT count(*) FROM traffic_analysis.flow_stats;
   ```

2. 查询特定时间范围内的流量：
   ```sql
   SELECT * FROM traffic_analysis.flow_stats 
   WHERE timestamp >= 1630000000000 AND timestamp <= 1630003600000
   LIMIT 10;
   ```

3. 按应用类型统计流量：
   ```sql
   SELECT app_name, count(*) as flow_count, sum(total_bytes) as total_bytes
   FROM traffic_analysis.flow_stats
   GROUP BY app_name
   ORDER BY total_bytes DESC;
   ```

## 6. 实时统计线程实现

### 6.1 设计原理

实时统计线程是一个独立运行的线程，负责周期性地收集程序的运行状态并将其写入文件。该线程的设计考虑了以下几点：

1. **独立性**：统计线程独立于数据处理线程运行，不影响主业务逻辑
2. **低延迟**：默认1秒的刷新间隔，可以实时监控程序状态
3. **文件输出**：将统计信息写入文件，便于外部程序读取和监控

### 6.2 实现细节

实时统计线程的主要实现位于 `src/main.c` 文件中：

1. **线程函数**：`stats_thread_main()` 函数负责线程的主要逻辑
2. **文件输出**：`write_stats_to_file()` 函数负责将统计信息写入文件
3. **线程控制**：通过 `stats_thread_running` 标志控制线程的启停

### 6.3 扩展开发

如需扩展实时统计功能，可以考虑以下方向：

1. **自定义统计信息**：在 `write_stats_to_file()` 函数中添加自定义统计信息
2. **调整刷新间隔**：修改 `DEFAULT_STATS_REFRESH_INTERVAL` 常量调整刷新频率
3. **更改输出格式**：修改文件输出格式以适应特定监控需求
4. **多文件输出**：将不同类型的统计信息输出到不同文件

### 6.4 注意事项

1. 实时统计线程会占用一个逻辑核心，确保系统有足够的核心资源
2. 频繁的文件写入可能影响系统性能，建议根据实际需求调整刷新间隔
3. 输出文件会不断被覆盖，如需保留历史数据需要额外处理

## 7. 注意事项

### 7.1 系统要求

1. 需要 root 权限运行程序
2. 需要足够的大页内存（建议至少 1GB）
3. 需要支持 DPDK 的网卡
4. 需要预配置的 ClickHouse 服务器

### 7.2 性能优化建议

1. 合理分配核心资源，避免核心争用
2. 根据实际硬件配置调整队列数量
3. 确保充足的内存资源
4. 定期清理过期的流表项

### 7.3 故障排除

1. **程序无法启动**：
   - 检查是否以 root 权限运行
   - 检查大页内存是否配置正确
   - 检查网卡是否正确绑定到 DPDK

2. **ClickHouse 连接失败**：
   - 检查 ClickHouse 服务是否运行
   - 检查网络连接是否正常
   - 检查配置文件中的连接参数是否正确

3. **性能问题**：
   - 检查核心分配是否合理
   - 检查是否有核心争用
   - 检查内存使用情况

4. **程序退出卡住**：
   - 程序现在使用改进的信号处理机制，可以正常退出
   - 如果仍然卡住，请检查是否有线程没有正确停止
   - 可以使用 `kill -9` 强制终止进程（不推荐常规使用）

### 7.4 实时统计文件监控

1. **查看实时统计**：
   ```bash
   tail -f traffic_analysis.s
   ```

2. **监控统计文件更新**：
   ```bash
   watch -n 1 cat traffic_analysis.s
   ```

### 7.5 数据安全

1. 程序提供了数据备份机制，当 ClickHouse 连接失败时会将数据写入本地 CSV 文件
2. 建议定期备份 ClickHouse 数据库
3. 在生产环境中应配置适当的访问控制和安全策略
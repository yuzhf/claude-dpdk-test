/*
 * DPDK多网口多队列收发包程序 - 主要头文件
 * 支持多核心生产者消费者模型，基于rte_ring无锁队列实现
 * 扩展功能：协议识别、应用识别、多维度统计、ClickHouse输出
 */

#ifndef _DPDK_MULTI_PORT_H_
#define _DPDK_MULTI_PORT_H_

#include <stdint.h>
#include <stdbool.h>
#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_lcore.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

/* Hyperscan头文件 */
#include <hs.h>

/* 应用程序配置常量 */
#define MAX_PORTS           8       /* 最大网口数 */
#define MAX_QUEUES_PER_PORT 16      /* 每个网口最大队列数 */
#define MAX_RX_CORES        32      /* 最大接收核心数 */
#define MAX_WORKER_CORES    32      /* 最大业务核心数 */
#define MAX_RINGS           64      /* 最大ring数量 */

#define RX_RING_SIZE        4096    /* 接收ring大小 */
#define TX_RING_SIZE        4096    /* 发送ring大小 */
#define WORKER_RING_SIZE    8192    /* 业务处理ring大小 */

#define BURST_SIZE          32      /* 批量收发包大小 */
#define MBUF_CACHE_SIZE     512     /* mbuf缓存大小 */
#define MBUF_COUNT          8192    /* mbuf池大小 */

/* 时间和批处理常量 */
#define US_PER_S 1000000            /* 每秒微秒数 */
#define BURST_TX_DRAIN_US 100       /* 发送批处理排空时间(微秒) */

/* 五元组哈希表配置 */
#define FLOW_HASH_ENTRIES   1024*1024  /* 流表最大条目数 */
#define FLOW_TIMEOUT        10         /* 流超时时间(秒) */

/* 协议识别配置 */
#define MAX_PROTOCOL_RULES  10000       /* 最大协议规则数 */
#define MAX_PROTOCOL_NAME   64          /* 协议名称最大长度 */
#define PROTOCOL_CONFIG_FILE "./config/protocol_port_mapping.conf"

/* 应用识别配置 */
#define MAX_APP_RULES       50000       /* 最大应用规则数 */
#define MAX_APP_NAME        64          /* 应用名称最大长度 */
#define MAX_DOMAIN_LENGTH   256         /* 域名最大长度 */
#define APP_RULES_FILE      "./config/app_domain_rules.conf"

/* ClickHouse配置 */
#define CLICKHOUSE_HOST     "127.0.0.1"
#define CLICKHOUSE_PORT     8123
#define CLICKHOUSE_DB       "traffic_analysis"
#define CLICKHOUSE_TABLE    "flow_stats"
#define CH_BATCH_SIZE       1000        /* ClickHouse批量插入大小 */
#define CH_REALTIME_SIZE    1           /* ClickHouse实时模式批量大小 */
#define CH_FLUSH_INTERVAL   5           /* ClickHouse强制刷新间隔(秒) */

/* 实时统计配置 */
#define DEFAULT_STATS_REFRESH_INTERVAL  1  /* 默认统计刷新间隔(秒) */
#define STATS_OUTPUT_FILE               "traffic_analysis.s"  /* 实时统计输出文件 */

/* 流方向定义 */
#define FLOW_DIR_UPSTREAM   1           /* 上行 */
#define FLOW_DIR_DOWNSTREAM 2           /* 下行 */

/* 协议识别结果 */
struct protocol_info {
    uint16_t protocol_id;               /* 协议ID */
    char protocol_name[MAX_PROTOCOL_NAME]; /* 协议名称 */
    uint8_t confidence;                 /* 识别置信度 */
} __rte_packed;

/* 应用识别结果 */
struct app_info {
    uint16_t app_id;                    /* 应用ID */
    char app_name[MAX_APP_NAME];        /* 应用名称 */
    uint8_t confidence;                 /* 识别置信度 */
    char matched_domain[MAX_DOMAIN_LENGTH]; /* 匹配的域名 */
} __rte_packed;

/* 队列配置结构 */
struct queue_conf {
    uint16_t port_id;      /* 端口ID */
    uint16_t queue_id;     /* 队列ID */
    uint16_t lcore_id;     /* 绑定的逻辑核心ID */
};

/* 核心配置结构 */
struct lcore_conf {
    uint16_t lcore_id;                      /* 逻辑核心ID */
    uint16_t n_rx_queues;                   /* 接收队列数量 */
    struct queue_conf rx_queues[MAX_QUEUES_PER_PORT];  /* 接收队列配置 */
    uint16_t n_worker_rings;                /* 关联的worker ring数量 */
    struct rte_ring *worker_rings[MAX_WORKER_CORES];    /* worker ring指针 */
} __rte_cache_aligned;

/* 业务核心配置 */
struct worker_conf {
    uint16_t lcore_id;                      /* 逻辑核心ID */
    struct rte_ring *rx_ring;               /* 接收数据的ring */
    uint16_t n_producer_cores;              /* 生产者核心数量 */
    uint16_t producer_cores[MAX_RX_CORES];  /* 生产者核心ID列表 */
} __rte_cache_aligned;

/* 五元组结构 */
struct flow_key {
    uint32_t src_ip;        /* 源IP */
    uint32_t dst_ip;        /* 目的IP */
    uint16_t src_port;      /* 源端口 */
    uint16_t dst_port;      /* 目的端口 */
    uint8_t  protocol;      /* 协议类型 */
} __rte_packed;

/* 增强的流统计信息 */
struct flow_stats {
    /* 基础统计 */
    uint64_t packets;           /* 总包数量 */
    uint64_t bytes;             /* 总字节数 */

    /* 方向统计 */
    uint64_t up_packets;        /* 上行包数量 */
    uint64_t up_bytes;          /* 上行字节数 */
    uint64_t down_packets;      /* 下行包数量 */
    uint64_t down_bytes;        /* 下行字节数 */

    /* 时间统计 */
    uint64_t first_seen;        /* 首次发现时间 */
    uint64_t last_seen;         /* 最后发现时间 */
    uint64_t duration;          /* 流持续时间 */

    /* 速率统计 */
    double avg_pps;             /* 平均包速率 */
    double avg_bps;             /* 平均字节速率 */
    uint32_t peak_pps;          /* 峰值包速率 */
    uint64_t peak_bps;          /* 峰值字节速率 */

    /* 包大小统计 */
    uint32_t min_packet_size;   /* 最小包大小 */
    uint32_t max_packet_size;   /* 最大包大小 */
    uint32_t avg_packet_size;   /* 平均包大小 */

    /* TCP特有统计 */
    uint32_t tcp_flags;         /* TCP标志位统计 */
    uint16_t tcp_window_size;   /* TCP窗口大小 */
    uint32_t tcp_seq_gaps;      /* TCP序列号间隙 */

    /* 服务质量统计 */
    uint32_t retransmissions;   /* 重传计数 */
    uint32_t out_of_order;      /* 乱序包计数 */
    uint32_t lost_packets;      /* 丢包计数 */
} __rte_cache_aligned;

/* 增强的流信息结构 */
struct flow_info {
    struct flow_key key;                /* 五元组 */
    struct flow_stats stats;            /* 流统计信息 */
    struct protocol_info protocol;      /* 协议识别结果 */
    struct app_info application;        /* 应用识别结果 */

    uint8_t  flags;                     /* 流状态标志位 */
    uint8_t  direction_detected;        /* 方向检测标志 */
    uint32_t src_is_server;             /* 源端是否为服务器端 */

    /* 用于ClickHouse输出 */
    uint8_t  need_export;               /* 需要导出标志 */
    uint64_t last_exported;             /* 上次导出时间 */
} __rte_cache_aligned;

/* RX核心统计信息 */
struct rx_core_stats {
    uint64_t rx_packets;        /* 接收包数量 */
    uint64_t rx_bytes;          /* 接收字节数 */
    uint64_t rx_errors;         /* 接收错误数 */
    uint64_t ditr_packets;      /* 转发包数量 */
    uint64_t ditr_errors;       /* 转发错误数 */
    uint64_t dropped_packets;   /* 丢弃包数量 */
    uint64_t ring_full_drops;   /* Ring满导致的丢包 */
    uint64_t last_print_time;   /* 上次打印时间 */
} __rte_cache_aligned;

/* Worker核心统计信息 */
struct worker_core_stats {
    uint64_t rx_packets;            /* 接收包数量 */
    uint64_t rx_bytes;              /* 接收字节数 */
    uint64_t processed_packets;     /* 处理包数量 */
    uint64_t new_flows;             /* 新建流数量 */
    uint64_t existing_flows;        /* 现有流数量 */
    uint64_t dropped_packets;       /* 丢弃包数量 */
    uint64_t flow_lookup_failed;    /* 流查找失败数量 */
    uint64_t last_print_time;       /* 上次打印时间 */
} __rte_cache_aligned;

/* 应用程序配置结构 */
struct app_config {
    /* 端口配置 */
    uint16_t n_ports;                       /* 启用的端口数量 */
    uint16_t port_list[MAX_PORTS];          /* 端口ID列表 */
    uint16_t n_rx_queues[MAX_PORTS];        /* 每个端口的RX队列数 */
    uint16_t n_tx_queues[MAX_PORTS];        /* 每个端口的TX队列数 */

    /* 核心配置 */
    uint16_t n_rx_cores;                    /* 接收核心数量 */
    struct lcore_conf rx_lcore_conf[MAX_RX_CORES];  /* 接收核心配置 */

    uint16_t n_worker_cores;                /* 业务核心数量 */
    struct worker_conf worker_conf[MAX_WORKER_CORES];  /* 业务核心配置 */

    /* 统计线程核心配置 */
    uint16_t stats_lcore_id;                /* 统计线程核心ID */

    /* Ring配置 */
    struct rte_ring *worker_rings[MAX_RINGS];   /* worker ring数组 */
    uint16_t n_rings;                           /* ring数量 */

    /* 流表配置 */
    struct rte_hash *flow_hash;             /* 流哈希表 */
    struct flow_info *flow_table;           /* 流信息表 */

    /* 内存池 */
    struct rte_mempool *mbuf_pool[MAX_PORTS][MAX_QUEUES_PER_PORT];          /* mbuf内存池 */

    /* 协议识别配置 */
    void *protocol_engine;                  /* 协议识别引擎 */

    /* 应用识别配置 */
    hs_database_t *app_database;            /* Hyperscan数据库 */
    hs_scratch_t *app_scratch;              /* Hyperscan临时空间 */

    /* ClickHouse配置 */
    void *clickhouse_client;                /* ClickHouse客户端 */
    char ch_host[64];                       /* ClickHouse主机 */
    uint16_t ch_port;                       /* ClickHouse端口 */
    char ch_database[64];                   /* 数据库名 */
    char ch_table[64];                      /* 表名 */
};

/* 全局变量声明 */
extern struct app_config *g_app_config;
extern volatile bool force_quit;

/* 函数声明 */

/* 配置管理 */
int config_init(void);
int config_parse_args(int argc, char **argv);
void config_print(void);
void config_cleanup(void);

/* DPDK初始化 */
int dpdk_init(void);
int port_init(uint16_t port_id, uint16_t n_rx_queues, uint16_t n_tx_queues);
void dpdk_cleanup(void);

/* Ring管理 */
int rings_init(void);
struct rte_ring *get_worker_ring(uint16_t worker_id);
void rings_cleanup(void);
void ring_print_stats();

/* 流表管理 */
int flow_table_init(void);
int flow_table_add(struct flow_key *key, struct flow_info **info);
int flow_table_lookup(struct flow_key *key, struct flow_info **info);
void flow_table_cleanup(void);
void flow_table_stats_print(void);

/* 包处理 */
int extract_flow_key(struct rte_mbuf *pkt, struct flow_key *key);
void update_flow_stats(struct flow_info *info, struct rte_mbuf *pkt);

/* 核心处理函数 */
int rx_core_main(void *arg);
void print_rx_cores_summary();

int worker_core_main(void *arg);
void print_worker_cores_summary();

/* 工具函数 */
void print_stats(void);
void signal_handler(int sig);

/* 协议识别模块 */
int protocol_engine_init(void);
int protocol_identify(struct rte_mbuf *pkt, struct protocol_info *proto);
void protocol_engine_cleanup(void);

/* 应用识别模块 */
int app_engine_init(void);
int app_identify(struct rte_mbuf *pkt, struct app_info *app);
void app_engine_cleanup(void);

/* 增强流表统计 */
void flow_stats_init(struct flow_stats *stats);
void flow_stats_update(struct flow_stats *stats, struct rte_mbuf *pkt, uint8_t direction);
void flow_stats_calculate(struct flow_info *flow);

/* ClickHouse输出模块 */
int clickhouse_init(void);
int clickhouse_export_flow(struct flow_info *flow);
int clickhouse_export_batch(struct flow_info **flows, int count);
void clickhouse_cleanup(void);

/* 多维度统计输出 */
void print_enhanced_stats(void);
void print_protocol_stats(void);
void print_application_stats(void);

/* 增强流表统计 */
int enhanced_stats_init(void);
void enhanced_stats_cleanup(void);

/* ClickHouse输出模块 */
void print_clickhouse_stats(void);
int clickhouse_flush_buffer(void);

/* 流表管理 */
int flow_table_cleanup_expired(void);

/* 内联函数 - 五元组哈希 */
static inline uint32_t flow_hash_func(const void *key, uint32_t key_len, uint32_t init_val)
{
    const struct flow_key *fkey = (const struct flow_key *)key;
    uint32_t hash_val;

    /* 使用jhash计算五元组哈希值，处理可能的非对齐访问 */
    hash_val = rte_jhash((const void *)fkey,
                         sizeof(struct flow_key),
                         init_val);
    return hash_val;
}

/* 内联函数 - 判断流方向 */
static inline uint8_t determine_flow_direction(struct flow_key *key)
{
    /* 简单的方向判断逻辑：较大端口号通常是客户端 */
    if (key->src_port > key->dst_port) {
        return FLOW_DIR_UPSTREAM;   /* 源端口大，认为是上行 */
    } else {
        return FLOW_DIR_DOWNSTREAM; /* 目的端口大，认为是下行 */
    }
}

#endif /* _DPDK_MULTI_PORT_H_ */

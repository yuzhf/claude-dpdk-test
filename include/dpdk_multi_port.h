/*
 * DPDK多端口包处理头文件
 * 包含所有模块的公共定义和声明
 */

#ifndef _DPDK_MULTI_PORT_H_
#define _DPDK_MULTI_PORT_H_

#include <stdint.h>
#include <stdbool.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_hash.h>

/* 常量定义 */
#define MAX_PORTS           8
#define MAX_RX_QUEUES       16
#define MAX_TX_QUEUES       16
#define MAX_RX_CORES        16
#define MAX_WORKER_CORES    16
#define MAX_RINGS           64
#define BURST_SIZE          32
#define MBUF_CACHE_SIZE     512
#define MBUF_COUNT          8192
#define BURST_TX_DRAIN_US   100
#define US_PER_S            1000000
#define FLOW_HASH_ENTRIES   65536
#define FLOW_TIMEOUT        300  /* 5分钟 */

/* 队列配置结构 */
struct queue_conf {
    uint16_t port_id;
    uint16_t queue_id;
};

/* 核心配置结构 */
struct lcore_conf {
    uint16_t lcore_id;
    uint16_t n_rx_queues;
    struct queue_conf rx_queues[MAX_RX_QUEUES];
    uint16_t n_worker_rings;
    struct rte_ring *worker_rings[MAX_RINGS];
};

/* Worker核心配置结构 */
struct worker_conf {
    uint16_t lcore_id;
    uint16_t n_rings;
    struct rte_ring **rings;
};

/* 应用配置结构 */
struct app_config {
    uint16_t n_ports;
    uint16_t port_list[MAX_PORTS];
    uint16_t n_rx_queues[MAX_PORTS];
    uint16_t n_tx_queues[MAX_PORTS];
    uint16_t n_rx_cores;
    struct lcore_conf rx_lcore_conf[MAX_RX_CORES];
    uint16_t n_worker_cores;
    struct worker_conf worker_conf[MAX_WORKER_CORES];
    uint16_t n_rings;
    struct rte_mempool *mbuf_pool;
    struct rte_hash *flow_hash;
    void *flow_table;
};

/* 五元组流键 */
struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} __attribute__((packed));

/* 流统计信息 */
struct flow_stats {
    uint64_t packets;
    uint64_t bytes;
    uint64_t up_packets;
    uint64_t up_bytes;
    uint64_t down_packets;
    uint64_t down_bytes;
    uint64_t first_seen;
    uint64_t last_seen;
};

/* 流信息 */
struct flow_info {
    struct flow_key key;
    struct flow_stats stats;
    uint8_t flags;
    uint8_t tcp_flags;
    uint32_t retransmissions;
    uint32_t out_of_order;
    uint32_t lost_packets;
    char protocol_name[32];
    uint8_t protocol_confidence;
    char app_name[32];
    uint8_t app_confidence;
    char matched_domain[128];
};

/* RX核心统计信息 */
struct rx_core_stats {
    uint64_t rx_packets;        /* 接收包数量 */
    uint64_t rx_bytes;          /* 接收字节数 */
    uint64_t rx_errors;         /* 接收错误数 */
    uint64_t tx_packets;        /* 转发包数量 */
    uint64_t tx_errors;         /* 转发错误数 */
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

/* Ring统计信息 */
struct ring_stats {
    uint64_t enqueue_count;     /* 入队计数 */
    uint64_t dequeue_count;     /* 出队计数 */
    uint64_t enqueue_failed;    /* 入队失败计数 */
    uint64_t dequeue_failed;    /* 出队失败计数 */
    uint64_t ring_full;         /* Ring满计数 */
    uint64_t ring_empty;        /* Ring空计数 */
} __rte_cache_aligned;

/* Ring管理器 */
struct ring_manager {
    struct rte_ring **rings;        /* Ring指针数组 */
    struct ring_stats *stats;       /* 统计信息数组 */
    uint16_t n_rings;               /* Ring数量 */
    uint16_t ring_size;             /* Ring大小 */
};

/* 流表管理器 */
struct flow_table_manager {
    struct rte_hash *hash_table;        /* 哈希表 */
    struct flow_info *flow_entries;     /* 流条目数组 */
    uint32_t max_flows;                 /* 最大流数量 */
    uint32_t current_flows;             /* 当前流数量 */
    uint64_t flow_timeout_tsc;          /* 流超时周期数 */
    uint64_t last_cleanup_tsc;          /* 上次清理时间 */
    
    /* 统计信息 */
    uint64_t flows_created;             /* 创建的流数量 */
    uint64_t flows_expired;             /* 过期的流数量 */
    uint64_t flows_lookup_hit;          /* 查找命中次数 */
    uint64_t flows_lookup_miss;         /* 查找丢失次数 */
    uint64_t hash_collisions;           /* 哈希冲突次数 */
} __rte_cache_aligned;

/* 增强统计 */
struct global_stats {
    uint64_t stats_start_time;
    uint64_t stats_end_time;
    uint64_t total_flows;
    uint64_t active_flows;
    uint64_t expired_flows;
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t up_packets;
    uint64_t up_bytes;
    uint64_t down_packets;
    uint64_t down_bytes;
    int num_protocols;
    int num_apps;
    int num_ports;
    struct protocol_stats protocol_stats[256];
    struct app_stats app_stats[1000];
    struct port_stats port_stats[65536];
    struct top_stats top_protocols[10];
    struct top_stats top_apps[10];
    struct top_port_stats top_ports[10];
};

/* 协议统计 */
struct protocol_stats {
    char protocol_name[32];
    uint64_t flows;
    uint64_t packets;
    uint64_t bytes;
};

/* 应用统计 */
struct app_stats {
    char app_name[64];
    uint64_t flows;
    uint64_t packets;
    uint64_t bytes;
};

/* 端口统计 */
struct port_stats {
    uint16_t port;
    uint64_t flows;
    uint64_t packets;
    uint64_t bytes;
};

/* Top统计 */
struct top_stats {
    char name[64];
    uint64_t value;
};

/* Top端口统计 */
struct top_port_stats {
    uint16_t port;
    uint64_t value;
};

/* 全局配置变量 */
extern struct app_config *g_app_config;
extern struct ring_manager *g_ring_mgr;
extern struct flow_table_manager *g_flow_mgr;
extern struct global_stats *g_global_stats;

/* 函数声明 */
int config_init(void);
void config_cleanup(void);
int config_parse_args(int argc, char **argv);
void config_print(void);
void config_print_to_file(void (*write_func)(const char *format, ...));

int dpdk_init(void);
void dpdk_cleanup(void);

int rings_init(void);
void rings_cleanup(void);
int ring_enqueue_burst(struct rte_ring *ring, struct rte_mbuf **pkts, uint16_t n_pkts, uint16_t ring_idx);
int ring_dequeue_burst(struct rte_ring *ring, struct rte_mbuf **pkts, uint16_t n_pkts, uint16_t ring_idx);
void ring_print_stats(void);
void ring_get_stats(uint16_t ring_idx, struct ring_stats *stats_out);

int flow_table_init(void);
void flow_table_cleanup(void);
int flow_table_lookup(struct flow_key *key, struct flow_info **info);
int flow_table_add(struct flow_key *key, struct flow_info **info);
void update_flow_stats(struct flow_info *info, struct rte_mbuf *pkt);
int flow_table_cleanup_expired(void);
void flow_table_stats_print(void);

int protocol_engine_init(void);
void protocol_engine_cleanup(void);
int identify_protocol(struct rte_mbuf *pkt, struct flow_info *flow_info);

int app_engine_init(void);
void app_engine_cleanup(void);
int identify_application(struct rte_mbuf *pkt, struct flow_info *flow_info);

int clickhouse_init(void);
void clickhouse_cleanup(void);
int clickhouse_insert_flow(struct flow_info *flow_info);
void clickhouse_flush_buffer(void);

int enhanced_stats_init(void);
void enhanced_stats_cleanup(void);
void collect_global_stats(void);
void calculate_top_stats(void);
void print_enhanced_stats(void);
void print_protocol_stats(void);
void print_application_stats(void);
void print_clickhouse_stats(void);

void print_protocol_stats_to_file(void (*write_func)(const char *format, ...));
void print_application_stats_to_file(void (*write_func)(const char *format, ...));
void print_clickhouse_stats_to_file(void (*write_func)(const char *format, ...));

/* 内联函数声明 */
static inline uint32_t flow_hash_func(const void *key, uint32_t key_len, uint32_t init_val);
static inline uint8_t determine_flow_direction(struct flow_key *key);

/* 获取核心统计信息 */
void get_rx_core_stats(uint16_t rx_core_idx, struct rx_core_stats *stats_out);
void get_worker_core_stats(uint16_t worker_core_idx, struct worker_core_stats *stats_out);

/* ClickHouse配置 */
#define CLICKHOUSE_HOST     "127.0.0.1"
#define CLICKHOUSE_PORT     9000
#define CLICKHOUSE_DB       "traffic_analysis"
#define CLICKHOUSE_TABLE    "flow_stats"
#define CH_BATCH_SIZE       1000        /* ClickHouse批量插入大小 */

/* 实时统计配置 */
#define DEFAULT_STATS_REFRESH_INTERVAL  1  /* 默认统计刷新间隔(秒) */
#define STATS_OUTPUT_FILE               "traffic_analysis.s"  /* 实时统计输出文件 */

#endif /* _DPDK_MULTI_PORT_H_ */
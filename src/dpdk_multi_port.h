/*
 * DPDK多网口多队列收发包程序 - 主要头文件
 * 支持多核心生产者消费者模型，基于rte_ring无锁队列实现
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
#define MBUF_CACHE_SIZE     256     /* mbuf缓存大小 */
#define MBUF_COUNT          8192    /* mbuf池大小 */

/* 五元组哈希表配置 */
#define FLOW_HASH_ENTRIES   1024*1024  /* 流表最大条目数 */
#define FLOW_TIMEOUT        300         /* 流超时时间(秒) */

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

/* 流信息结构 */
struct flow_info {
    struct flow_key key;    /* 五元组 */
    uint64_t packets;       /* 包数量 */
    uint64_t bytes;         /* 字节数 */
    uint64_t first_seen;    /* 首次发现时间 */
    uint64_t last_seen;     /* 最后发现时间 */
    uint8_t  flags;         /* 流标志位 */
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
    
    /* Ring配置 */
    struct rte_ring *worker_rings[MAX_RINGS];   /* worker ring数组 */
    uint16_t n_rings;                           /* ring数量 */
    
    /* 流表配置 */
    struct rte_hash *flow_hash;             /* 流哈希表 */
    struct flow_info *flow_table;           /* 流信息表 */
    
    /* 内存池 */
    struct rte_mempool *mbuf_pool;          /* mbuf内存池 */
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
int worker_core_main(void *arg);

/* 工具函数 */
void print_stats(void);
void signal_handler(int sig);

/* 内联函数 - 五元组哈希 */
static inline uint32_t flow_hash_func(const void *key, uint32_t key_len, uint32_t init_val)
{
    const struct flow_key *fkey = (const struct flow_key *)key;
    uint32_t hash_val;
    
    /* 使用jhash计算五元组哈希值 */
    hash_val = rte_jhash_32b((const uint32_t *)fkey, 
                             sizeof(struct flow_key) / sizeof(uint32_t), 
                             init_val);
    return hash_val;
}

#endif /* _DPDK_MULTI_PORT_H_ */
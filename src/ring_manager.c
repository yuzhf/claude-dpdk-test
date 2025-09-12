/*
 * rte_ring无锁队列管理模块
 * 实现生产者消费者模式的无锁队列，支持m:n模型
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_lcore.h>

#include "dpdk_multi_port.h"

#define RTE_LOGTYPE_RING_MANAGER RTE_LOGTYPE_USER3

/* Ring统计信息 */
struct ring_stats {
    uint64_t enqueue_count;     /* 入队计数 */
    uint64_t dequeue_count;     /* 出队计数 */
    uint64_t enqueue_failed;    /* 入队失败计数 */
    uint64_t dequeue_failed;    /* 出队失败计数 */
    uint64_t ring_full;         /* Ring满计数 */
    uint64_t ring_empty;        /* Ring空计数 */
} __rte_cache_aligned;

/* Ring管理结构 */
struct ring_manager {
    struct rte_ring **rings;            /* Ring数组 */
    struct ring_stats *stats;           /* 统计信息数组 */
    uint16_t n_rings;                   /* Ring数量 */
    uint16_t n_producers;               /* 生产者数量 */
    uint16_t n_consumers;               /* 消费者数量 */
} __rte_cache_aligned;

static struct ring_manager *g_ring_mgr = NULL;

/* 创建单个Ring */
static struct rte_ring *create_single_ring(const char *name, unsigned count, int socket_id, unsigned flags)
{
    struct rte_ring *ring;
    
    ring = rte_ring_create(name, count, socket_id, flags);
    if (ring == NULL) {
        RTE_LOG(ERR, RING_MANAGER, "Cannot create ring %s: %s\n", name, rte_strerror(rte_errno));
        return NULL;
    }
    
    RTE_LOG(INFO, RING_MANAGER, "Created ring %s: size=%u, socket=%d, flags=0x%x\n",
            name, count, socket_id, flags);
    
    return ring;
}

/* 建立RX核心和Worker核心的Ring连接 */
static int setup_rx_worker_connections(void)
{
    int ring_idx = 0;
    char ring_name[RTE_RING_NAMESIZE];
    uint16_t i, j;
    
    /* 为每个RX核心创建到Worker核心的Ring */
    for (i = 0; i < g_app_config->n_rx_cores; i++) {
        struct lcore_conf *rx_lconf = &g_app_config->rx_lcore_conf[i];
        
        /* 为每个Worker核心创建一个Ring */
        for (j = 0; j < g_app_config->n_worker_cores; j++) {
            struct worker_conf *worker_conf = &g_app_config->worker_conf[j];
            
            snprintf(ring_name, sizeof(ring_name), "rx%u_worker%u",
                     rx_lconf->lcore_id, worker_conf->lcore_id);
            
            struct rte_ring *ring = create_single_ring(ring_name, WORKER_RING_SIZE,
                                                       rte_socket_id(),
                                                       RING_F_SP_ENQ | RING_F_SC_DEQ);
            if (ring == NULL) {
                return -1;
            }
            
            /* 将Ring添加到RX核心配置 */
            if (rx_lconf->n_worker_rings < MAX_WORKER_CORES) {
                rx_lconf->worker_rings[rx_lconf->n_worker_rings] = ring;
                rx_lconf->n_worker_rings++;
            }
            
            /* 将Ring设置给Worker核心 */
            if (worker_conf->rx_ring == NULL) {
                worker_conf->rx_ring = ring;
                worker_conf->n_producer_cores++;
                worker_conf->producer_cores[worker_conf->n_producer_cores - 1] = rx_lconf->lcore_id;
            }
            
            /* 将Ring添加到全局Ring数组 */
            if (ring_idx < MAX_RINGS) {
                g_app_config->worker_rings[ring_idx] = ring;
                ring_idx++;
            } else {
                RTE_LOG(ERR, RING_MANAGER, "Too many rings, maximum is %d\n", MAX_RINGS);
                return -1;
            }
        }
    }
    
    g_app_config->n_rings = ring_idx;
    
    RTE_LOG(INFO, RING_MANAGER, "Created %u rings for RX-Worker connections\n", ring_idx);
    return 0;
}

/* 初始化Ring管理器 */
int rings_init(void)
{
    int ret;
    
    RTE_LOG(INFO, RING_MANAGER, "Initializing rings...\n");
    
    /* 分配Ring管理器内存 */
    g_ring_mgr = rte_zmalloc("ring_manager", sizeof(struct ring_manager), RTE_CACHE_LINE_SIZE);
    if (g_ring_mgr == NULL) {
        RTE_LOG(ERR, RING_MANAGER, "Cannot allocate memory for ring manager\n");
        return -1;
    }
    
    /* 设置生产者和消费者数量 */
    g_ring_mgr->n_producers = g_app_config->n_rx_cores;
    g_ring_mgr->n_consumers = g_app_config->n_worker_cores;
    
    /* 建立RX核心和Worker核心的连接 */
    ret = setup_rx_worker_connections();
    if (ret != 0) {
        RTE_LOG(ERR, RING_MANAGER, "Failed to setup RX-Worker connections\n");
        rte_free(g_ring_mgr);
        g_ring_mgr = NULL;
        return ret;
    }
    
    /* 分配统计信息内存 */
    g_ring_mgr->stats = rte_zmalloc("ring_stats", 
                                    sizeof(struct ring_stats) * g_app_config->n_rings,
                                    RTE_CACHE_LINE_SIZE);
    if (g_ring_mgr->stats == NULL) {
        RTE_LOG(ERR, RING_MANAGER, "Cannot allocate memory for ring stats\n");
        rte_free(g_ring_mgr);
        g_ring_mgr = NULL;
        return -1;
    }
    
    g_ring_mgr->rings = g_app_config->worker_rings;
    g_ring_mgr->n_rings = g_app_config->n_rings;
    
    RTE_LOG(INFO, RING_MANAGER, "Ring initialization completed: %u rings, %u producers, %u consumers\n",
            g_ring_mgr->n_rings, g_ring_mgr->n_producers, g_ring_mgr->n_consumers);
    
    /* 打印Ring连接信息 */
    printf("\n=== Ring Connections ===\n");
    for (uint16_t i = 0; i < g_app_config->n_rx_cores; i++) {
        struct lcore_conf *rx_lconf = &g_app_config->rx_lcore_conf[i];
        printf("RX Core %u -> ", rx_lconf->lcore_id);
        for (uint16_t j = 0; j < rx_lconf->n_worker_rings; j++) {
            printf("Worker%u ", g_app_config->worker_conf[j].lcore_id);
        }
        printf("(%u rings)\n", rx_lconf->n_worker_rings);
    }
    
    for (uint16_t i = 0; i < g_app_config->n_worker_cores; i++) {
        struct worker_conf *worker_conf = &g_app_config->worker_conf[i];
        printf("Worker Core %u <- ", worker_conf->lcore_id);
        for (uint16_t j = 0; j < worker_conf->n_producer_cores; j++) {
            printf("RX%u ", worker_conf->producer_cores[j]);
        }
        printf("(%u producers)\n", worker_conf->n_producer_cores);
    }
    printf("========================\n\n");
    
    return 0;
}

/* 获取指定Worker的Ring */
struct rte_ring *get_worker_ring(uint16_t worker_id)
{
    if (worker_id >= g_app_config->n_worker_cores) {
        RTE_LOG(ERR, RING_MANAGER, "Invalid worker_id %u\n", worker_id);
        return NULL;
    }
    
    return g_app_config->worker_conf[worker_id].rx_ring;
}

/* 入队数据包到Ring（生产者使用）*/
int ring_enqueue_burst(struct rte_ring *ring, struct rte_mbuf **pkts, uint16_t n_pkts, uint16_t ring_idx)
{
    unsigned int enqueued;
    
    if (unlikely(ring == NULL || pkts == NULL || n_pkts == 0)) {
        return 0;
    }
    
    enqueued = rte_ring_enqueue_burst(ring, (void * const *)pkts, n_pkts, NULL);
    
    if (likely(g_ring_mgr && ring_idx < g_ring_mgr->n_rings)) {
        struct ring_stats *stats = &g_ring_mgr->stats[ring_idx];
        stats->enqueue_count += enqueued;
        
        if (unlikely(enqueued < n_pkts)) {
            stats->enqueue_failed += (n_pkts - enqueued);
            if (rte_ring_full(ring)) {
                stats->ring_full++;
            }
        }
    }
    
    return enqueued;
}

/* 从Ring出队数据包（消费者使用）*/
int ring_dequeue_burst(struct rte_ring *ring, struct rte_mbuf **pkts, uint16_t n_pkts, uint16_t ring_idx)
{
    unsigned int dequeued;
    
    if (unlikely(ring == NULL || pkts == NULL || n_pkts == 0)) {
        return 0;
    }
    
    dequeued = rte_ring_dequeue_burst(ring, (void **)pkts, n_pkts, NULL);
    
    if (likely(g_ring_mgr && ring_idx < g_ring_mgr->n_rings)) {
        struct ring_stats *stats = &g_ring_mgr->stats[ring_idx];
        stats->dequeue_count += dequeued;
        
        if (unlikely(dequeued == 0)) {
            stats->dequeue_failed++;
            if (rte_ring_empty(ring)) {
                stats->ring_empty++;
            }
        }
    }
    
    return dequeued;
}

/* 获取Ring状态信息 */
void ring_get_stats(uint16_t ring_idx, struct ring_stats *stats_out)
{
    if (g_ring_mgr == NULL || ring_idx >= g_ring_mgr->n_rings || stats_out == NULL) {
        memset(stats_out, 0, sizeof(struct ring_stats));
        return;
    }
    
    memcpy(stats_out, &g_ring_mgr->stats[ring_idx], sizeof(struct ring_stats));
}

/* 打印Ring统计信息 */
void ring_print_stats(void)
{
    struct ring_stats stats;
    uint16_t i;
    
    if (g_ring_mgr == NULL) {
        printf("Ring manager not initialized\n");
        return;
    }
    
    printf("\n=== Ring Statistics ===\n");
    printf("%-15s %-12s %-12s %-12s %-12s %-10s %-10s\n",
           "Ring", "Enqueue", "Dequeue", "Enq_Failed", "Deq_Failed", "Full", "Empty");
    printf("%-15s %-12s %-12s %-12s %-12s %-10s %-10s\n",
           "----", "-------", "-------", "----------", "----------", "----", "-----");
    
    for (i = 0; i < g_ring_mgr->n_rings; i++) {
        ring_get_stats(i, &stats);
        printf("ring%-11d %-12" PRIu64 " %-12" PRIu64 " %-12" PRIu64 " %-12" PRIu64 " %-10" PRIu64 " %-10" PRIu64 "\n",
               i,
               stats.enqueue_count,
               stats.dequeue_count,
               stats.enqueue_failed,
               stats.dequeue_failed,
               stats.ring_full,
               stats.ring_empty);
    }
    printf("=======================\n\n");
}

/* 清理Ring资源 */
void rings_cleanup(void)
{
    uint16_t i;
    
    if (g_ring_mgr == NULL) {
        return;
    }
    
    RTE_LOG(INFO, RING_MANAGER, "Cleaning up rings...\n");
    
    /* 打印最终统计信息 */
    ring_print_stats();
    
    /* 清理统计信息 */
    if (g_ring_mgr->stats) {
        rte_free(g_ring_mgr->stats);
        g_ring_mgr->stats = NULL;
    }
    
    /* Ring由DPDK自动清理，这里只需要清理管理结构 */
    for (i = 0; i < g_app_config->n_rings; i++) {
        g_app_config->worker_rings[i] = NULL;
    }
    g_app_config->n_rings = 0;
    
    /* 清理核心配置中的Ring引用 */
    for (i = 0; i < g_app_config->n_rx_cores; i++) {
        struct lcore_conf *lconf = &g_app_config->rx_lcore_conf[i];
        memset(lconf->worker_rings, 0, sizeof(lconf->worker_rings));
        lconf->n_worker_rings = 0;
    }
    
    for (i = 0; i < g_app_config->n_worker_cores; i++) {
        struct worker_conf *wconf = &g_app_config->worker_conf[i];
        wconf->rx_ring = NULL;
        wconf->n_producer_cores = 0;
        memset(wconf->producer_cores, 0, sizeof(wconf->producer_cores));
    }
    
    /* 清理管理器 */
    rte_free(g_ring_mgr);
    g_ring_mgr = NULL;
    
    RTE_LOG(INFO, RING_MANAGER, "Ring cleanup completed\n");
}

/* 检查Ring健康状态 */
int ring_health_check(void)
{
    uint16_t i;
    int issues = 0;
    
    if (g_ring_mgr == NULL) {
        RTE_LOG(ERR, RING_MANAGER, "Ring manager not initialized\n");
        return -1;
    }
    
    for (i = 0; i < g_ring_mgr->n_rings; i++) {
        struct rte_ring *ring = g_ring_mgr->rings[i];
        if (ring == NULL) {
            RTE_LOG(ERR, RING_MANAGER, "Ring %u is NULL\n", i);
            issues++;
            continue;
        }
        
        /* 检查Ring是否一直满 */
        if (rte_ring_full(ring)) {
            struct ring_stats *stats = &g_ring_mgr->stats[i];
            if (stats->ring_full > 1000) {  /* 阈值可调整 */
                RTE_LOG(WARNING, RING_MANAGER, "Ring %d is frequently full (count: %" PRIu64 ")\n",
                        i, stats->ring_full);
            }
        }
        
        /* 检查Ring是否一直空 */
        if (rte_ring_empty(ring)) {
            struct ring_stats *stats = &g_ring_mgr->stats[i];
            if (stats->ring_empty > 10000) {  /* 阈值可调整 */
                RTE_LOG(DEBUG, RING_MANAGER, "Ring %d is frequently empty (count: %" PRIu64 ")\n",
                        i, stats->ring_empty);
            }
        }
    }
    
    return issues;
}
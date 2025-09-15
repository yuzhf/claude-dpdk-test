/*
 * 多核心收包线程模块（生产者）
 * 负责从网卡队列收包，并通过rte_ring分发给业务核心
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_prefetch.h>
#include <rte_branch_prediction.h>
#include <rte_ring.h>

#include "dpdk_multi_port.h"

#define RTE_LOGTYPE_RX_CORE RTE_LOGTYPE_USER5


/* 全局RX统计信息 */
static struct rx_core_stats rx_stats[MAX_RX_CORES];
extern volatile bool force_quit;

/* 简单的负载均衡：基于包的五元组哈希选择worker核心 */
static inline uint16_t select_worker_ring(struct rte_mbuf *pkt, uint16_t n_workers)
{
#if 0
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    uint32_t hash_val = 0;

    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);

    /* 检查是否为IP包 */
    if (likely(eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))) {
        ipv4_hdr = (struct rte_ipv4_hdr *)((char *)eth_hdr + sizeof(struct rte_ether_hdr));

        /* 计算五元组哈希 */
        hash_val = rte_jhash_3words(ipv4_hdr->src_addr,
                                   ipv4_hdr->dst_addr,
                                   (uint32_t)ipv4_hdr->next_proto_id,
                                   0xdeadbeef);

        /* 如果是TCP/UDP，加入端口信息 */
        if (ipv4_hdr->next_proto_id == IPPROTO_TCP || ipv4_hdr->next_proto_id == IPPROTO_UDP) {
            uint16_t *ports = (uint16_t *)((char *)ipv4_hdr + (ipv4_hdr->version_ihl & 0x0F) * 4);
            hash_val = rte_jhash_2words(hash_val,
                                       (uint32_t)ports[0] << 16 | ports[1],
                                       0xdeadbeef);
        }
    } else {
        /* 非IP包，使用简单哈希 */
        hash_val = rte_jhash(eth_hdr, sizeof(struct rte_ether_hdr), 0xdeadbeef);
    }
#else
	uint32_t hash_val = pkt->hash.rss;
#endif

    return hash_val % n_workers;
}

/* 批量分发数据包到worker rings */
static void distribute_packets(struct rte_mbuf **pkts, uint16_t nb_pkts,
                              struct lcore_conf *lconf, uint16_t rx_core_idx)
{
    struct rte_mbuf *worker_pkts[MAX_WORKER_CORES][BURST_SIZE];
    uint16_t worker_counts[MAX_WORKER_CORES] = {0};
    uint16_t i, worker_idx, enqueued, remaining;
    struct rx_core_stats *stats = &rx_stats[rx_core_idx];

    /* 将包分配到不同的worker队列 */
    for (i = 0; i < nb_pkts; i++) {
        worker_idx = select_worker_ring(pkts[i], lconf->n_worker_rings);

        if (likely(worker_idx < lconf->n_worker_rings && worker_counts[worker_idx] < BURST_SIZE)) {
            worker_pkts[worker_idx][worker_counts[worker_idx]] = pkts[i];
            worker_counts[worker_idx]++;
        } else {
            /* 选择失败，使用轮询方式 */
            worker_idx = stats->ditr_packets % lconf->n_worker_rings;
            if (worker_counts[worker_idx] < BURST_SIZE) {
                worker_pkts[worker_idx][worker_counts[worker_idx]] = pkts[i];
                worker_counts[worker_idx]++;
            } else {
                /* Ring满，丢弃包 */
                rte_pktmbuf_free(pkts[i]);
                stats->dropped_packets++;
                stats->ditr_errors++;
            }
        }
    }

    /* 批量入队到各个worker ring */
    for (worker_idx = 0; worker_idx < lconf->n_worker_rings; worker_idx++) {
        if (worker_counts[worker_idx] > 0) {
            enqueued = rte_ring_enqueue_burst(lconf->worker_rings[worker_idx],
                                            (void **)worker_pkts[worker_idx],
                                            worker_counts[worker_idx], NULL);

            stats->ditr_packets += enqueued;
            remaining = worker_counts[worker_idx] - enqueued;

            /* 处理未能入队的包 */
            if (unlikely(remaining > 0)) {
                stats->ring_full_drops += remaining;

                /* 释放未能入队的包 */
                for (i = enqueued; i < worker_counts[worker_idx]; i++) {
                    rte_pktmbuf_free(worker_pkts[worker_idx][i]);
                }
            }
        }
    }
}

/* 处理单个RX队列 */
static inline void process_rx_queue(uint16_t port_id, uint16_t queue_id,
                                   struct lcore_conf *lconf, uint16_t rx_core_idx)
{
    struct rte_mbuf *pkts_burst[BURST_SIZE];
    uint16_t nb_rx, i;
    uint64_t total_bytes = 0;
    struct rx_core_stats *stats = &rx_stats[rx_core_idx];

    /* 批量接收数据包 */
    nb_rx = rte_eth_rx_burst(port_id, queue_id, pkts_burst, BURST_SIZE);
    if (unlikely(nb_rx == 0)) {
        return;
    }

    /* 预取前几个包的数据 */
    for (i = 0; i < RTE_MIN(nb_rx, 4); i++) {
        rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[i], void *));
    }

    /* 计算字节数 */
    for (i = 0; i < nb_rx; i++) {
        total_bytes += rte_pktmbuf_pkt_len(pkts_burst[i]);
    }

    /* 更新统计信息 */
    stats->rx_packets += nb_rx;
    stats->rx_bytes += total_bytes;

    /* 分发数据包到worker核心 */
    if (likely(lconf->n_worker_rings > 0)) {
        distribute_packets(pkts_burst, nb_rx, lconf, rx_core_idx);
    } else {
        /* 没有配置worker核心，直接丢弃 */
        for (i = 0; i < nb_rx; i++) {
            rte_pktmbuf_free(pkts_burst[i]);
        }
        stats->dropped_packets += nb_rx;
    }
}

/* 打印RX核心统计信息 */
static void print_rx_stats(uint16_t rx_core_idx, uint16_t lcore_id)
{
    struct rx_core_stats *stats = &rx_stats[rx_core_idx];
    uint64_t current_time = rte_get_timer_cycles();
    uint64_t elapsed_cycles = current_time - stats->last_print_time;
    double elapsed_seconds = (double)elapsed_cycles / rte_get_timer_hz();

	static uint64_t last_rx_packets = 0;
	static uint64_t last_rx_bytes = 0;

    if (elapsed_seconds >= 8.0) {
        uint64_t pps = (uint64_t)((stats->rx_packets - last_rx_packets) / elapsed_seconds);
        uint64_t bps = (uint64_t)((stats->rx_bytes - last_rx_bytes) * 8 / elapsed_seconds);

        RTE_LOG(INFO, RX_CORE,
                "RX Core %u: %" PRIu64 " pkts (%" PRIu64 " pps), "
                "%" PRIu64 " bytes (%" PRIu64 " bps), "
                "%" PRIu64 " dropped, %" PRIu64 " ring_full_drops\n",
                lcore_id, stats->rx_packets, pps, stats->rx_bytes, bps,
                stats->dropped_packets, stats->ring_full_drops);

        /* 重置统计周期 */
#if 0
        stats->rx_packets = 0;
        stats->rx_bytes = 0;
        stats->dropped_packets = 0;
        stats->ring_full_drops = 0;
#endif
        stats->last_print_time = current_time;
        last_rx_packets = stats->rx_packets;
        last_rx_bytes = stats->rx_bytes;
    }
}

/* RX核心主循环 */
int rx_core_main(void *arg)
{
    struct lcore_conf *lconf;
    uint16_t lcore_id, rx_core_idx;
    uint16_t i;
    uint64_t prev_tsc = 0, cur_tsc, diff_tsc;
    const uint64_t drain_tsc = (rte_get_timer_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

    lcore_id = rte_lcore_id();

    /* 查找当前核心的配置 */
    lconf = NULL;
    rx_core_idx = 0;
    for (i = 0; i < g_app_config->n_rx_cores; i++) {
        if (g_app_config->rx_lcore_conf[i].lcore_id == lcore_id) {
            lconf = &g_app_config->rx_lcore_conf[i];
            rx_core_idx = i;
            break;
        }
    }

    if (lconf == NULL) {
        RTE_LOG(ERR, RX_CORE, "Cannot find configuration for lcore %u\n", lcore_id);
        return -1;
    }

    RTE_LOG(INFO, RX_CORE, "RX Core %u started, processing %u queues\n",
            lcore_id, lconf->n_rx_queues);

    /* 初始化统计信息 */
    memset(&rx_stats[rx_core_idx], 0, sizeof(struct rx_core_stats));
    rx_stats[rx_core_idx].last_print_time = rte_get_timer_cycles();

    /* 主处理循环 */
    while (!force_quit) {
        cur_tsc = rte_rdtsc();
        diff_tsc = cur_tsc - prev_tsc;

        /* 处理所有配置的RX队列 */
        for (i = 0; i < lconf->n_rx_queues; i++) {
            struct queue_conf *qconf = &lconf->rx_queues[i];
            process_rx_queue(qconf->port_id, qconf->queue_id, lconf, rx_core_idx);
        }

        /* 定期打印统计信息 */
        if (unlikely(diff_tsc > drain_tsc)) {
            print_rx_stats(rx_core_idx, lcore_id);
            prev_tsc = cur_tsc;
        }
    }

    RTE_LOG(INFO, RX_CORE, "RX Core %u stopping...\n", lcore_id);

    /* 打印最终统计信息 */
    print_rx_stats(rx_core_idx, lcore_id);

    return 0;
}

/* 获取RX核心统计信息 */
void get_rx_core_stats(uint16_t rx_core_idx, struct rx_core_stats *stats_out)
{
    if (rx_core_idx < MAX_RX_CORES && stats_out) {
        memcpy(stats_out, &rx_stats[rx_core_idx], sizeof(struct rx_core_stats));
    }
}

/* 重置RX核心统计信息 */
void reset_rx_core_stats(void)
{
    memset(rx_stats, 0, sizeof(rx_stats));
    for (int i = 0; i < MAX_RX_CORES; i++) {
        rx_stats[i].last_print_time = rte_get_timer_cycles();
    }
}

/* 打印所有RX核心统计汇总 */
void print_rx_cores_summary(void)
{
    uint64_t total_rx_pkts = 0, total_rx_bytes = 0;
    uint64_t total_ditr_pkts = 0, total_dropped = 0;
    uint16_t i;

    printf("\n=== RX Cores Summary ===\n");
    printf("%-8s %-12s %-12s %-12s %-12s %-12s\n",
           "Core", "RX_Packets", "RX_Bytes", "Ditr_Packets", "Dropped", "Ring_Drops");
    printf("%-8s %-12s %-12s %-12s %-12s %-12s\n",
           "----", "----------", "--------", "----------", "-------", "----------");

    for (i = 0; i < g_app_config->n_rx_cores; i++) {
        struct rx_core_stats *stats = &rx_stats[i];
        uint16_t lcore_id = g_app_config->rx_lcore_conf[i].lcore_id;

        printf("%-8u %-12" PRIu64 " %-12" PRIu64 " %-12" PRIu64 " %-12" PRIu64 " %-12" PRIu64 "\n",
               lcore_id, stats->rx_packets, stats->rx_bytes, stats->ditr_packets,
               stats->dropped_packets, stats->ring_full_drops);

        total_rx_pkts += stats->rx_packets;
        total_rx_bytes += stats->rx_bytes;
        total_ditr_pkts += stats->ditr_packets;
        total_dropped += stats->dropped_packets;
    }

    printf("%-8s %-12s %-12s %-12s %-12s %-12s\n",
           "----", "----------", "--------", "----------", "-------", "----------");
    printf("%-8s %-12" PRIu64 " %-12" PRIu64 " %-12" PRIu64 " %-12" PRIu64 " %-12s\n",
           "Total", total_rx_pkts, total_rx_bytes, total_ditr_pkts, total_dropped, "-");
    printf("========================\n\n");
}

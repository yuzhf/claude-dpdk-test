/*
 * 多核心业务处理线程模块（消费者）
 * 负责从rte_ring接收数据包，进行流表处理和业务逻辑
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
#include <rte_prefetch.h>
#include <rte_branch_prediction.h>
#include <rte_ring.h>

#include "dpdk_multi_port.h"

#define RTE_LOGTYPE_WORKER RTE_LOGTYPE_USER6

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

/* 全局Worker统计信息 */
static struct worker_core_stats worker_stats[MAX_WORKER_CORES] __rte_cache_aligned;
extern volatile bool force_quit;

/* 处理单个数据包的业务逻辑 */
static int process_packet_business_logic(struct rte_mbuf *pkt, struct flow_info *flow, uint16_t worker_idx)
{
    struct worker_core_stats *stats = &worker_stats[worker_idx];
    uint8_t direction;
    
    /* 确定数据包方向 */
    direction = determine_flow_direction(&flow->key);
    
    /* 更新增强流统计 */
    flow_stats_update(&flow->stats, pkt, direction);
    
    /* 协议识别（只对新流进行识别，或者协议未识别的流）*/
    if (flow->protocol.protocol_id == 0) {
        if (protocol_identify(pkt, &flow->protocol) == 0) {
            RTE_LOG(DEBUG, WORKER, "Protocol identified: %s (confidence: %u)\n",
                    flow->protocol.protocol_name, flow->protocol.confidence);
        }
    }
    
    /* 应用识别（只对HTTP/HTTPS流量进行识别）*/
    if (flow->application.app_id == 0 && 
        (flow->key.dst_port == 80 || flow->key.dst_port == 443 || 
         flow->key.src_port == 80 || flow->key.src_port == 443)) {
        if (app_identify(pkt, &flow->application) == 0) {
            RTE_LOG(DEBUG, WORKER, "Application identified: %s (confidence: %u, domain: %s)\n",
                    flow->application.app_name, flow->application.confidence,
                    flow->application.matched_domain);
        }
    }
    
    /* 业务处理：根据协议类型进行不同处理 */
    switch (flow->key.protocol) {
    case IPPROTO_TCP:
        /* TCP包处理逻辑 */
        // 可以在这里添加TCP状态跟踪、会话分析等
        break;
        
    case IPPROTO_UDP:
        /* UDP包处理逻辑 */  
        // 可以在这里添加UDP流量分析等
        break;
        
    case IPPROTO_ICMP:
        /* ICMP包处理逻辑 */
        // 可以在这里添加ICMP消息分析等
        break;
        
    default:
        /* 其他协议处理 */
        break;
    }
    
    /* 标记需要导出到ClickHouse */
    flow->need_export = 1;
    
    stats->processed_packets++;
    
    /* 返回处理结果：
     * 0: 正常处理
     * 1: 需要转发
     * -1: 丢弃包
     */
    return 0;
}

/* 批量处理数据包 */
static void process_packets_batch(struct rte_mbuf **pkts, uint16_t nb_pkts, 
                                 uint16_t worker_idx)
{
    struct flow_key key;
    struct flow_info *flow_info;
    struct worker_core_stats *stats = &worker_stats[worker_idx];
    uint16_t i;
    int ret, flow_ret;
    
    /* 预取前几个包的数据 */
    for (i = 0; i < RTE_MIN(nb_pkts, 4); i++) {
        rte_prefetch0(rte_pktmbuf_mtod(pkts[i], void *));
    }
    
    /* 逐个处理数据包 */
    for (i = 0; i < nb_pkts; i++) {
        /* 预取下一个包 */
        if (i + 4 < nb_pkts) {
            rte_prefetch0(rte_pktmbuf_mtod(pkts[i + 4], void *));
        }
        
        stats->rx_packets++;
        stats->rx_bytes += rte_pktmbuf_pkt_len(pkts[i]);
        
        /* 提取五元组 */
        ret = extract_flow_key(pkts[i], &key);
        if (unlikely(ret < 0)) {
            /* 无法提取五元组，丢弃包 */
            rte_pktmbuf_free(pkts[i]);
            stats->dropped_packets++;
            continue;
        }
        
        /* 查找现有流 */
        flow_ret = flow_table_lookup(&key, &flow_info);
        if (flow_ret == 0) {
            /* 找到现有流 */
            stats->existing_flows++;
        } else if (flow_ret == -ENOENT) {
            /* 未找到流，创建新流 */
            flow_ret = flow_table_add(&key, &flow_info);
            if (flow_ret == 0) {
                stats->new_flows++;
            } else {
                /* 创建流失败，丢弃包 */
                RTE_LOG(DEBUG, WORKER, "Worker %u: Failed to create new flow\n", worker_idx);
                rte_pktmbuf_free(pkts[i]);
                stats->dropped_packets++;
                stats->flow_lookup_failed++;
                continue;
            }
        } else {
            /* 查找流失败，丢弃包 */
            RTE_LOG(DEBUG, WORKER, "Worker %u: Flow lookup failed\n", worker_idx);
            rte_pktmbuf_free(pkts[i]);
            stats->dropped_packets++;
            stats->flow_lookup_failed++;
            continue;
        }
        
        /* 执行业务处理逻辑 */
        ret = process_packet_business_logic(pkts[i], flow_info, worker_idx);
        
        /* 根据处理结果决定包的去向 */
        switch (ret) {
        case 0:
            /* 正常处理完成，释放包 */
            rte_pktmbuf_free(pkts[i]);
            break;
            
        case 1:
            /* 需要转发（暂未实现转发逻辑）*/
            rte_pktmbuf_free(pkts[i]);
            break;
            
        case -1:
        default:
            /* 丢弃包 */
            rte_pktmbuf_free(pkts[i]);
            stats->dropped_packets++;
            break;
        }
    }
}

/* 打印Worker核心统计信息 */
static void print_worker_stats(uint16_t worker_idx, uint16_t lcore_id)
{
    struct worker_core_stats *stats = &worker_stats[worker_idx];
    uint64_t current_time = rte_get_timer_cycles();
    uint64_t elapsed_cycles = current_time - stats->last_print_time;
    double elapsed_seconds = (double)elapsed_cycles / rte_get_timer_hz();
    
    if (elapsed_seconds >= 5.0) {  /* 每5秒打印一次 */
        uint64_t pps = (uint64_t)(stats->rx_packets / elapsed_seconds);
        uint64_t bps = (uint64_t)(stats->rx_bytes * 8 / elapsed_seconds);
        
        RTE_LOG(INFO, WORKER, 
                "Worker Core %u: %" PRIu64 " pkts (%" PRIu64 " pps), "
                "%" PRIu64 " bytes (%" PRIu64 " bps), "
                "%" PRIu64 " processed, %" PRIu64 " new_flows, "
                "%" PRIu64 " dropped\n",
                lcore_id, stats->rx_packets, pps, stats->rx_bytes, bps,
                stats->processed_packets, stats->new_flows, stats->dropped_packets);
        
        /* 重置统计周期 */
        stats->rx_packets = 0;
        stats->rx_bytes = 0;
        stats->processed_packets = 0;
        stats->new_flows = 0;
        stats->dropped_packets = 0;
        stats->existing_flows = 0;
        stats->flow_lookup_failed = 0;
        stats->last_print_time = current_time;
    }
}

/* Worker核心主循环 */
int worker_core_main(void *arg)
{
    struct worker_conf *wconf;
    uint16_t lcore_id, worker_idx;
    struct rte_mbuf *pkts_burst[BURST_SIZE];
    uint16_t nb_rx;
    uint64_t prev_tsc = 0, cur_tsc, diff_tsc;
    const uint64_t drain_tsc = (rte_get_timer_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
    
    lcore_id = rte_lcore_id();
    
    /* 查找当前核心的配置 */
    wconf = NULL;
    worker_idx = 0;
    for (uint16_t i = 0; i < g_app_config->n_worker_cores; i++) {
        if (g_app_config->worker_conf[i].lcore_id == lcore_id) {
            wconf = &g_app_config->worker_conf[i];
            worker_idx = i;
            break;
        }
    }
    
    if (wconf == NULL) {
        RTE_LOG(ERR, WORKER, "Cannot find configuration for worker lcore %u\n", lcore_id);
        return -1;
    }
    
    if (wconf->rx_ring == NULL) {
        RTE_LOG(ERR, WORKER, "Worker lcore %u has no input ring\n", lcore_id);
        return -1;
    }
    
    RTE_LOG(INFO, WORKER, "Worker Core %u started, worker_idx: %d\n", 
            lcore_id, worker_idx);
    
    /* 初始化统计信息 */
    memset(&worker_stats[worker_idx], 0, sizeof(struct worker_core_stats));
    worker_stats[worker_idx].last_print_time = rte_get_timer_cycles();
    
    /* 主处理循环 */
    while (!force_quit) {
        cur_tsc = rte_rdtsc();
        diff_tsc = cur_tsc - prev_tsc;
        
        /* 从Ring接收数据包 */
        nb_rx = rte_ring_dequeue_burst(wconf->rx_ring, (void **)pkts_burst, BURST_SIZE, NULL);
        
        if (likely(nb_rx > 0)) {
            /* 批量处理数据包 */
            process_packets_batch(pkts_burst, nb_rx, worker_idx);
        }
        
        /* 定期执行维护任务 */
        if (unlikely(diff_tsc > drain_tsc)) {
            /* 打印统计信息 */
            print_worker_stats(worker_idx, lcore_id);
            
            /* 清理过期流（只有一个worker负责，避免竞争）*/
            if (worker_idx == 0) {
                flow_table_cleanup_expired();
                
                /* 定期导出流数据到ClickHouse */
                clickhouse_flush_buffer();
            }
            
            prev_tsc = cur_tsc;
        }
    }
    
    RTE_LOG(INFO, WORKER, "Worker Core %u stopping...\n", lcore_id);
    
    /* 处理剩余的数据包 */
    do {
        nb_rx = rte_ring_dequeue_burst(wconf->rx_ring, (void **)pkts_burst, BURST_SIZE, NULL);
        if (nb_rx > 0) {
            /* 简单释放包，不再进行业务处理 */
            for (uint16_t i = 0; i < nb_rx; i++) {
                rte_pktmbuf_free(pkts_burst[i]);
            }
        }
    } while (nb_rx > 0);
    
    /* 打印最终统计信息 */
    print_worker_stats(worker_idx, lcore_id);
    
    return 0;
}

/* 获取Worker核心统计信息 */
void get_worker_core_stats(uint16_t worker_idx, struct worker_core_stats *stats_out)
{
    if (worker_idx < MAX_WORKER_CORES && stats_out) {
        memcpy(stats_out, &worker_stats[worker_idx], sizeof(struct worker_core_stats));
    }
}

/* 重置Worker核心统计信息 */
void reset_worker_core_stats(void)
{
    memset(worker_stats, 0, sizeof(worker_stats));
    for (int i = 0; i < MAX_WORKER_CORES; i++) {
        worker_stats[i].last_print_time = rte_get_timer_cycles();
    }
}

/* 打印所有Worker核心统计汇总 */
void print_worker_cores_summary(void)
{
    uint64_t total_rx_pkts = 0, total_rx_bytes = 0;
    uint64_t total_processed = 0, total_new_flows = 0, total_dropped = 0;
    uint16_t i;
    
    printf("\n=== Worker Cores Summary ===\n");
    printf("%-8s %-12s %-12s %-12s %-12s %-12s\n",
           "Core", "RX_Packets", "RX_Bytes", "Processed", "New_Flows", "Dropped");
    printf("%-8s %-12s %-12s %-12s %-12s %-12s\n",
           "----", "----------", "--------", "---------", "---------", "-------");
    
    for (i = 0; i < g_app_config->n_worker_cores; i++) {
        struct worker_core_stats *stats = &worker_stats[i];
        uint16_t lcore_id = g_app_config->worker_conf[i].lcore_id;
        
        printf("%-8u %-12" PRIu64 " %-12" PRIu64 " %-12" PRIu64 " %-12" PRIu64 " %-12" PRIu64 "\n",
               lcore_id, stats->rx_packets, stats->rx_bytes, stats->processed_packets,
               stats->new_flows, stats->dropped_packets);
        
        total_rx_pkts += stats->rx_packets;
        total_rx_bytes += stats->rx_bytes;
        total_processed += stats->processed_packets;
        total_new_flows += stats->new_flows;
        total_dropped += stats->dropped_packets;
    }
    
    printf("%-8s %-12s %-12s %-12s %-12s %-12s\n",
           "----", "----------", "--------", "---------", "---------", "-------");
    printf("%-8s %-12" PRIu64 " %-12" PRIu64 " %-12" PRIu64 " %-12" PRIu64 " %-12" PRIu64 "\n",
           "Total", total_rx_pkts, total_rx_bytes, total_processed, total_new_flows, total_dropped);
    printf("============================\n\n");
}
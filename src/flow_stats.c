/*
 * 增强流统计功能实现
 * 支持上下行多维度统计和详细的流量分析
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_cycles.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "dpdk_multi_port.h"

#define RTE_LOGTYPE_FLOW_STATS RTE_LOGTYPE_USER12

/* 初始化流统计信息 */
void flow_stats_init(struct flow_stats *stats)
{
    if (stats == NULL) {
        return;
    }
    
    memset(stats, 0, sizeof(struct flow_stats));
    
    /* 设置初始值 */
    stats->first_seen = rte_get_timer_cycles();
    stats->last_seen = stats->first_seen;
    stats->min_packet_size = UINT32_MAX;
    stats->max_packet_size = 0;
}

/* 更新流统计信息 */
void flow_stats_update(struct flow_stats *stats, struct rte_mbuf *pkt, uint8_t direction)
{
    uint32_t pkt_size;
    uint64_t current_time;
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_tcp_hdr *tcp_hdr;
    
    if (stats == NULL || pkt == NULL) {
        return;
    }
    
    pkt_size = rte_pktmbuf_pkt_len(pkt);
    current_time = rte_get_timer_cycles();
    
    /* 更新基础统计 */
    stats->packets++;
    stats->bytes += pkt_size;
    stats->last_seen = current_time;
    
    /* 更新方向统计 */
    if (direction == FLOW_DIR_UPSTREAM) {
        stats->up_packets++;
        stats->up_bytes += pkt_size;
    } else if (direction == FLOW_DIR_DOWNSTREAM) {
        stats->down_packets++;
        stats->down_bytes += pkt_size;
    }
    
    /* 更新包大小统计 */
    if (pkt_size < stats->min_packet_size) {
        stats->min_packet_size = pkt_size;
    }
    if (pkt_size > stats->max_packet_size) {
        stats->max_packet_size = pkt_size;
    }
    
    /* 计算平均包大小 */
    stats->avg_packet_size = (uint32_t)(stats->bytes / stats->packets);
    
    /* 处理TCP特有统计 */
    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    if (rte_be_to_cpu_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_IPV4) {
        ipv4_hdr = (struct rte_ipv4_hdr *)((char *)eth_hdr + sizeof(struct rte_ether_hdr));
        
        if (ipv4_hdr->next_proto_id == IPPROTO_TCP) {
            uint8_t ip_hdr_len = (ipv4_hdr->version_ihl & 0x0F) * 4;
            
            if (rte_pktmbuf_data_len(pkt) >= sizeof(struct rte_ether_hdr) + ip_hdr_len + sizeof(struct rte_tcp_hdr)) {
                tcp_hdr = (struct rte_tcp_hdr *)((char *)ipv4_hdr + ip_hdr_len);
                
                /* 记录TCP标志位 */
                stats->tcp_flags |= tcp_hdr->tcp_flags;
                
                /* 更新TCP窗口大小 */
                uint16_t window_size = rte_be_to_cpu_16(tcp_hdr->rx_win);
                if (window_size > stats->tcp_window_size) {
                    stats->tcp_window_size = window_size;
                }
                
                /* 简单的重传检测（基于标志位）*/
                if (tcp_hdr->tcp_flags & (RTE_TCP_RST_FLAG | RTE_TCP_FIN_FLAG)) {
                    /* 可以在这里添加更复杂的重传检测逻辑 */
                }
            }
        }
    }
}

/* 计算流的衍生统计信息 */
void flow_stats_calculate(struct flow_info *flow)
{
    uint64_t duration_cycles, duration_sec;
    
    if (flow == NULL) {
        return;
    }
    
    /* 计算流持续时间 */
    duration_cycles = flow->stats.last_seen - flow->stats.first_seen;
    duration_sec = duration_cycles / rte_get_timer_hz();
    flow->stats.duration = duration_sec;
    
    /* 计算平均速率 */
    if (duration_sec > 0) {
        flow->stats.avg_pps = (double)flow->stats.packets / duration_sec;
        flow->stats.avg_bps = (double)flow->stats.bytes * 8 / duration_sec;
    } else {
        flow->stats.avg_pps = 0;
        flow->stats.avg_bps = 0;
    }
    
    /* 计算峰值速率（简化实现）*/
    /* 实际应用中可以使用滑动窗口来计算真实的峰值 */
    flow->stats.peak_pps = (uint32_t)(flow->stats.avg_pps * 1.5);  /* 估算 */
    flow->stats.peak_bps = (uint64_t)(flow->stats.avg_bps * 1.5);  /* 估算 */
    
    /* 修正最小包大小 */
    if (flow->stats.min_packet_size == UINT32_MAX) {
        flow->stats.min_packet_size = 0;
    }
}
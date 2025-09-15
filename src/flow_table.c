/*
 * 五元组流表管理模块
 * 负责维护数据流的五元组信息，支持流的创建、查找、更新和老化
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/time.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_cycles.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_byteorder.h>

#include "dpdk_multi_port.h"

#define RTE_LOGTYPE_FLOW RTE_LOGTYPE_USER5

/* 流状态标志 */
#define FLOW_STATE_NEW      0x01    /* 新建流 */
#define FLOW_STATE_ACTIVE   0x02    /* 活跃流 */
#define FLOW_STATE_CLOSING  0x04    /* 关闭中 */
#define FLOW_STATE_EXPIRED  0x08    /* 已过期 */

/* TCP标志位 */
#define TCP_FLAG_FIN        0x01
#define TCP_FLAG_SYN        0x02
#define TCP_FLAG_RST        0x04
#define TCP_FLAG_PSH        0x08
#define TCP_FLAG_ACK        0x10
#define TCP_FLAG_URG        0x20

/* 流表管理结构 */
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

static struct flow_table_manager *g_flow_mgr = NULL;

/* 从数据包中提取五元组 */
int extract_flow_key(struct rte_mbuf *pkt, struct flow_key *key)
{
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_tcp_hdr *tcp_hdr;
    struct rte_udp_hdr *udp_hdr;
    uint16_t ether_type;

    if (unlikely(pkt == NULL || key == NULL)) {
        return -1;
    }

    /* 清零key */
    memset(key, 0, sizeof(struct flow_key));

    /* 获取以太网头 */
    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

    /* 只处理IPv4包 */
    if (unlikely(ether_type != RTE_ETHER_TYPE_IPV4)) {
        return -1;
    }

    /* 检查包长度 */
    if (unlikely(rte_pktmbuf_data_len(pkt) < sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr))) {
        return -1;
    }

    /* 获取IPv4头 */
    ipv4_hdr = (struct rte_ipv4_hdr *)((char *)eth_hdr + sizeof(struct rte_ether_hdr));

    /* 提取IP地址和协议 */
    key->src_ip = rte_be_to_cpu_32(ipv4_hdr->src_addr);
    key->dst_ip = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
    key->protocol = ipv4_hdr->next_proto_id;

    /* 根据协议类型提取端口信息 */
    uint8_t ip_hdr_len = (ipv4_hdr->version_ihl & 0x0F) * 4;
    char *l4_hdr = (char *)ipv4_hdr + ip_hdr_len;

    switch (key->protocol) {
    case IPPROTO_TCP:
        if (unlikely(rte_pktmbuf_data_len(pkt) < sizeof(struct rte_ether_hdr) + ip_hdr_len + sizeof(struct rte_tcp_hdr))) {
            return -1;
        }
        tcp_hdr = (struct rte_tcp_hdr *)l4_hdr;
        key->src_port = rte_be_to_cpu_16(tcp_hdr->src_port);
        key->dst_port = rte_be_to_cpu_16(tcp_hdr->dst_port);
        break;

    case IPPROTO_UDP:
        if (unlikely(rte_pktmbuf_data_len(pkt) < sizeof(struct rte_ether_hdr) + ip_hdr_len + sizeof(struct rte_udp_hdr))) {
            return -1;
        }
        udp_hdr = (struct rte_udp_hdr *)l4_hdr;
        key->src_port = rte_be_to_cpu_16(udp_hdr->src_port);
        key->dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
        break;

    case IPPROTO_ICMP:
        /* ICMP没有端口概念，使用type和code */
        key->src_port = 0;
        key->dst_port = 0;
        break;

    default:
        /* 其他协议 */
        key->src_port = 0;
        key->dst_port = 0;
        break;
    }

    return 0;
}

/* 初始化流表 */
int flow_table_init(void)
{
    struct rte_hash_parameters hash_params = {0};
    char hash_name[RTE_HASH_NAMESIZE];

    RTE_LOG(INFO, FLOW, "Initializing flow table...\n");

    /* 分配流表管理器内存 */
    g_flow_mgr = rte_zmalloc("flow_table_manager", sizeof(struct flow_table_manager), RTE_CACHE_LINE_SIZE);
    if (g_flow_mgr == NULL) {
        RTE_LOG(ERR, FLOW, "Cannot allocate memory for flow table manager\n");
        return -1;
    }

    g_flow_mgr->max_flows = FLOW_HASH_ENTRIES;
    g_flow_mgr->flow_timeout_tsc = FLOW_TIMEOUT * rte_get_timer_hz();

    /* 分配流条目数组 */
    g_flow_mgr->flow_entries = rte_zmalloc("flow_entries",
                                          sizeof(struct flow_info) * g_flow_mgr->max_flows,
                                          RTE_CACHE_LINE_SIZE);
    if (g_flow_mgr->flow_entries == NULL) {
        RTE_LOG(ERR, FLOW, "Cannot allocate memory for flow entries\n");
        rte_free(g_flow_mgr);
        g_flow_mgr = NULL;
        return -1;
    }

    /* 创建哈希表 */
    snprintf(hash_name, sizeof(hash_name), "flow_hash_table");
    hash_params.name = hash_name;
    hash_params.entries = g_flow_mgr->max_flows;
    hash_params.key_len = sizeof(struct flow_key);
    hash_params.hash_func = flow_hash_func;
    hash_params.hash_func_init_val = 0;
    hash_params.socket_id = rte_socket_id();
    hash_params.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY;

    g_flow_mgr->hash_table = rte_hash_create(&hash_params);
    if (g_flow_mgr->hash_table == NULL) {
        RTE_LOG(ERR, FLOW, "Cannot create flow hash table: %s\n", rte_strerror(rte_errno));
        rte_free(g_flow_mgr->flow_entries);
        rte_free(g_flow_mgr);
        g_flow_mgr = NULL;
        return -1;
    }

    /* 设置全局配置指针 */
    g_app_config->flow_hash = g_flow_mgr->hash_table;
    g_app_config->flow_table = g_flow_mgr->flow_entries;

    g_flow_mgr->last_cleanup_tsc = rte_get_timer_cycles();

    RTE_LOG(INFO, FLOW, "Flow table initialized: max_flows=%u, timeout=%us\n\n",
            g_flow_mgr->max_flows, FLOW_TIMEOUT);

    return 0;
}

/* 查找流 */
int flow_table_lookup(struct flow_key *key, struct flow_info **info)
{
    int32_t ret;
    uint32_t flow_idx;

    if (unlikely(g_flow_mgr == NULL || key == NULL || info == NULL)) {
        return -1;
    }

    ret = rte_hash_lookup(g_flow_mgr->hash_table, key);
    if (ret >= 0) {
        /* 找到流 */
        flow_idx = (uint32_t)ret;
        *info = &g_flow_mgr->flow_entries[flow_idx];
        g_flow_mgr->flows_lookup_hit++;
        return 0;
    } else if (ret == -ENOENT) {
        /* 未找到流 */
        *info = NULL;
        g_flow_mgr->flows_lookup_miss++;
        return -ENOENT;
    } else {
        /* 其他错误 */
        *info = NULL;
        return ret;
    }
}

/* 添加新流 */
int flow_table_add(struct flow_key *key, struct flow_info **info)
{
    int32_t ret;
    uint32_t flow_idx;
    struct flow_info *flow_entry;
    uint64_t current_time = rte_get_timer_cycles();

    if (unlikely(g_flow_mgr == NULL || key == NULL || info == NULL)) {
        return -1;
    }

    /* 检查是否已达到最大流数量 */
    if (g_flow_mgr->current_flows >= g_flow_mgr->max_flows) {
        RTE_LOG(WARNING, FLOW, "Flow table is full, current flows: %u\n", g_flow_mgr->current_flows);
        return -ENOSPC;
    }

    /* 添加到哈希表 */
    ret = rte_hash_add_key(g_flow_mgr->hash_table, key);
    if (ret < 0) {
        if (ret == -ENOSPC) {
            RTE_LOG(WARNING, FLOW, "Hash table is full\n");
        } else {
            RTE_LOG(ERR, FLOW, "Failed to add flow to hash table: %s\n", rte_strerror(-ret));
        }
        return ret;
    }

    flow_idx = (uint32_t)ret;
    flow_entry = &g_flow_mgr->flow_entries[flow_idx];

    /* 初始化流信息 */
    memcpy(&flow_entry->key, key, sizeof(struct flow_key));
    flow_entry->stats.packets = 0;
    flow_entry->stats.bytes = 0;
    flow_entry->stats.first_seen = current_time;
    flow_entry->stats.last_seen = current_time;
    flow_entry->flags = FLOW_STATE_NEW;

    g_flow_mgr->current_flows++;
    g_flow_mgr->flows_created++;

    *info = flow_entry;

    RTE_LOG(DEBUG, FLOW, "New flow added: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u proto=%u\n",
            (key->src_ip >> 24) & 0xFF, (key->src_ip >> 16) & 0xFF,
            (key->src_ip >> 8) & 0xFF, key->src_ip & 0xFF, key->src_port,
            (key->dst_ip >> 24) & 0xFF, (key->dst_ip >> 16) & 0xFF,
            (key->dst_ip >> 8) & 0xFF, key->dst_ip & 0xFF, key->dst_port,
            key->protocol);

    return 0;
}

/* 更新流统计信息 */
void update_flow_stats(struct flow_info *info, struct rte_mbuf *pkt)
{
    if (unlikely(info == NULL || pkt == NULL)) {
        return;
    }

    info->stats.packets++;
    info->stats.bytes += rte_pktmbuf_pkt_len(pkt);
    info->stats.last_seen = rte_get_timer_cycles();

    /* 更新流状态 */
    if (info->flags & FLOW_STATE_NEW) {
        info->flags = FLOW_STATE_ACTIVE;
    }

    /* 检查TCP标志位 */
    if (info->key.protocol == IPPROTO_TCP) {
        struct rte_ether_hdr *eth_hdr;
        struct rte_ipv4_hdr *ipv4_hdr;
        struct rte_tcp_hdr *tcp_hdr;

        eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
        ipv4_hdr = (struct rte_ipv4_hdr *)((char *)eth_hdr + sizeof(struct rte_ether_hdr));
        uint8_t ip_hdr_len = (ipv4_hdr->version_ihl & 0x0F) * 4;
        tcp_hdr = (struct rte_tcp_hdr *)((char *)ipv4_hdr + ip_hdr_len);

        /* 检查连接关闭标志 */
        if (tcp_hdr->tcp_flags & (TCP_FLAG_FIN | TCP_FLAG_RST)) {
            info->flags |= FLOW_STATE_CLOSING;
        }
    }
}

/* 删除过期流 */
static int remove_expired_flow(const struct flow_key *key, uint32_t flow_idx)
{
    int ret;
    struct flow_info *flow = &g_flow_mgr->flow_entries[flow_idx];

    /* 在删除前先导出到ClickHouse（如果有数据且需要导出）*/
    if (flow->need_export && flow->stats.packets > 0) {
        clickhouse_export_flow(flow);
        RTE_LOG(DEBUG, FLOW, "Exported flow before removal\n");
    }

    ret = rte_hash_del_key(g_flow_mgr->hash_table, key);
    if (ret >= 0) {
        /* 清理流条目 */
        memset(&g_flow_mgr->flow_entries[flow_idx], 0, sizeof(struct flow_info));
        g_flow_mgr->current_flows--;
        g_flow_mgr->flows_expired++;

        RTE_LOG(DEBUG, FLOW, "Expired flow removed: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u proto=%u\n",
                (key->src_ip >> 24) & 0xFF, (key->src_ip >> 16) & 0xFF,
                (key->src_ip >> 8) & 0xFF, key->src_ip & 0xFF, key->src_port,
                (key->dst_ip >> 24) & 0xFF, (key->dst_ip >> 16) & 0xFF,
                (key->dst_ip >> 8) & 0xFF, key->dst_ip & 0xFF, key->dst_port,
                key->protocol);

        return 0;
    }

    return ret;
}

/* 清理过期流 */
int flow_table_cleanup_expired(void)
{
    uint64_t current_time = rte_get_timer_cycles();
    uint32_t i;
    int cleaned = 0;

    if (g_flow_mgr == NULL) {
        return -1;
    }

    /* 避免过于频繁的清理操作 */
    if ((current_time - g_flow_mgr->last_cleanup_tsc) < (rte_get_timer_hz() * 1)) {  /* 1秒清理一次 */
        return 0;
    }

    /* 遍历所有流条目 */
    for (i = 0; i < g_flow_mgr->max_flows; i++) {
        struct flow_info *flow = &g_flow_mgr->flow_entries[i];

        /* 跳过空条目 */
        if (flow->stats.first_seen == 0) {
            continue;
        }

        /* 检查是否过期 */
        bool should_remove = false;

        if ((current_time - flow->stats.last_seen) > g_flow_mgr->flow_timeout_tsc) {
            /* 普通超时 */
            should_remove = true;
        } else if ((flow->flags & FLOW_STATE_CLOSING) &&
                   ((current_time - flow->stats.last_seen) > (rte_get_timer_hz() * 3))) {
            /* TCP连接关闭后3秒超时 */
            should_remove = true;
        }

        if (should_remove) {
            if (remove_expired_flow(&flow->key, i) == 0) {
                cleaned++;
            }
        }
    }

    g_flow_mgr->last_cleanup_tsc = current_time;

    if (cleaned > 0) {
        RTE_LOG(INFO, FLOW, "Cleaned up %d expired flows, current flows: %u\n",
                cleaned, g_flow_mgr->current_flows);
    }

    return cleaned;
}

/* 打印流表统计信息 */
void flow_table_stats_print(void)
{
    if (g_flow_mgr == NULL) {
        printf("Flow table not initialized\n");
        return;
    }

    printf("\n=== Flow Table Statistics ===\n");
    printf("Max flows:       %u\n", g_flow_mgr->max_flows);
    printf("Current flows:   %u\n", g_flow_mgr->current_flows);
    printf("Flows created:   %" PRIu64 "\n", g_flow_mgr->flows_created);
    printf("Flows expired:   %" PRIu64 "\n", g_flow_mgr->flows_expired);
    printf("Lookup hits:     %" PRIu64 "\n", g_flow_mgr->flows_lookup_hit);
    printf("Lookup misses:   %" PRIu64 "\n", g_flow_mgr->flows_lookup_miss);
    printf("Hit ratio:       %.2f%%\n",
           (g_flow_mgr->flows_lookup_hit + g_flow_mgr->flows_lookup_miss) > 0 ?
           (double)g_flow_mgr->flows_lookup_hit * 100 /
           (g_flow_mgr->flows_lookup_hit + g_flow_mgr->flows_lookup_miss) : 0.0);
    printf("Usage ratio:     %.2f%%\n",
           (double)g_flow_mgr->current_flows * 100 / g_flow_mgr->max_flows);
    printf("=============================\n\n");
}

/* 清理流表 */
void flow_table_cleanup(void)
{
    if (g_flow_mgr == NULL) {
        return;
    }

    RTE_LOG(INFO, FLOW, "Cleaning up flow table...\n");

    /* 打印最终统计信息 */
    flow_table_stats_print();

    /* 清理哈希表 */
    if (g_flow_mgr->hash_table) {
        rte_hash_free(g_flow_mgr->hash_table);
        g_flow_mgr->hash_table = NULL;
    }

    /* 清理流条目数组 */
    if (g_flow_mgr->flow_entries) {
        rte_free(g_flow_mgr->flow_entries);
        g_flow_mgr->flow_entries = NULL;
    }

    /* 清理管理器 */
    rte_free(g_flow_mgr);
    g_flow_mgr = NULL;

    /* 清理全局配置指针 */
    if (g_app_config) {
        g_app_config->flow_hash = NULL;
        g_app_config->flow_table = NULL;
    }

    RTE_LOG(INFO, FLOW, "Flow table cleanup completed\n");
}
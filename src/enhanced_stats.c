/*
 * 多维度统计输出模块
 * 提供协议、应用、流量等多个维度的统计分析和输出
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_hash.h>

#include "dpdk_multi_port.h"

#define RTE_LOGTYPE_STATS RTE_LOGTYPE_USER4

/* 协议统计结构 */
struct protocol_stats {
    char protocol_name[MAX_PROTOCOL_NAME];
    uint64_t flows;
    uint64_t packets;
    uint64_t bytes;
    uint64_t up_packets;
    uint64_t up_bytes;
    uint64_t down_packets;
    uint64_t down_bytes;
} __rte_cache_aligned;

/* 应用统计结构 */
struct app_stats {
    char app_name[MAX_APP_NAME];
    uint64_t flows;
    uint64_t packets;
    uint64_t bytes;
    uint64_t up_packets;
    uint64_t up_bytes;
    uint64_t down_packets;
    uint64_t down_bytes;
} __rte_cache_aligned;

/* 端口统计结构 */
struct port_stats {
    uint16_t port;
    uint8_t protocol_type;  /* TCP/UDP */
    uint64_t flows;
    uint64_t packets;
    uint64_t bytes;
} __rte_cache_aligned;

/* 全局统计结构 */
struct global_stats {
    /* 总体统计 */
    uint64_t total_flows;
    uint64_t active_flows;
    uint64_t expired_flows;
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t up_packets;
    uint64_t up_bytes;
    uint64_t down_packets;
    uint64_t down_bytes;
    
    /* 协议分布统计 */
    struct protocol_stats protocol_stats[256];  /* 按协议名索引 */
    uint32_t num_protocols;
    
    /* 应用分布统计 */
    struct app_stats app_stats[1000];  /* 按应用名索引 */
    uint32_t num_apps;
    
    /* 端口分布统计 */
    struct port_stats port_stats[65536];  /* 按端口号索引 */
    uint32_t num_ports;
    
    /* Top统计 */
    struct {
        char name[64];
        uint64_t value;
    } top_protocols[10];
    
    struct {
        char name[64];
        uint64_t value;
    } top_apps[10];
    
    struct {
        uint16_t port;
        uint64_t value;
    } top_ports[10];
    
    /* 时间统计 */
    uint64_t stats_start_time;
    uint64_t stats_end_time;
} __rte_cache_aligned;

static struct global_stats *g_global_stats = NULL;

/* 格式化字节数 */
static void format_bytes(uint64_t bytes, char *str, size_t len)
{
    const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double value = bytes;
    
    while (value >= 1024 && unit < 4) {
        value /= 1024;
        unit++;
    }
    
    if (unit == 0) {
        snprintf(str, len, "%lu %s", (unsigned long)value, units[unit]);
    } else {
        snprintf(str, len, "%.2f %s", value, units[unit]);
    }
}

/* 格式化包速率 */
static void format_pps(uint64_t pps, char *str, size_t len)
{
    const char *units[] = {"pps", "Kpps", "Mpps", "Gpps"};
    int unit = 0;
    double value = pps;
    
    while (value >= 1000 && unit < 3) {
        value /= 1000;
        unit++;
    }
    
    if (unit == 0) {
        snprintf(str, len, "%lu %s", (unsigned long)value, units[unit]);
    } else {
        snprintf(str, len, "%.2f %s", value, units[unit]);
    }
}

/* 格式化比特率 */
static void format_bps(uint64_t bps, char *str, size_t len)
{
    const char *units[] = {"bps", "Kbps", "Mbps", "Gbps", "Tbps"};
    int unit = 0;
    double value = bps;
    
    while (value >= 1000 && unit < 4) {
        value /= 1000;
        unit++;
    }
    
    if (unit == 0) {
        snprintf(str, len, "%lu %s", (unsigned long)value, units[unit]);
    } else {
        snprintf(str, len, "%.2f %s", value, units[unit]);
    }
}

/* 初始化统计模块 */
int enhanced_stats_init(void)
{
    RTE_LOG(INFO, STATS, "Initializing enhanced statistics module...\n");
    
    g_global_stats = rte_zmalloc("global_stats", sizeof(struct global_stats), RTE_CACHE_LINE_SIZE);
    if (g_global_stats == NULL) {
        RTE_LOG(ERR, STATS, "Cannot allocate memory for global statistics\n");
        return -1;
    }
    
    g_global_stats->stats_start_time = rte_get_timer_cycles();
    
    RTE_LOG(INFO, STATS, "Enhanced statistics module initialized\n");
    return 0;
}

/* 更新协议统计 */
static void update_protocol_stats(struct flow_info *flow)
{
    struct protocol_stats *pstats = NULL;
    uint32_t i;
    
    /* 查找现有协议统计 */
    for (i = 0; i < g_global_stats->num_protocols; i++) {
        if (strcmp(g_global_stats->protocol_stats[i].protocol_name, 
                   flow->protocol.protocol_name) == 0) {
            pstats = &g_global_stats->protocol_stats[i];
            break;
        }
    }
    
    /* 如果没找到，创建新的协议统计 */
    if (pstats == NULL && g_global_stats->num_protocols < 256) {
        pstats = &g_global_stats->protocol_stats[g_global_stats->num_protocols];
        strncpy(pstats->protocol_name, flow->protocol.protocol_name, MAX_PROTOCOL_NAME - 1);
        pstats->protocol_name[MAX_PROTOCOL_NAME - 1] = '\0';
        g_global_stats->num_protocols++;
    }
    
    /* 更新统计 */
    if (pstats) {
        pstats->flows++;
        pstats->packets += flow->stats.packets;
        pstats->bytes += flow->stats.bytes;
        pstats->up_packets += flow->stats.up_packets;
        pstats->up_bytes += flow->stats.up_bytes;
        pstats->down_packets += flow->stats.down_packets;
        pstats->down_bytes += flow->stats.down_bytes;
    }
}

/* 更新应用统计 */
static void update_app_stats(struct flow_info *flow)
{
    struct app_stats *astats = NULL;
    uint32_t i;
    
    /* 跳过未识别的应用 */
    if (strlen(flow->application.app_name) == 0) {
        return;
    }
    
    /* 查找现有应用统计 */
    for (i = 0; i < g_global_stats->num_apps; i++) {
        if (strcmp(g_global_stats->app_stats[i].app_name, 
                   flow->application.app_name) == 0) {
            astats = &g_global_stats->app_stats[i];
            break;
        }
    }
    
    /* 如果没找到，创建新的应用统计 */
    if (astats == NULL && g_global_stats->num_apps < 1000) {
        astats = &g_global_stats->app_stats[g_global_stats->num_apps];
        strncpy(astats->app_name, flow->application.app_name, MAX_APP_NAME - 1);
        astats->app_name[MAX_APP_NAME - 1] = '\0';
        g_global_stats->num_apps++;
    }
    
    /* 更新统计 */
    if (astats) {
        astats->flows++;
        astats->packets += flow->stats.packets;
        astats->bytes += flow->stats.bytes;
        astats->up_packets += flow->stats.up_packets;
        astats->up_bytes += flow->stats.up_bytes;
        astats->down_packets += flow->stats.down_packets;
        astats->down_bytes += flow->stats.down_bytes;
    }
}

/* 更新端口统计 */
static void update_port_stats(struct flow_info *flow)
{
    /* 更新源端口统计 */
    if (flow->key.src_port > 0) {
        struct port_stats *pstats = &g_global_stats->port_stats[flow->key.src_port];
        if (pstats->flows == 0) {
            pstats->port = flow->key.src_port;
            pstats->protocol_type = flow->key.protocol;
            g_global_stats->num_ports++;
        }
        pstats->flows++;
        pstats->packets += flow->stats.packets;
        pstats->bytes += flow->stats.bytes;
    }
    
    /* 更新目的端口统计 */
    if (flow->key.dst_port > 0 && flow->key.dst_port != flow->key.src_port) {
        struct port_stats *pstats = &g_global_stats->port_stats[flow->key.dst_port];
        if (pstats->flows == 0) {
            pstats->port = flow->key.dst_port;
            pstats->protocol_type = flow->key.protocol;
            g_global_stats->num_ports++;
        }
        pstats->flows++;
        pstats->packets += flow->stats.packets;
        pstats->bytes += flow->stats.bytes;
    }
}

/* 收集全局统计信息 */
int collect_global_stats(void)
{
    struct flow_info *flow_table;
    uint32_t max_flows;
    uint32_t i;
    
    if (g_global_stats == NULL || g_app_config == NULL || g_app_config->flow_table == NULL) {
        return -1;
    }
    
    /* 重置统计 */
    memset(&g_global_stats->protocol_stats, 0, sizeof(g_global_stats->protocol_stats));
    memset(&g_global_stats->app_stats, 0, sizeof(g_global_stats->app_stats));
    memset(&g_global_stats->port_stats, 0, sizeof(g_global_stats->port_stats));
    g_global_stats->num_protocols = 0;
    g_global_stats->num_apps = 0;
    g_global_stats->num_ports = 0;
    
    /* 重置全局计数器 */
    g_global_stats->total_flows = 0;
    g_global_stats->active_flows = 0;
    g_global_stats->total_packets = 0;
    g_global_stats->total_bytes = 0;
    g_global_stats->up_packets = 0;
    g_global_stats->up_bytes = 0;
    g_global_stats->down_packets = 0;
    g_global_stats->down_bytes = 0;
    
    flow_table = g_app_config->flow_table;
    max_flows = FLOW_HASH_ENTRIES;
    
    /* 遍历所有流条目 */
    for (i = 0; i < max_flows; i++) {
        struct flow_info *flow = &flow_table[i];
        
        /* 跳过空条目 */
        if (flow->stats.first_seen == 0) {
            continue;
        }
        
        g_global_stats->total_flows++;
        g_global_stats->total_packets += flow->stats.packets;
        g_global_stats->total_bytes += flow->stats.bytes;
        g_global_stats->up_packets += flow->stats.up_packets;
        g_global_stats->up_bytes += flow->stats.up_bytes;
        g_global_stats->down_packets += flow->stats.down_packets;
        g_global_stats->down_bytes += flow->stats.down_bytes;
        
        /* 检查流是否活跃 */
        uint64_t current_time = rte_get_timer_cycles();
        if ((current_time - flow->stats.last_seen) < (rte_get_timer_hz() * 60)) {  /* 1分钟内活跃 */
            g_global_stats->active_flows++;
        }
        
        /* 更新各维度统计 */
        update_protocol_stats(flow);
        update_app_stats(flow);
        update_port_stats(flow);
    }
    
    g_global_stats->expired_flows = g_global_stats->total_flows - g_global_stats->active_flows;
    g_global_stats->stats_end_time = rte_get_timer_cycles();
    
    return 0;
}

/* 计算Top排序 */
static void calculate_top_stats(void)
{
    uint32_t i, j;
    
    /* 初始化Top数组 */
    memset(g_global_stats->top_protocols, 0, sizeof(g_global_stats->top_protocols));
    memset(g_global_stats->top_apps, 0, sizeof(g_global_stats->top_apps));
    memset(g_global_stats->top_ports, 0, sizeof(g_global_stats->top_ports));
    
    /* 计算Top协议（按字节数排序）*/
    for (i = 0; i < g_global_stats->num_protocols; i++) {
        struct protocol_stats *pstats = &g_global_stats->protocol_stats[i];
        
        for (j = 0; j < 10; j++) {
            if (pstats->bytes > g_global_stats->top_protocols[j].value) {
                /* 向后移动 */
                if (j < 9) {
                    memmove(&g_global_stats->top_protocols[j + 1], 
                           &g_global_stats->top_protocols[j], 
                           sizeof(g_global_stats->top_protocols[0]) * (9 - j));
                }
                /* 插入新值 */
                strncpy(g_global_stats->top_protocols[j].name, pstats->protocol_name, 63);
                g_global_stats->top_protocols[j].name[63] = '\0';
                g_global_stats->top_protocols[j].value = pstats->bytes;
                break;
            }
        }
    }
    
    /* 计算Top应用（按字节数排序）*/
    for (i = 0; i < g_global_stats->num_apps; i++) {
        struct app_stats *astats = &g_global_stats->app_stats[i];
        
        for (j = 0; j < 10; j++) {
            if (astats->bytes > g_global_stats->top_apps[j].value) {
                /* 向后移动 */
                if (j < 9) {
                    memmove(&g_global_stats->top_apps[j + 1], 
                           &g_global_stats->top_apps[j], 
                           sizeof(g_global_stats->top_apps[0]) * (9 - j));
                }
                /* 插入新值 */
                strncpy(g_global_stats->top_apps[j].name, astats->app_name, 63);
                g_global_stats->top_apps[j].name[63] = '\0';
                g_global_stats->top_apps[j].value = astats->bytes;
                break;
            }
        }
    }
    
    /* 计算Top端口（按流数量排序）*/
    for (i = 1; i < 65536; i++) {
        struct port_stats *pstats = &g_global_stats->port_stats[i];
        
        if (pstats->flows == 0) continue;
        
        for (j = 0; j < 10; j++) {
            if (pstats->flows > g_global_stats->top_ports[j].value) {
                /* 向后移动 */
                if (j < 9) {
                    memmove(&g_global_stats->top_ports[j + 1], 
                           &g_global_stats->top_ports[j], 
                           sizeof(g_global_stats->top_ports[0]) * (9 - j));
                }
                /* 插入新值 */
                g_global_stats->top_ports[j].port = pstats->port;
                g_global_stats->top_ports[j].value = pstats->flows;
                break;
            }
        }
    }
}

/* 打印增强统计信息 */
void print_enhanced_stats(void)
{
    char bytes_str[64], pps_str[64], bps_str[64];
    uint64_t duration_sec;
    double avg_pps, avg_bps;
    int i;
    
    if (g_global_stats == NULL) {
        printf("Enhanced statistics not initialized\n");
        return;
    }
    
    /* 收集最新统计 */
    collect_global_stats();
    calculate_top_stats();
    
    duration_sec = (g_global_stats->stats_end_time - g_global_stats->stats_start_time) / rte_get_timer_hz();
    if (duration_sec == 0) duration_sec = 1;
    
    avg_pps = (double)g_global_stats->total_packets / duration_sec;
    avg_bps = (double)g_global_stats->total_bytes * 8 / duration_sec;
    
    printf("\n=== Enhanced Traffic Statistics ===\n");
    
    /* 总体统计 */
    printf("=== Overall Statistics ===\n");
    printf("Duration:        %lu seconds\n", duration_sec);
    printf("Total flows:     %lu\n", g_global_stats->total_flows);
    printf("Active flows:    %lu\n", g_global_stats->active_flows);
    printf("Expired flows:   %lu\n", g_global_stats->expired_flows);
    
    format_bytes(g_global_stats->total_bytes, bytes_str, sizeof(bytes_str));
    format_pps((uint64_t)avg_pps, pps_str, sizeof(pps_str));
    format_bps((uint64_t)avg_bps, bps_str, sizeof(bps_str));
    
    printf("Total packets:   %lu\n", g_global_stats->total_packets);
    printf("Total bytes:     %s\n", bytes_str);
    printf("Average PPS:     %s\n", pps_str);
    printf("Average BPS:     %s\n", bps_str);
    
    /* 方向统计 */
    printf("\n=== Directional Statistics ===\n");
    if (g_global_stats->total_packets > 0) {
        double up_ratio = (double)g_global_stats->up_packets * 100 / g_global_stats->total_packets;
        double down_ratio = (double)g_global_stats->down_packets * 100 / g_global_stats->total_packets;
        
        format_bytes(g_global_stats->up_bytes, bytes_str, sizeof(bytes_str));
        printf("Upstream:        %lu packets (%.1f%%), %s\n", 
               g_global_stats->up_packets, up_ratio, bytes_str);
        
        format_bytes(g_global_stats->down_bytes, bytes_str, sizeof(bytes_str));
        printf("Downstream:      %lu packets (%.1f%%), %s\n", 
               g_global_stats->down_packets, down_ratio, bytes_str);
    }
    
    /* Top协议 */
    printf("\n=== Top Protocols (by bytes) ===\n");
    printf("%-20s %-12s %-12s %-8s\n", "Protocol", "Flows", "Bytes", "Share");
    printf("%-20s %-12s %-12s %-8s\n", "--------", "-----", "-----", "-----");
    for (i = 0; i < 10 && g_global_stats->top_protocols[i].value > 0; i++) {
        format_bytes(g_global_stats->top_protocols[i].value, bytes_str, sizeof(bytes_str));
        double share = g_global_stats->total_bytes > 0 ? 
                      (double)g_global_stats->top_protocols[i].value * 100 / g_global_stats->total_bytes : 0;
        printf("%-20s %-12s %-12s %.1f%%\n", 
               g_global_stats->top_protocols[i].name, "-", bytes_str, share);
    }
    
    /* Top应用 */
    printf("\n=== Top Applications (by bytes) ===\n");
    printf("%-20s %-12s %-12s %-8s\n", "Application", "Flows", "Bytes", "Share");
    printf("%-20s %-12s %-12s %-8s\n", "-----------", "-----", "-----", "-----");
    for (i = 0; i < 10 && g_global_stats->top_apps[i].value > 0; i++) {
        format_bytes(g_global_stats->top_apps[i].value, bytes_str, sizeof(bytes_str));
        double share = g_global_stats->total_bytes > 0 ? 
                      (double)g_global_stats->top_apps[i].value * 100 / g_global_stats->total_bytes : 0;
        printf("%-20s %-12s %-12s %.1f%%\n", 
               g_global_stats->top_apps[i].name, "-", bytes_str, share);
    }
    
    /* Top端口 */
    printf("\n=== Top Ports (by flows) ===\n");
    printf("%-8s %-12s %-8s\n", "Port", "Flows", "Share");
    printf("%-8s %-12s %-8s\n", "----", "-----", "-----");
    for (i = 0; i < 10 && g_global_stats->top_ports[i].value > 0; i++) {
        double share = g_global_stats->total_flows > 0 ? 
                      (double)g_global_stats->top_ports[i].value * 100 / g_global_stats->total_flows : 0;
        printf("%-8u %-12lu %.1f%%\n", 
               g_global_stats->top_ports[i].port, 
               g_global_stats->top_ports[i].value, share);
    }
    
    printf("===================================\n\n");
}

/* 获取协议识别统计 - 调用protocol_engine中的实现 */
/* 函数在protocol_engine.c中实现 */

/* 获取应用识别统计 - 调用app_engine中的实现 */
/* 函数在app_engine.c中实现 */

/* 获取ClickHouse统计 - 调用clickhouse_client中的实现 */
/* 函数在clickhouse_client.c中实现 */

/* 清理统计模块 */
void enhanced_stats_cleanup(void)
{
    if (g_global_stats == NULL) {
        return;
    }
    
    RTE_LOG(INFO, STATS, "Cleaning up enhanced statistics module...\n");
    
    /* 打印最终统计信息 */
    print_enhanced_stats();
    
    rte_free(g_global_stats);
    g_global_stats = NULL;
    
    RTE_LOG(INFO, STATS, "Enhanced statistics cleanup completed\n");
}
/*
 * ClickHouse数据输出模块
 * 支持批量导出流统计数据到ClickHouse数据库
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_lcore.h>

#include "dpdk_multi_port.h"

#define RTE_LOGTYPE_CLICKHOUSE RTE_LOGTYPE_USER10

/* ClickHouse客户端结构 */
struct clickhouse_client {
    char host[64];                          /* ClickHouse主机 */
    uint16_t port;                          /* ClickHouse端口 */
    char database[64];                      /* 数据库名 */
    char table[64];                         /* 表名 */
    char username[64];                      /* 用户名 */
    char password[64];                      /* 密码 */
    
    /* 批量导出缓冲区 */
    struct flow_info *export_buffer[CH_BATCH_SIZE];  /* 导出缓冲区 */
    uint32_t buffer_count;                  /* 缓冲区数据数量 */
    
    /* 统计信息 */
    uint64_t total_exports;                 /* 总导出次数 */
    uint64_t total_records;                 /* 总记录数 */
    uint64_t failed_exports;                /* 导出失败次数 */
    uint64_t last_export_time;              /* 上次导出时间 */
    
    /* 连接状态 */
    int connected;                          /* 连接状态 */
    FILE *output_file;                      /* 输出文件（如果连接失败） */
} __rte_cache_aligned;

static struct clickhouse_client *g_ch_client = NULL;

/* 将IP地址转换为字符串 */
static void ip_to_string(uint32_t ip, char *str, size_t len)
{
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    strncpy(str, inet_ntoa(addr), len - 1);
    str[len - 1] = '\0';
}

/* 获取当前时间戳（毫秒） */
static uint64_t get_current_timestamp_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/* 转换DPDK时间戳为Unix时间戳 */
static uint64_t dpdk_tsc_to_timestamp(uint64_t tsc)
{
    static uint64_t hz = 0;
    static uint64_t start_tsc = 0;
    static uint64_t start_time = 0;
    
    if (hz == 0) {
        hz = rte_get_timer_hz();
        start_tsc = rte_get_timer_cycles();
        start_time = get_current_timestamp_ms();
    }
    
    uint64_t elapsed_tsc = tsc - start_tsc;
    uint64_t elapsed_ms = (elapsed_tsc * 1000) / hz;
    return start_time + elapsed_ms;
}

/* 生成SQL插入语句 */
static int generate_insert_sql(struct flow_info **flows, int count, char *sql, size_t sql_size)
{
    char src_ip_str[16], dst_ip_str[16];
    int offset = 0;
    int i;
    
    /* SQL插入语句头部 */
    offset += snprintf(sql + offset, sql_size - offset,
        "INSERT INTO %s.%s ("
        "timestamp, src_ip, dst_ip, src_port, dst_port, protocol, "
        "total_packets, total_bytes, up_packets, up_bytes, down_packets, down_bytes, "
        "duration, avg_pps, avg_bps, min_packet_size, max_packet_size, avg_packet_size, "
        "protocol_name, protocol_confidence, app_name, app_confidence, matched_domain, "
        "first_seen, last_seen, tcp_flags, retransmissions, out_of_order, lost_packets"
        ") VALUES ",
        g_ch_client->database, g_ch_client->table);
    
    /* 生成每条记录的VALUES */
    for (i = 0; i < count; i++) {
        struct flow_info *flow = flows[i];
        
        /* IP地址转字符串 */
        ip_to_string(flow->key.src_ip, src_ip_str, sizeof(src_ip_str));
        ip_to_string(flow->key.dst_ip, dst_ip_str, sizeof(dst_ip_str));
        
        /* 计算流持续时间和平均速率 */
        uint64_t first_seen_ts = dpdk_tsc_to_timestamp(flow->stats.first_seen);
        uint64_t last_seen_ts = dpdk_tsc_to_timestamp(flow->stats.last_seen);
        uint64_t duration = (flow->stats.last_seen - flow->stats.first_seen) / rte_get_timer_hz();
        
        double avg_pps = duration > 0 ? (double)flow->stats.packets / duration : 0;
        double avg_bps = duration > 0 ? (double)flow->stats.bytes * 8 / duration : 0;
        
        if (i > 0) {
            offset += snprintf(sql + offset, sql_size - offset, ",");
        }
        
        offset += snprintf(sql + offset, sql_size - offset,
            "(%lu,'%s','%s',%u,%u,%u,"
            "%lu,%lu,%lu,%lu,%lu,%lu,"
            "%lu,%.2f,%.2f,%u,%u,%u,"
            "'%s',%u,'%s',%u,'%s',"
            "%lu,%lu,%u,%u,%u,%u)",
            get_current_timestamp_ms(),  /* timestamp */
            src_ip_str, dst_ip_str,      /* src_ip, dst_ip */
            flow->key.src_port, flow->key.dst_port, flow->key.protocol,  /* ports, protocol */
            flow->stats.packets, flow->stats.bytes,                       /* total stats */
            flow->stats.up_packets, flow->stats.up_bytes,                 /* upstream stats */
            flow->stats.down_packets, flow->stats.down_bytes,             /* downstream stats */
            duration, avg_pps, avg_bps,                                   /* duration, rates */
            flow->stats.min_packet_size, flow->stats.max_packet_size, flow->stats.avg_packet_size,  /* packet sizes */
            flow->protocol.protocol_name, flow->protocol.confidence,      /* protocol info */
            flow->application.app_name, flow->application.confidence,     /* app info */
            flow->application.matched_domain,                             /* matched domain */
            first_seen_ts, last_seen_ts,                                  /* timestamps */
            flow->stats.tcp_flags, flow->stats.retransmissions,          /* TCP info */
            flow->stats.out_of_order, flow->stats.lost_packets           /* QoS info */
        );
        
        if (offset >= sql_size - 1000) {  /* 防止缓冲区溢出 */
            RTE_LOG(WARNING, CLICKHOUSE, "SQL buffer full, truncating batch\n");
            break;
        }
    }
    
    return i;  /* 返回实际处理的记录数 */
}

/* 执行ClickHouse命令 */
static int execute_clickhouse_command(const char *sql)
{
    char command[8192];
    int ret;
    
    /* 构建curl命令 */
    snprintf(command, sizeof(command),
        "curl -s -X POST 'http://%s:%u/' "
        "--data-binary @- "
        "-H 'Content-Type: text/plain' "
        "<<< \"%s\"",
        g_ch_client->host, g_ch_client->port, sql);
    
    /* 执行命令 */
    ret = system(command);
    if (ret != 0) {
        RTE_LOG(ERR, CLICKHOUSE, "ClickHouse command failed: %d\n", ret);
        return -1;
    }
    
    return 0;
}

/* 写入备用文件 */
static int write_to_backup_file(struct flow_info **flows, int count)
{
    if (g_ch_client->output_file == NULL) {
        char filename[256];
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        
        snprintf(filename, sizeof(filename), "flow_stats_%04d%02d%02d_%02d%02d%02d.csv",
                tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
                tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec);
        
        g_ch_client->output_file = fopen(filename, "w");
        if (g_ch_client->output_file == NULL) {
            RTE_LOG(ERR, CLICKHOUSE, "Cannot create backup file: %s\n", filename);
            return -1;
        }
        
        /* 写入CSV头部 */
        fprintf(g_ch_client->output_file,
            "timestamp,src_ip,dst_ip,src_port,dst_port,protocol,"
            "total_packets,total_bytes,up_packets,up_bytes,down_packets,down_bytes,"
            "duration,avg_pps,avg_bps,min_packet_size,max_packet_size,avg_packet_size,"
            "protocol_name,protocol_confidence,app_name,app_confidence,matched_domain,"
            "first_seen,last_seen,tcp_flags,retransmissions,out_of_order,lost_packets\n");
        
        RTE_LOG(INFO, CLICKHOUSE, "Created backup file: %s\n", filename);
    }
    
    /* 写入数据记录 */
    for (int i = 0; i < count; i++) {
        struct flow_info *flow = flows[i];
        char src_ip_str[16], dst_ip_str[16];
        
        ip_to_string(flow->key.src_ip, src_ip_str, sizeof(src_ip_str));
        ip_to_string(flow->key.dst_ip, dst_ip_str, sizeof(dst_ip_str));
        
        uint64_t duration = (flow->stats.last_seen - flow->stats.first_seen) / rte_get_timer_hz();
        double avg_pps = duration > 0 ? (double)flow->stats.packets / duration : 0;
        double avg_bps = duration > 0 ? (double)flow->stats.bytes * 8 / duration : 0;
        
        fprintf(g_ch_client->output_file,
            "%lu,%s,%s,%u,%u,%u,"
            "%lu,%lu,%lu,%lu,%lu,%lu,"
            "%lu,%.2f,%.2f,%u,%u,%u,"
            "%s,%u,%s,%u,%s,"
            "%lu,%lu,%u,%u,%u,%u\n",
            get_current_timestamp_ms(),
            src_ip_str, dst_ip_str, flow->key.src_port, flow->key.dst_port, flow->key.protocol,
            flow->stats.packets, flow->stats.bytes,
            flow->stats.up_packets, flow->stats.up_bytes,
            flow->stats.down_packets, flow->stats.down_bytes,
            duration, avg_pps, avg_bps,
            flow->stats.min_packet_size, flow->stats.max_packet_size, flow->stats.avg_packet_size,
            flow->protocol.protocol_name, flow->protocol.confidence,
            flow->application.app_name, flow->application.confidence,
            flow->application.matched_domain,
            dpdk_tsc_to_timestamp(flow->stats.first_seen),
            dpdk_tsc_to_timestamp(flow->stats.last_seen),
            flow->stats.tcp_flags, flow->stats.retransmissions,
            flow->stats.out_of_order, flow->stats.lost_packets);
    }
    
    fflush(g_ch_client->output_file);
    return 0;
}

/* 初始化ClickHouse客户端 */
int clickhouse_init(void)
{
    char create_table_sql[4096];
    
    RTE_LOG(INFO, CLICKHOUSE, "Initializing ClickHouse client...\n");
    
    /* 分配客户端内存 */
    g_ch_client = rte_zmalloc("clickhouse_client", sizeof(struct clickhouse_client), RTE_CACHE_LINE_SIZE);
    if (g_ch_client == NULL) {
        RTE_LOG(ERR, CLICKHOUSE, "Cannot allocate memory for ClickHouse client\n");
        return -1;
    }
    
    /* 设置连接参数 */
    strncpy(g_ch_client->host, CLICKHOUSE_HOST, sizeof(g_ch_client->host) - 1);
    g_ch_client->port = CLICKHOUSE_PORT;
    strncpy(g_ch_client->database, CLICKHOUSE_DB, sizeof(g_ch_client->database) - 1);
    strncpy(g_ch_client->table, CLICKHOUSE_TABLE, sizeof(g_ch_client->table) - 1);
    
    /* 设置全局配置指针 */
    g_app_config->clickhouse_client = g_ch_client;
    strncpy(g_app_config->ch_host, g_ch_client->host, sizeof(g_app_config->ch_host) - 1);
    g_app_config->ch_port = g_ch_client->port;
    strncpy(g_app_config->ch_database, g_ch_client->database, sizeof(g_app_config->ch_database) - 1);
    strncpy(g_app_config->ch_table, g_ch_client->table, sizeof(g_app_config->ch_table) - 1);
    
    /* 创建数据库（如果不存在）*/
    snprintf(create_table_sql, sizeof(create_table_sql),
        "CREATE DATABASE IF NOT EXISTS %s", g_ch_client->database);
    
    if (execute_clickhouse_command(create_table_sql) == 0) {
        RTE_LOG(INFO, CLICKHOUSE, "Database %s created or exists\n", g_ch_client->database);
        g_ch_client->connected = 1;
    } else {
        RTE_LOG(WARNING, CLICKHOUSE, "Failed to create database, will use backup file\n");
        g_ch_client->connected = 0;
    }
    
    /* 创建表（如果不存在）*/
    if (g_ch_client->connected) {
        snprintf(create_table_sql, sizeof(create_table_sql),
            "CREATE TABLE IF NOT EXISTS %s.%s ("
            "timestamp UInt64, "
            "src_ip String, "
            "dst_ip String, "
            "src_port UInt16, "
            "dst_port UInt16, "
            "protocol UInt8, "
            "total_packets UInt64, "
            "total_bytes UInt64, "
            "up_packets UInt64, "
            "up_bytes UInt64, "
            "down_packets UInt64, "
            "down_bytes UInt64, "
            "duration UInt64, "
            "avg_pps Float64, "
            "avg_bps Float64, "
            "min_packet_size UInt32, "
            "max_packet_size UInt32, "
            "avg_packet_size UInt32, "
            "protocol_name String, "
            "protocol_confidence UInt8, "
            "app_name String, "
            "app_confidence UInt8, "
            "matched_domain String, "
            "first_seen UInt64, "
            "last_seen UInt64, "
            "tcp_flags UInt32, "
            "retransmissions UInt32, "
            "out_of_order UInt32, "
            "lost_packets UInt32"
            ") ENGINE = MergeTree() "
            "ORDER BY (timestamp, src_ip, dst_ip) "
            "SETTINGS index_granularity = 8192",
            g_ch_client->database, g_ch_client->table);
        
        if (execute_clickhouse_command(create_table_sql) == 0) {
            RTE_LOG(INFO, CLICKHOUSE, "Table %s.%s created or exists\n", 
                    g_ch_client->database, g_ch_client->table);
        } else {
            RTE_LOG(WARNING, CLICKHOUSE, "Failed to create table, will use backup file\n");
            g_ch_client->connected = 0;
        }
    }
    
    RTE_LOG(INFO, CLICKHOUSE, "ClickHouse client initialized (connected: %s)\n", 
            g_ch_client->connected ? "yes" : "no");
    
    return 0;
}

/* 导出单个流 */
int clickhouse_export_flow(struct flow_info *flow)
{
    if (g_ch_client == NULL || flow == NULL) {
        return -1;
    }
    
    /* 添加到批量缓冲区 */
    if (g_ch_client->buffer_count < CH_BATCH_SIZE) {
        g_ch_client->export_buffer[g_ch_client->buffer_count] = flow;
        g_ch_client->buffer_count++;
        
        /* 如果缓冲区满了，执行批量导出 */
        if (g_ch_client->buffer_count >= CH_BATCH_SIZE) {
            return clickhouse_export_batch(g_ch_client->export_buffer, g_ch_client->buffer_count);
        }
        
        return 0;
    }
    
    return -1;
}

/* 批量导出流数据 */
int clickhouse_export_batch(struct flow_info **flows, int count)
{
    char *sql;
    int ret = 0;
    int processed;
    
    if (g_ch_client == NULL || flows == NULL || count <= 0) {
        return -1;
    }
    
    /* 分配SQL缓冲区 */
    sql = malloc(1024 * 1024);  /* 1MB缓冲区 */
    if (sql == NULL) {
        RTE_LOG(ERR, CLICKHOUSE, "Cannot allocate SQL buffer\n");
        return -1;
    }
    
    /* 生成SQL插入语句 */
    processed = generate_insert_sql(flows, count, sql, 1024 * 1024);
    if (processed <= 0) {
        free(sql);
        return -1;
    }
    
    /* 尝试导出到ClickHouse */
    if (g_ch_client->connected) {
        if (execute_clickhouse_command(sql) == 0) {
            g_ch_client->total_exports++;
            g_ch_client->total_records += processed;
            ret = processed;
            
            RTE_LOG(DEBUG, CLICKHOUSE, "Exported %d records to ClickHouse\n", processed);
        } else {
            g_ch_client->failed_exports++;
            g_ch_client->connected = 0;  /* 标记连接失败 */
            RTE_LOG(WARNING, CLICKHOUSE, "ClickHouse export failed, switching to backup file\n");
            
            /* 降级到备用文件 */
            if (write_to_backup_file(flows, processed) == 0) {
                ret = processed;
            }
        }
    } else {
        /* 使用备用文件 */
        if (write_to_backup_file(flows, processed) == 0) {
            g_ch_client->total_exports++;
            g_ch_client->total_records += processed;
            ret = processed;
        }
    }
    
    free(sql);
    
    /* 清空缓冲区 */
    g_ch_client->buffer_count = 0;
    g_ch_client->last_export_time = rte_get_timer_cycles();
    
    return ret;
}

/* 强制导出缓冲区中的数据 */
int clickhouse_flush_buffer(void)
{
    if (g_ch_client == NULL || g_ch_client->buffer_count == 0) {
        return 0;
    }
    
    return clickhouse_export_batch(g_ch_client->export_buffer, g_ch_client->buffer_count);
}

/* 打印ClickHouse统计信息 */
void print_clickhouse_stats(void)
{
    if (g_ch_client == NULL) {
        printf("ClickHouse client not initialized\n");
        return;
    }
    
    printf("\n=== ClickHouse Export Statistics ===\n");
    printf("Connection status:   %s\n", g_ch_client->connected ? "Connected" : "Disconnected");
    printf("Host:                %s:%u\n", g_ch_client->host, g_ch_client->port);
    printf("Database.Table:      %s.%s\n", g_ch_client->database, g_ch_client->table);
    printf("Total exports:       %" PRIu64 "\n", g_ch_client->total_exports);
    printf("Total records:       %" PRIu64 "\n", g_ch_client->total_records);
    printf("Failed exports:      %" PRIu64 "\n", g_ch_client->failed_exports);
    printf("Buffer count:        %u\n", g_ch_client->buffer_count);
    
    if (g_ch_client->total_exports > 0) {
        double avg_records = (double)g_ch_client->total_records / g_ch_client->total_exports;
        printf("Avg records/batch:   %.2f\n", avg_records);
    }
    
    printf("====================================\n\n");
}

/* 清理ClickHouse客户端 */
void clickhouse_cleanup(void)
{
    if (g_ch_client == NULL) {
        return;
    }
    
    RTE_LOG(INFO, CLICKHOUSE, "Cleaning up ClickHouse client...\n");
    
    /* 导出缓冲区中剩余的数据 */
    clickhouse_flush_buffer();
    
    /* 打印最终统计信息 */
    print_clickhouse_stats();
    
    /* 关闭备用文件 */
    if (g_ch_client->output_file) {
        fclose(g_ch_client->output_file);
        g_ch_client->output_file = NULL;
    }
    
    /* 清理客户端 */
    rte_free(g_ch_client);
    g_ch_client = NULL;
    
    /* 清理全局配置指针 */
    if (g_app_config) {
        g_app_config->clickhouse_client = NULL;
    }
    
    RTE_LOG(INFO, CLICKHOUSE, "ClickHouse client cleanup completed\n");
}
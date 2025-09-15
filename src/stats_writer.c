/*
 * 统计信息写入模块
 * 负责将统计信息写入文件，供实时监控使用
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdarg.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_cycles.h>

#include "dpdk_multi_port.h"

#define RTE_LOGTYPE_STATS_WRITER RTE_LOGTYPE_USER8

/* 全局文件指针 */
static FILE *stats_file = NULL;

/* 初始化统计文件写入器 */
int stats_writer_init(void)
{
    stats_file = fopen(STATS_OUTPUT_FILE, "w");
    if (stats_file == NULL) {
        RTE_LOG(ERR, STATS_WRITER, "Cannot open stats output file %s\n", STATS_OUTPUT_FILE);
        return -1;
    }

    //RTE_LOG(INFO, STATS_WRITER, "Stats writer initialized, output to %s\n", STATS_OUTPUT_FILE);
    return 0;
}

/* 清理统计文件写入器 */
void stats_writer_cleanup(void)
{
    if (stats_file) {
        fclose(stats_file);
        stats_file = NULL;
    }
}

/* 写入所有统计信息到文件 */
void write_all_stats_to_file(void)
{
    FILE *original_stdout = stdout;

    /* 打开文件 */
    if (stats_writer_init() < 0) {
        return;
    }

    /* 重定向stdout到文件 */
    stdout = stats_file;

    printf("=======================================================\n");
    printf("           DPDK Multi-Port Packet Processor           \n");
    printf("=======================================================\n");

    /* 打印配置信息 */
    config_print();

    /* 打印RX核心统计 */
    print_rx_cores_summary();

    /* 打印Worker核心统计 */
    print_worker_cores_summary();

    /* 打印Ring统计 */
    ring_print_stats();

    /* 打印流表统计 */
    flow_table_stats_print();

    /* 打印增强统计信息 */
    print_enhanced_stats();

    /* 打印协议识别统计 */
    print_protocol_stats();

    /* 打印应用识别统计 */
    print_application_stats();

    /* 打印ClickHouse统计 */
    print_clickhouse_stats();

    printf("=======================================================\n");

    /* 恢复stdout */
    stdout = original_stdout;

    /* 关闭文件 */
    stats_writer_cleanup();
}
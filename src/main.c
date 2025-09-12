/*
 * 主控制程序和线程管理
 * 负责初始化所有模块，启动各个核心线程，处理信号和统计输出
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>

#include "dpdk_multi_port.h"

#define RTE_LOGTYPE_MAIN RTE_LOGTYPE_USER7

/* 全局变量 */
volatile bool force_quit = false;

/* 实时统计线程相关 */
static volatile bool stats_thread_running = false;
static uint32_t stats_refresh_interval = DEFAULT_STATS_REFRESH_INTERVAL;  /* 统计刷新间隔(秒) */

/* 声明外部函数 */
extern int ring_enqueue_burst(struct rte_ring *ring, struct rte_mbuf **pkts, uint16_t n_pkts, uint16_t ring_idx);
extern int ring_dequeue_burst(struct rte_ring *ring, struct rte_mbuf **pkts, uint16_t n_pkts, uint16_t ring_idx);
extern void print_rx_cores_summary(void);
extern void print_worker_cores_summary(void);
extern void ring_print_stats(void);

/* 信号处理函数 */
void signal_handler(int sig)
{
    if (sig == SIGINT || sig == SIGTERM) {
        printf("\nSignal %d received, preparing to exit...\n", sig);
        force_quit = true;
    }
}

/* 将统计信息写入文件 */
static void write_stats_to_file(void)
{
    FILE *file = fopen(STATS_OUTPUT_FILE, "w");
    if (file == NULL) {
        RTE_LOG(ERR, MAIN, "Cannot open stats output file %s\n", STATS_OUTPUT_FILE);
        return;
    }

    fprintf(file, "=======================================================\n");
    fprintf(file, "           DPDK Multi-Port Packet Processor           \n");
    fprintf(file, "=======================================================\n");

    /* 这里需要实现将统计信息写入文件的逻辑 */
    /* 由于现有的打印函数直接输出到stdout，我们需要重写这些函数 */
    /* 或者创建新的函数将统计信息写入文件 */

    fprintf(file, "NOTE: Real-time stats output to file is not fully implemented yet.\n");
    fprintf(file, "Please check the terminal output for detailed statistics.\n");

    fprintf(file, "=======================================================\n");

    fclose(file);
}

/* 打印应用程序统计信息到终端（用于调试）*/
void print_stats(void)
{
    static uint64_t prev_tsc = 0;
    uint64_t cur_tsc = rte_get_timer_cycles();
    uint64_t diff_tsc = cur_tsc - prev_tsc;

    /* 每10秒打印一次统计信息 */
    if (diff_tsc > rte_get_timer_hz() * 10) {
        system("clear");  /* 清屏 */

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
        printf("Press Ctrl+C to quit\n");

        prev_tsc = cur_tsc;
    }
}

/* 实时统计线程函数 */
static int stats_thread_main(__rte_unused void *arg)
{
    RTE_LOG(INFO, MAIN, "Starting real-time stats thread with interval %u seconds\n", stats_refresh_interval);

    stats_thread_running = true;

    while (!force_quit && stats_thread_running) {
        /* 收集并写入统计信息 */
        write_stats_to_file();

        /* 等待指定间隔，使用DPDK的延迟函数并分段检查退出信号 */
        uint32_t delay_ms = stats_refresh_interval * 1000;
        uint32_t elapsed_ms = 0;
        const uint32_t check_interval = 1000;  /* 每秒检查一次退出信号 */

        while (elapsed_ms < delay_ms && !force_quit && stats_thread_running) {
            uint32_t sleep_ms = (delay_ms - elapsed_ms) > check_interval ? check_interval : (delay_ms - elapsed_ms);
            rte_delay_ms(sleep_ms);
            elapsed_ms += sleep_ms;
        }
    }

    RTE_LOG(INFO, MAIN, "Real-time stats thread stopped\n");
    return 0;
}

/* 启动RX核心线程 */
static int launch_rx_cores(void)
{
    uint16_t i;
    int ret;

    RTE_LOG(INFO, MAIN, "Launching RX cores...\n");

    for (i = 0; i < g_app_config->n_rx_cores; i++) {
        uint16_t lcore_id = g_app_config->rx_lcore_conf[i].lcore_id;

        if (!rte_lcore_is_enabled(lcore_id)) {
            RTE_LOG(ERR, MAIN, "RX lcore %u is not enabled in EAL\n", lcore_id);
            return -1;
        }

        RTE_LOG(INFO, MAIN, "Starting RX core on lcore %u\n", lcore_id);
        ret = rte_eal_remote_launch(rx_core_main, NULL, lcore_id);
        if (ret != 0) {
            RTE_LOG(ERR, MAIN, "Failed to launch RX core on lcore %u\n", lcore_id);
            return ret;
        }
    }

    return 0;
}

/* 启动Worker核心线程 */
static int launch_worker_cores(void)
{
    uint16_t i;
    int ret;

    RTE_LOG(INFO, MAIN, "Launching Worker cores...\n");

    for (i = 0; i < g_app_config->n_worker_cores; i++) {
        uint16_t lcore_id = g_app_config->worker_conf[i].lcore_id;

        if (!rte_lcore_is_enabled(lcore_id)) {
            RTE_LOG(ERR, MAIN, "Worker lcore %u is not enabled in EAL\n", lcore_id);
            return -1;
        }

        RTE_LOG(INFO, MAIN, "Starting Worker core on lcore %u\n", lcore_id);
        ret = rte_eal_remote_launch(worker_core_main, NULL, lcore_id);
        if (ret != 0) {
            RTE_LOG(ERR, MAIN, "Failed to launch Worker core on lcore %u\n", lcore_id);
            return ret;
        }
    }

    return 0;
}

/* 等待所有核心线程结束 */
static void wait_for_cores(void)
{
    uint16_t i;
    int ret;

    RTE_LOG(INFO, MAIN, "Waiting for all cores to stop...\n");

    /* 停止统计线程 */
    stats_thread_running = false;

    /* 等待RX核心 */
    for (i = 0; i < g_app_config->n_rx_cores; i++) {
        uint16_t lcore_id = g_app_config->rx_lcore_conf[i].lcore_id;
        ret = rte_eal_wait_lcore(lcore_id);
        if (ret < 0) {
            RTE_LOG(ERR, MAIN, "RX core %u returned with error %d\n", lcore_id, ret);
        } else {
            RTE_LOG(INFO, MAIN, "RX core %u stopped normally\n", lcore_id);
        }
    }

    /* 等待Worker核心 */
    for (i = 0; i < g_app_config->n_worker_cores; i++) {
        uint16_t lcore_id = g_app_config->worker_conf[i].lcore_id;
        ret = rte_eal_wait_lcore(lcore_id);
        if (ret < 0) {
            RTE_LOG(ERR, MAIN, "Worker core %u returned with error %d\n", lcore_id, ret);
        } else {
            RTE_LOG(INFO, MAIN, "Worker core %u stopped normally\n", lcore_id);
        }
    }
}

/* 主函数 */
int main(int argc, char **argv)
{
    int ret;
    uint16_t lcore_id;

    /* 初始化EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_panic("Cannot init EAL\n");
    }
    argc -= ret;
    argv += ret;

    /* 检查可用的逻辑核心数量 */
    if (rte_lcore_count() < 2) {
        rte_panic("At least 2 lcores are required\n");
    }

    RTE_LOG(INFO, MAIN, "DPDK Multi-Port Packet Processor Starting...\n");
    RTE_LOG(INFO, MAIN, "Available lcores: %u\n", rte_lcore_count());

    /* 初始化配置 */
    ret = config_init();
    if (ret < 0) {
        rte_panic("Cannot initialize config\n");
    }

    /* 解析应用程序参数 */
    ret = config_parse_args(argc, argv);
    if (ret < 0) {
        rte_panic("Cannot parse app arguments\n");
    } else if (ret > 0) {
        /* 显示帮助信息后退出 */
        config_cleanup();
        rte_eal_cleanup();
        return 0;
    }

    /* 验证核心配置 */
    RTE_LCORE_FOREACH(lcore_id) {
        bool is_used = false;

        /* 检查是否用作RX核心 */
        for (uint16_t i = 0; i < g_app_config->n_rx_cores; i++) {
            if (g_app_config->rx_lcore_conf[i].lcore_id == lcore_id) {
                is_used = true;
                break;
            }
        }

        /* 检查是否用作Worker核心 */
        if (!is_used) {
            for (uint16_t i = 0; i < g_app_config->n_worker_cores; i++) {
                if (g_app_config->worker_conf[i].lcore_id == lcore_id) {
                    is_used = true;
                    break;
                }
            }
        }

        if (!is_used && lcore_id != rte_get_main_lcore()) {
            RTE_LOG(WARNING, MAIN, "Lcore %u is enabled but not used\n", lcore_id);
        }
    }

    /* 打印配置信息 */
    config_print();

    /* 初始化DPDK */
    ret = dpdk_init();
    if (ret < 0) {
        rte_panic("Cannot initialize DPDK\n");
    }

    /* 初始化Ring管理 */
    ret = rings_init();
    if (ret < 0) {
        rte_panic("Cannot initialize rings\n");
    }

    /* 初始化流表 */
    ret = flow_table_init();
    if (ret < 0) {
        rte_panic("Cannot initialize flow table\n");
    }

    /* 初始化协议识别引擎 */
    ret = protocol_engine_init();
    if (ret < 0) {
        RTE_LOG(WARNING, MAIN, "Protocol engine initialization failed, continuing without protocol identification\n");
    }

    /* 初始化应用识别引擎 */
    ret = app_engine_init();
    if (ret < 0) {
        RTE_LOG(WARNING, MAIN, "Application engine initialization failed, continuing without application identification\n");
    }

    /* 初始化ClickHouse客户端 */
    ret = clickhouse_init();
    if (ret < 0) {
        RTE_LOG(WARNING, MAIN, "ClickHouse initialization failed, will use backup file output\n");
    }

    /* 初始化增强统计模块 */
    ret = enhanced_stats_init();
    if (ret < 0) {
        RTE_LOG(WARNING, MAIN, "Enhanced statistics initialization failed, continuing with basic stats\n");
    }

    /* 注册信号处理函数 */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("\n=== Initialization Complete ===\n");
    printf("Press Ctrl+C to quit\n\n");

    /* 启动实时统计线程 */
    //rte_eal_remote_launch(stats_thread_main, NULL, rte_get_next_lcore(rte_lcore_id(), 1, 0));

    /* 启动所有核心线程 */
    ret = launch_rx_cores();
    if (ret < 0) {
        force_quit = true;
        goto cleanup;
    }

    ret = launch_worker_cores();
    if (ret < 0) {
        force_quit = true;
        goto cleanup;
    }

    /* 主循环：定期打印统计信息到终端（用于调试）*/
    while (!force_quit) {
        print_stats();
        rte_delay_ms(100);  /* 100ms休眠 */
    }

    RTE_LOG(INFO, MAIN, "Application shutting down...\n");

cleanup:
    /* 等待所有核心停止 */
    wait_for_cores();

    /* 清理资源 */
    printf("\nCleaning up...\n");

    /* 导出剩余数据到ClickHouse */
    clickhouse_flush_buffer();

    enhanced_stats_cleanup();
    app_engine_cleanup();
    protocol_engine_cleanup();
    clickhouse_cleanup();
    flow_table_cleanup();
    rings_cleanup();
    dpdk_cleanup();
    config_cleanup();

    /* 清理EAL */
    ret = rte_eal_cleanup();
    if (ret < 0) {
        RTE_LOG(ERR, MAIN, "EAL cleanup failed: %s\n", strerror(-ret));
    }

    printf("Application exit.\n");
    return 0;
}
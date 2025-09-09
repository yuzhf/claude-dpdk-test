/*
 * 配置管理模块
 * 负责解析命令行参数、配置核心队列映射关系
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_lcore.h>

#include "dpdk_multi_port.h"

#define RTE_LOGTYPE_CONFIG RTE_LOGTYPE_USER1

/* 全局配置变量 */
struct app_config *g_app_config = NULL;

/* 默认配置 */
static struct app_config default_config = {
    .n_ports = 2,
    .port_list = {0, 1},
    .n_rx_queues = {4, 4},
    .n_tx_queues = {4, 4},
    .n_rx_cores = 3,
    .n_worker_cores = 3,
    .n_rings = 0
};

/* 命令行选项 */
static const char short_options[] = 
    "p:"  /* portmask */
    "q:"  /* queues per port */
    "r:"  /* rx cores */
    "w:"  /* worker cores */
    "h";  /* help */

static const struct option long_options[] = {
    {"portmask", required_argument, NULL, 'p'},
    {"queues", required_argument, NULL, 'q'},
    {"rx-cores", required_argument, NULL, 'r'},
    {"worker-cores", required_argument, NULL, 'w'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}
};

/* 解析端口掩码 */
static int parse_portmask(const char *portmask_str)
{
    unsigned long portmask;
    uint16_t port_id;
    int i = 0;

    portmask = strtoul(portmask_str, NULL, 16);
    if (portmask == 0) {
        RTE_LOG(ERR, CONFIG, "Invalid portmask\n");
        return -1;
    }

    g_app_config->n_ports = 0;
    for (port_id = 0; port_id < RTE_MAX_ETHPORTS && i < MAX_PORTS; port_id++) {
        if ((portmask & (1UL << port_id)) != 0) {
            g_app_config->port_list[i] = port_id;
            i++;
        }
    }
    g_app_config->n_ports = i;

    RTE_LOG(INFO, CONFIG, "Parsed %u ports from portmask 0x%lx\n", 
            g_app_config->n_ports, portmask);
    
    return 0;
}

/* 解析队列配置 "port0:4,port1:4" */
static int parse_queue_config(const char *queue_str)
{
    char *str_copy, *token, *port_str, *queue_str_ptr;
    uint16_t port_id, n_queues;
    int i;

    str_copy = strdup(queue_str);
    if (!str_copy) {
        RTE_LOG(ERR, CONFIG, "Memory allocation failed\n");
        return -1;
    }

    token = strtok(str_copy, ",");
    while (token != NULL) {
        port_str = strtok(token, ":");
        queue_str_ptr = strtok(NULL, ":");
        
        if (!port_str || !queue_str_ptr) {
            RTE_LOG(ERR, CONFIG, "Invalid queue config format\n");
            free(str_copy);
            return -1;
        }

        if (sscanf(port_str, "port%hu", &port_id) != 1) {
            RTE_LOG(ERR, CONFIG, "Invalid port format: %s\n", port_str);
            free(str_copy);
            return -1;
        }

        n_queues = (uint16_t)strtoul(queue_str_ptr, NULL, 10);

        /* 查找对应的端口并设置队列数 */
        for (i = 0; i < g_app_config->n_ports; i++) {
            if (g_app_config->port_list[i] == port_id) {
                g_app_config->n_rx_queues[i] = n_queues;
                g_app_config->n_tx_queues[i] = n_queues;
                RTE_LOG(INFO, CONFIG, "Port %u: %u RX/TX queues\n", 
                        port_id, n_queues);
                break;
            }
        }

        token = strtok(NULL, ",");
    }

    free(str_copy);
    return 0;
}

/* 解析核心配置 "1:port0.0-3,2:port1.0-1,3:port1.2-3" */
static int parse_rx_cores_config(const char *cores_str)
{
    char *str_copy, *core_token, *core_str, *queue_str;
    char *port_str, *range_str;
    uint16_t lcore_id, port_id, queue_start, queue_end, q;
    int core_idx = 0;

    str_copy = strdup(cores_str);
    if (!str_copy) {
        RTE_LOG(ERR, CONFIG, "Memory allocation failed\n");
        return -1;
    }

    core_token = strtok(str_copy, ",");
    while (core_token != NULL && core_idx < MAX_RX_CORES) {
        core_str = strtok(core_token, ":");
        queue_str = strtok(NULL, ":");
        
        if (!core_str || !queue_str) {
            RTE_LOG(ERR, CONFIG, "Invalid rx core config format\n");
            free(str_copy);
            return -1;
        }

        lcore_id = (uint16_t)strtoul(core_str, NULL, 10);
        
        /* 解析队列配置 port0.0-3 */
        port_str = strtok(queue_str, ".");
        range_str = strtok(NULL, ".");
        
        if (!port_str || !range_str) {
            RTE_LOG(ERR, CONFIG, "Invalid queue range format\n");
            free(str_copy);
            return -1;
        }

        if (sscanf(port_str, "port%hu", &port_id) != 1) {
            RTE_LOG(ERR, CONFIG, "Invalid port format: %s\n", port_str);
            free(str_copy);
            return -1;
        }

        if (sscanf(range_str, "%hu-%hu", &queue_start, &queue_end) != 2) {
            /* 单个队列 */
            queue_start = queue_end = (uint16_t)strtoul(range_str, NULL, 10);
        }

        /* 配置rx核心 */
        struct lcore_conf *lconf = &g_app_config->rx_lcore_conf[core_idx];
        lconf->lcore_id = lcore_id;
        lconf->n_rx_queues = 0;
        lconf->n_worker_rings = 0;

        for (q = queue_start; q <= queue_end && lconf->n_rx_queues < MAX_QUEUES_PER_PORT; q++) {
            lconf->rx_queues[lconf->n_rx_queues].port_id = port_id;
            lconf->rx_queues[lconf->n_rx_queues].queue_id = q;
            lconf->rx_queues[lconf->n_rx_queues].lcore_id = lcore_id;
            lconf->n_rx_queues++;
        }

        RTE_LOG(INFO, CONFIG, "RX Core %u: Port %u, Queues %u-%u (%u queues)\n",
                lcore_id, port_id, queue_start, queue_end, lconf->n_rx_queues);
        
        core_idx++;
        core_token = strtok(NULL, ",");
    }

    g_app_config->n_rx_cores = core_idx;
    free(str_copy);
    return 0;
}

/* 解析worker核心配置 "4,5,6" */
static int parse_worker_cores_config(const char *cores_str)
{
    char *str_copy, *token;
    uint16_t lcore_id;
    int core_idx = 0;

    str_copy = strdup(cores_str);
    if (!str_copy) {
        RTE_LOG(ERR, CONFIG, "Memory allocation failed\n");
        return -1;
    }

    token = strtok(str_copy, ",");
    while (token != NULL && core_idx < MAX_WORKER_CORES) {
        lcore_id = (uint16_t)strtoul(token, NULL, 10);
        
        struct worker_conf *wconf = &g_app_config->worker_conf[core_idx];
        wconf->lcore_id = lcore_id;
        wconf->n_producer_cores = 0;
        
        RTE_LOG(INFO, CONFIG, "Worker Core %u configured\n", lcore_id);
        
        core_idx++;
        token = strtok(NULL, ",");
    }

    g_app_config->n_worker_cores = core_idx;
    free(str_copy);
    return 0;
}

/* 打印使用帮助 */
static void print_usage(const char *prgname)
{
    printf("Usage: %s [EAL options] -- [APP options]\n\n", prgname);
    printf("APP options:\n");
    printf("  -p, --portmask PORTMASK: Hexadecimal bitmask of ports (default: 0x3)\n");
    printf("  -q, --queues QUEUES: Queue config per port, format: port0:4,port1:4\n");
    printf("  -r, --rx-cores CORES: RX core config, format: 1:port0.0-3,2:port1.0-1,3:port1.2-3\n");
    printf("  -w, --worker-cores CORES: Worker core config, format: 4,5,6\n");
    printf("  -h, --help: Show this help message\n\n");
    printf("Example:\n");
    printf("  %s -l 0-6 -- -p 0x3 -q port0:4,port1:4 -r 1:port0.0-3,2:port1.0-1,3:port1.2-3 -w 4,5,6\n", prgname);
}

/* 初始化配置 */
int config_init(void)
{
    /* 分配配置结构内存 */
    g_app_config = rte_zmalloc("app_config", sizeof(struct app_config), RTE_CACHE_LINE_SIZE);
    if (g_app_config == NULL) {
        RTE_LOG(ERR, CONFIG, "Cannot allocate memory for app config\n");
        return -1;
    }

    /* 使用默认配置初始化 */
    memcpy(g_app_config, &default_config, sizeof(struct app_config));
    
    RTE_LOG(INFO, CONFIG, "Configuration initialized with defaults\n");
    return 0;
}

/* 解析命令行参数 */
int config_parse_args(int argc, char **argv)
{
    int opt, ret;
    int option_index;
    char *prgname = argv[0];

    while ((opt = getopt_long(argc, argv, short_options, long_options, &option_index)) != EOF) {
        switch (opt) {
        case 'p':
            ret = parse_portmask(optarg);
            if (ret < 0) {
                print_usage(prgname);
                return -1;
            }
            break;
        case 'q':
            ret = parse_queue_config(optarg);
            if (ret < 0) {
                print_usage(prgname);
                return -1;
            }
            break;
        case 'r':
            ret = parse_rx_cores_config(optarg);
            if (ret < 0) {
                print_usage(prgname);
                return -1;
            }
            break;
        case 'w':
            ret = parse_worker_cores_config(optarg);
            if (ret < 0) {
                print_usage(prgname);
                return -1;
            }
            break;
        case 'h':
            print_usage(prgname);
            return 1; /* 正常退出 */
        default:
            print_usage(prgname);
            return -1;
        }
    }

    RTE_LOG(INFO, CONFIG, "Command line arguments parsed successfully\n");
    return 0;
}

/* 打印配置信息 */
void config_print(void)
{
    int i, j;

    printf("\n=== Application Configuration ===\n");
    
    printf("Ports (%u): ", g_app_config->n_ports);
    for (i = 0; i < g_app_config->n_ports; i++) {
        printf("%u ", g_app_config->port_list[i]);
    }
    printf("\n");

    for (i = 0; i < g_app_config->n_ports; i++) {
        printf("Port %u: %u RX queues, %u TX queues\n", 
               g_app_config->port_list[i],
               g_app_config->n_rx_queues[i],
               g_app_config->n_tx_queues[i]);
    }

    printf("\nRX Cores (%u):\n", g_app_config->n_rx_cores);
    for (i = 0; i < g_app_config->n_rx_cores; i++) {
        struct lcore_conf *lconf = &g_app_config->rx_lcore_conf[i];
        printf("  Core %u: ", lconf->lcore_id);
        for (j = 0; j < lconf->n_rx_queues; j++) {
            printf("Port%u.Q%u ", 
                   lconf->rx_queues[j].port_id,
                   lconf->rx_queues[j].queue_id);
        }
        printf("\n");
    }

    printf("\nWorker Cores (%u): ", g_app_config->n_worker_cores);
    for (i = 0; i < g_app_config->n_worker_cores; i++) {
        printf("%u ", g_app_config->worker_conf[i].lcore_id);
    }
    printf("\n");

    printf("===============================\n\n");
}

/* 清理配置资源 */
void config_cleanup(void)
{
    if (g_app_config) {
        rte_free(g_app_config);
        g_app_config = NULL;
    }
}
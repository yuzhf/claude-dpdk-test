/*
 * DPDK端口和队列初始化模块
 * 负责初始化网卡、配置队列、创建内存池等
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
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#include "dpdk_multi_port.h"

#define RTE_LOGTYPE_DPDK_INIT RTE_LOGTYPE_USER3

/* 默认RSS key */
static uint8_t rss_key[] = {
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
};

/* 端口默认配置 */
static struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .mtu = RTE_ETHER_MAX_LEN,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = rss_key,
            .rss_key_len = sizeof(rss_key),
            .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP,
        },
    },
    .txmode = {
        .mq_mode = RTE_ETH_MQ_TX_NONE,
    },
};

/* 创建内存池 */
static struct rte_mempool * create_mbuf_pool(uint16_t port_id, uint16_t rx_queue_id)
{
    unsigned int nb_mbufs;

    /* 计算所需的mbuf数量 */
    nb_mbufs = MBUF_COUNT;

	struct rte_mempool *mbuf_pool = NULL;

    /* 为每个worker核心额外分配mbuf */
    nb_mbufs += g_app_config->n_worker_cores * 4096;

    RTE_LOG(INFO, DPDK_INIT, "Creating mbuf pool with %u mbufs\n", nb_mbufs);

	char name[64];
	snprintf(name, 64, "rx-pool-%u-%u", port_id, rx_queue_id);
    mbuf_pool = rte_pktmbuf_pool_create(name, nb_mbufs,
                                          MBUF_CACHE_SIZE, 0,
                                          RTE_MBUF_DEFAULT_BUF_SIZE,
                                          rte_socket_id());

    if (mbuf_pool == NULL) {
        RTE_LOG(ERR, DPDK_INIT, "Cannot create mbuf pool\n");
        return NULL;
    }

    return mbuf_pool;
}

/* 配置端口队列 */
static int configure_port_queues(uint16_t port_id, uint16_t n_rx_queues, uint16_t n_tx_queues)
{
    struct rte_eth_dev_info dev_info;
    struct rte_eth_conf port_conf;
    struct rte_eth_rxconf rxconf;
    struct rte_eth_txconf txconf;
    int ret;
    uint16_t q;

    /* 获取设备信息 */
    ret = rte_eth_dev_info_get(port_id, &dev_info);
    if (ret != 0) {
        RTE_LOG(ERR, DPDK_INIT, "Error getting device info for port %u: %s\n",
                port_id, strerror(-ret));
        return ret;
    }

    /* 配置端口 */
    port_conf = port_conf_default;

    /* 检查RSS支持 */
    if (dev_info.flow_type_rss_offloads & port_conf.rx_adv_conf.rss_conf.rss_hf) {
        port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
    } else {
        port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
        port_conf.rx_adv_conf.rss_conf.rss_hf = 0;
        RTE_LOG(WARNING, DPDK_INIT, "Port %u does not support RSS\n", port_id);
    }

    /* 限制队列数量 */
    if (n_rx_queues > dev_info.max_rx_queues) {
        RTE_LOG(ERR, DPDK_INIT, "Port %u: requested %u RX queues, but only %u available\n",
                port_id, n_rx_queues, dev_info.max_rx_queues);
        return -1;
    }

    if (n_tx_queues > dev_info.max_tx_queues) {
        RTE_LOG(ERR, DPDK_INIT, "Port %u: requested %u TX queues, but only %u available\n",
                port_id, n_tx_queues, dev_info.max_tx_queues);
        return -1;
    }

    /* 配置设备 */
    ret = rte_eth_dev_configure(port_id, n_rx_queues, n_tx_queues, &port_conf);
    if (ret != 0) {
        RTE_LOG(ERR, DPDK_INIT, "Cannot configure device port %u: %s\n",
                port_id, strerror(-ret));
        return ret;
    }

    /* 调整RX/TX描述符数量 */
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;

    ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
    if (ret != 0) {
        RTE_LOG(ERR, DPDK_INIT, "Cannot adjust descriptors for port %u: %s\n",
                port_id, strerror(-ret));
        return ret;
    }

    RTE_LOG(INFO, DPDK_INIT, "Port %u: using %u RX desc, %u TX desc\n",
            port_id, nb_rxd, nb_txd);

    /* 配置RX队列 */
    rxconf = dev_info.default_rxconf;
    rxconf.offloads = port_conf.rxmode.offloads;

    for (q = 0; q < n_rx_queues; q++) {

	    /* 创建mbuf内存池 */
	    g_app_config->mbuf_pool[port_id][q] = create_mbuf_pool(port_id, q);
	    if (!g_app_config->mbuf_pool[port_id][q]) {
			RTE_LOG(ERR, DPDK_INIT, "create_mbuf_pool fail\n");
			return -1;
	    }

        ret = rte_eth_rx_queue_setup(port_id, q, nb_rxd,
                                     rte_eth_dev_socket_id(port_id),
                                     &rxconf,
                                     g_app_config->mbuf_pool[port_id][q]);
        if (ret < 0) {
            RTE_LOG(ERR, DPDK_INIT, "Cannot setup RX queue %u for port %u: %s\n",
                    q, port_id, strerror(-ret));
            return ret;
        }

        RTE_LOG(DEBUG, DPDK_INIT, "Port %u RX queue %u setup completed\n", port_id, q);
    }

    /* 配置TX队列 */
    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;

    for (q = 0; q < n_tx_queues; q++) {
        ret = rte_eth_tx_queue_setup(port_id, q, nb_txd,
                                     rte_eth_dev_socket_id(port_id),
                                     &txconf);
        if (ret < 0) {
            RTE_LOG(ERR, DPDK_INIT, "Cannot setup TX queue %u for port %u: %s\n",
                    q, port_id, strerror(-ret));
            return ret;
        }

        RTE_LOG(DEBUG, DPDK_INIT, "Port %u TX queue %u setup completed\n", port_id, q);
    }

    RTE_LOG(INFO, DPDK_INIT, "Port %u configured with %u RX queues, %u TX queues\n",
            port_id, n_rx_queues, n_tx_queues);

    return 0;
}

/* 初始化单个端口 */
int port_init(uint16_t port_id, uint16_t n_rx_queues, uint16_t n_tx_queues)
{
    struct rte_ether_addr addr;
    int ret;

    /* 检查端口是否有效 */
    if (!rte_eth_dev_is_valid_port(port_id)) {
        RTE_LOG(ERR, DPDK_INIT, "Port %u is not valid\n", port_id);
        return -1;
    }

    RTE_LOG(INFO, DPDK_INIT, "Initializing port %u with %u RX queues, %u TX queues\n",
            port_id, n_rx_queues, n_tx_queues);

    /* 配置端口队列 */
    ret = configure_port_queues(port_id, n_rx_queues, n_tx_queues);
    if (ret != 0) {
        return ret;
    }

    /* 启动端口 */
    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        RTE_LOG(ERR, DPDK_INIT, "Cannot start port %u: %s\n", port_id, strerror(-ret));
        return ret;
    }

    /* 设置混杂模式 */
    ret = rte_eth_promiscuous_enable(port_id);
    if (ret != 0) {
        RTE_LOG(WARNING, DPDK_INIT, "Cannot enable promiscuous mode for port %u: %s\n",
                port_id, strerror(-ret));
    }

    /* 获取MAC地址 */
    ret = rte_eth_macaddr_get(port_id, &addr);
    if (ret != 0) {
        RTE_LOG(ERR, DPDK_INIT, "Cannot get MAC address for port %u: %s\n",
                port_id, strerror(-ret));
        return ret;
    }

    RTE_LOG(INFO, DPDK_INIT, "Port %u MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
            port_id,
            addr.addr_bytes[0], addr.addr_bytes[1], addr.addr_bytes[2],
            addr.addr_bytes[3], addr.addr_bytes[4], addr.addr_bytes[5]);

    /* 等待链路状态 */
    struct rte_eth_link link;
    int link_get_err;
    const int max_check_time = 10;  /* 1s (10 * 100ms) max */

    for (int count = 0; count <= max_check_time; count++) {
        memset(&link, 0, sizeof(link));
        link_get_err = rte_eth_link_get_nowait(port_id, &link);
        if (link_get_err >= 0 && link.link_status == RTE_ETH_LINK_UP) {
            break;
        } else if (link_get_err < 0) {
            RTE_LOG(ERR, DPDK_INIT, "Port %u link get failed: %s\n",
                    port_id, strerror(-link_get_err));
            return -1;
        }
        rte_delay_ms(100);
    }

    if (link.link_status == RTE_ETH_LINK_UP) {
        RTE_LOG(INFO, DPDK_INIT, "Port %u Link Up - speed %u Mbps - %s\n",
                port_id, link.link_speed,
                (link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX) ? "full-duplex" : "half-duplex");
    } else {
        RTE_LOG(WARNING, DPDK_INIT, "Port %u Link Down\n", port_id);
    }

    return 0;
}

/* 初始化DPDK */
int dpdk_init(void)
{
    int ret;
    uint16_t i;

    RTE_LOG(INFO, DPDK_INIT, "Initializing DPDK...\n");

    /* 检查端口数量 */
    uint16_t nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0) {
        RTE_LOG(ERR, DPDK_INIT, "No Ethernet ports detected\n");
        return -1;
    }

    RTE_LOG(INFO, DPDK_INIT, "Detected %u Ethernet ports\n", nb_ports);

    /* 验证配置的端口是否存在 */
    for (i = 0; i < g_app_config->n_ports; i++) {
        uint16_t port_id = g_app_config->port_list[i];
        if (port_id >= nb_ports || !rte_eth_dev_is_valid_port(port_id)) {
            RTE_LOG(ERR, DPDK_INIT, "Port %u is not available\n", port_id);
            return -1;
        }
    }

    /* 初始化每个端口 */
    for (i = 0; i < g_app_config->n_ports; i++) {
        uint16_t port_id = g_app_config->port_list[i];
        ret = port_init(port_id, g_app_config->n_rx_queues[i], g_app_config->n_tx_queues[i]);
        if (ret != 0) {
            RTE_LOG(ERR, DPDK_INIT, "Cannot initialize port %u\n", port_id);
            return ret;
        }
    }

    RTE_LOG(INFO, DPDK_INIT, "DPDK initialization completed successfully\n\n");
    return 0;
}

/* 清理DPDK资源 */
void dpdk_cleanup(void)
{
    uint16_t i, j, port_id;

    RTE_LOG(INFO, DPDK_INIT, "Cleaning up DPDK resources...\n");

    /* 停止并关闭所有端口 */
    for (i = 0; i < g_app_config->n_ports; i++) {
        port_id = g_app_config->port_list[i];

        RTE_LOG(INFO, DPDK_INIT, "Stopping port %u\n", port_id);
        rte_eth_dev_stop(port_id);

        RTE_LOG(INFO, DPDK_INIT, "Closing port %u\n", port_id);
        rte_eth_dev_close(port_id);

		/* 清理内存池 */
		RTE_LOG(INFO, DPDK_INIT, "Cleaning up port %u mbuf pool\n", port_id);
		for (j = 0; j < g_app_config->n_rx_queues[i]; j++) {
			if (g_app_config->mbuf_pool[i][j]) {
				// mbuf池由EAL自动清理
				g_app_config->mbuf_pool[i][j] = NULL;
			}
		}
    }

    RTE_LOG(INFO, DPDK_INIT, "DPDK cleanup completed\n");
}

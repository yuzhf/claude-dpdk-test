/*
 * 基于端口的协议识别模块
 * 支持外部配置文件映射，高效可扩展
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <ctype.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "dpdk_multi_port.h"

#define RTE_LOGTYPE_PROTOCOL RTE_LOGTYPE_USER8

/* 端口协议映射表项 */
struct port_protocol_entry {
    uint16_t port;                          /* 端口号 */
    uint8_t protocol_type;                  /* 协议类型（TCP/UDP） */
    uint16_t protocol_id;                   /* 协议ID */
    char protocol_name[MAX_PROTOCOL_NAME];  /* 协议名称 */
    uint8_t confidence;                     /* 识别置信度 */
} __rte_packed;

/* 协议识别引擎 */
struct protocol_engine {
    struct rte_hash *port_hash;             /* 端口哈希表 */
    struct port_protocol_entry *entries;   /* 协议条目数组 */
    uint32_t max_entries;                   /* 最大条目数 */
    uint32_t num_entries;                   /* 当前条目数 */
    
    /* 统计信息 */
    uint64_t total_lookups;                 /* 总查找次数 */
    uint64_t successful_matches;            /* 成功匹配次数 */
    uint64_t failed_matches;                /* 失败匹配次数 */
} __rte_cache_aligned;

static struct protocol_engine *g_protocol_engine = NULL;

/* 端口协议键结构 */
struct port_key {
    uint16_t port;
    uint8_t protocol_type;  /* IPPROTO_TCP or IPPROTO_UDP */
} __rte_packed;

/* 端口协议键哈希函数 */
static uint32_t port_key_hash(const void *key, uint32_t key_len, uint32_t init_val)
{
    const struct port_key *pkey = (const struct port_key *)key;
    return rte_jhash_2words((uint32_t)pkey->port, (uint32_t)pkey->protocol_type, init_val);
}

/* 解析协议配置文件 */
static int parse_protocol_config_file(const char *filename)
{
    FILE *fp;
    char line[256];
    char protocol_name[MAX_PROTOCOL_NAME];
    uint16_t port;
    char protocol_type_str[16];
    uint8_t protocol_type;
    uint8_t confidence;
    uint32_t entry_idx = 0;
    
    fp = fopen(filename, "r");
    if (fp == NULL) {
        RTE_LOG(ERR, PROTOCOL, "Cannot open protocol config file: %s\n", filename);
        return -1;
    }
    
    RTE_LOG(INFO, PROTOCOL, "Loading protocol configuration from %s\n", filename);
    
    while (fgets(line, sizeof(line), fp) != NULL && entry_idx < g_protocol_engine->max_entries) {
        /* 跳过注释和空行 */
        char *p = line;
        while (isspace(*p)) p++;
        if (*p == '#' || *p == '\0' || *p == '\n') {
            continue;
        }
        
        /* 解析格式: protocol_name,port,tcp/udp,confidence */
        if (sscanf(line, "%63[^,],%hu,%15[^,],%hhu", 
                   protocol_name, &port, protocol_type_str, &confidence) == 4) {
            
            /* 转换协议类型 */
            if (strcasecmp(protocol_type_str, "tcp") == 0) {
                protocol_type = IPPROTO_TCP;
            } else if (strcasecmp(protocol_type_str, "udp") == 0) {
                protocol_type = IPPROTO_UDP;
            } else {
                RTE_LOG(WARNING, PROTOCOL, "Unknown protocol type: %s, skipping\n", protocol_type_str);
                continue;
            }
            
            /* 创建协议条目 */
            struct port_protocol_entry *entry = &g_protocol_engine->entries[entry_idx];
            entry->port = port;
            entry->protocol_type = protocol_type;
            entry->protocol_id = entry_idx + 1;  /* 简单的ID分配 */
            strncpy(entry->protocol_name, protocol_name, MAX_PROTOCOL_NAME - 1);
            entry->protocol_name[MAX_PROTOCOL_NAME - 1] = '\0';
            entry->confidence = confidence;
            
            /* 添加到哈希表 */
            struct port_key key = {port, protocol_type};
            int ret = rte_hash_add_key_data(g_protocol_engine->port_hash, &key, entry);
            if (ret < 0) {
                RTE_LOG(ERR, PROTOCOL, "Failed to add protocol entry to hash: %s\n", strerror(-ret));
                continue;
            }
            
            entry_idx++;
            
            RTE_LOG(DEBUG, PROTOCOL, "Loaded protocol: %s, port=%u, type=%s, confidence=%u\n",
                    protocol_name, port, protocol_type_str, confidence);
        } else {
            RTE_LOG(WARNING, PROTOCOL, "Invalid config line: %s", line);
        }
    }
    
    fclose(fp);
    
    g_protocol_engine->num_entries = entry_idx;
    RTE_LOG(INFO, PROTOCOL, "Loaded %u protocol entries\n", entry_idx);
    
    return 0;
}

/* 创建默认协议配置 */
static int create_default_protocol_config(void)
{
    /* 常见协议端口映射 */
    struct {
        const char *name;
        uint16_t port;
        uint8_t protocol_type;
        uint8_t confidence;
    } default_protocols[] = {
        /* Web服务 */
        {"HTTP", 80, IPPROTO_TCP, 95},
        {"HTTPS", 443, IPPROTO_TCP, 95},
        {"HTTP-Alt", 8080, IPPROTO_TCP, 85},
        {"HTTPS-Alt", 8443, IPPROTO_TCP, 85},
        
        /* 邮件服务 */
        {"SMTP", 25, IPPROTO_TCP, 90},
        {"POP3", 110, IPPROTO_TCP, 90},
        {"IMAP", 143, IPPROTO_TCP, 90},
        {"SMTPS", 465, IPPROTO_TCP, 90},
        {"IMAPS", 993, IPPROTO_TCP, 90},
        {"POP3S", 995, IPPROTO_TCP, 90},
        
        /* 文件传输 */
        {"FTP", 21, IPPROTO_TCP, 90},
        {"FTPS", 990, IPPROTO_TCP, 90},
        {"SFTP", 22, IPPROTO_TCP, 80}, /* SSH also uses 22 */
        {"TFTP", 69, IPPROTO_UDP, 85},
        
        /* 数据库 */
        {"MySQL", 3306, IPPROTO_TCP, 90},
        {"PostgreSQL", 5432, IPPROTO_TCP, 90},
        {"Redis", 6379, IPPROTO_TCP, 85},
        {"MongoDB", 27017, IPPROTO_TCP, 85},
        
        /* 网络管理 */
        {"SSH", 22, IPPROTO_TCP, 90},
        {"Telnet", 23, IPPROTO_TCP, 90},
        {"SNMP", 161, IPPROTO_UDP, 85},
        {"SNMP-Trap", 162, IPPROTO_UDP, 85},
        
        /* DNS */
        {"DNS", 53, IPPROTO_UDP, 95},
        {"DNS-TCP", 53, IPPROTO_TCP, 85},
        
        /* 时间同步 */
        {"NTP", 123, IPPROTO_UDP, 90},
        
        /* DHCP */
        {"DHCP-Server", 67, IPPROTO_UDP, 90},
        {"DHCP-Client", 68, IPPROTO_UDP, 90},
        
        /* 即时通讯 */
        {"QQ", 8000, IPPROTO_TCP, 75},
        {"WeChat", 80, IPPROTO_TCP, 60}, /* WeChat uses HTTP/HTTPS */
        {"WeChat", 443, IPPROTO_TCP, 60},
        
        /* 游戏 */
        {"Steam", 27015, IPPROTO_TCP, 80},
        {"Steam", 27015, IPPROTO_UDP, 80},
        
        /* 其他常见服务 */
        {"LDAP", 389, IPPROTO_TCP, 85},
        {"LDAPS", 636, IPPROTO_TCP, 85},
        {"Kerberos", 88, IPPROTO_TCP, 85},
        {"Kerberos", 88, IPPROTO_UDP, 85},
    };
    
    uint32_t num_defaults = sizeof(default_protocols) / sizeof(default_protocols[0]);
    uint32_t i;
    
    for (i = 0; i < num_defaults && i < g_protocol_engine->max_entries; i++) {
        struct port_protocol_entry *entry = &g_protocol_engine->entries[i];
        entry->port = default_protocols[i].port;
        entry->protocol_type = default_protocols[i].protocol_type;
        entry->protocol_id = i + 1;
        strncpy(entry->protocol_name, default_protocols[i].name, MAX_PROTOCOL_NAME - 1);
        entry->protocol_name[MAX_PROTOCOL_NAME - 1] = '\0';
        entry->confidence = default_protocols[i].confidence;
        
        /* 添加到哈希表 */
        struct port_key key = {entry->port, entry->protocol_type};
        int ret = rte_hash_add_key_data(g_protocol_engine->port_hash, &key, entry);
        if (ret < 0) {
            RTE_LOG(ERR, PROTOCOL, "Failed to add default protocol entry: %s\n", strerror(-ret));
            continue;
        }
    }
    
    g_protocol_engine->num_entries = i;
    RTE_LOG(INFO, PROTOCOL, "Created %u default protocol entries\n", i);
    
    return 0;
}

/* 初始化协议识别引擎 */
int protocol_engine_init(void)
{
    struct rte_hash_parameters hash_params = {0};
    char hash_name[RTE_HASH_NAMESIZE];
    
    RTE_LOG(INFO, PROTOCOL, "Initializing protocol identification engine...\n");
    
    /* 分配协议引擎内存 */
    g_protocol_engine = rte_zmalloc("protocol_engine", sizeof(struct protocol_engine), RTE_CACHE_LINE_SIZE);
    if (g_protocol_engine == NULL) {
        RTE_LOG(ERR, PROTOCOL, "Cannot allocate memory for protocol engine\n");
        return -1;
    }
    
    g_protocol_engine->max_entries = MAX_PROTOCOL_RULES;
    
    /* 分配协议条目数组 */
    g_protocol_engine->entries = rte_zmalloc("protocol_entries",
                                           sizeof(struct port_protocol_entry) * g_protocol_engine->max_entries,
                                           RTE_CACHE_LINE_SIZE);
    if (g_protocol_engine->entries == NULL) {
        RTE_LOG(ERR, PROTOCOL, "Cannot allocate memory for protocol entries\n");
        rte_free(g_protocol_engine);
        g_protocol_engine = NULL;
        return -1;
    }
    
    /* 创建端口哈希表 */
    snprintf(hash_name, sizeof(hash_name), "protocol_port_hash");
    hash_params.name = hash_name;
    hash_params.entries = g_protocol_engine->max_entries;
    hash_params.key_len = sizeof(struct port_key);
    hash_params.hash_func = port_key_hash;
    hash_params.hash_func_init_val = 0;
    hash_params.socket_id = rte_socket_id();
    hash_params.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY;
    
    g_protocol_engine->port_hash = rte_hash_create(&hash_params);
    if (g_protocol_engine->port_hash == NULL) {
        RTE_LOG(ERR, PROTOCOL, "Cannot create protocol port hash table: %s\n", rte_strerror(rte_errno));
        rte_free(g_protocol_engine->entries);
        rte_free(g_protocol_engine);
        g_protocol_engine = NULL;
        return -1;
    }
    
    /* 尝试加载配置文件，如果失败则使用默认配置 */
    if (parse_protocol_config_file(PROTOCOL_CONFIG_FILE) < 0) {
        RTE_LOG(INFO, PROTOCOL, "Config file not found, using default protocol configuration\n");
        if (create_default_protocol_config() < 0) {
            RTE_LOG(ERR, PROTOCOL, "Failed to create default protocol configuration\n");
            protocol_engine_cleanup();
            return -1;
        }
    }
    
    /* 设置全局配置指针 */
    g_app_config->protocol_engine = g_protocol_engine;
    
    RTE_LOG(INFO, PROTOCOL, "Protocol engine initialized with %u protocols\n", 
            g_protocol_engine->num_entries);
    
    return 0;
}

/* 协议识别 */
int protocol_identify(struct rte_mbuf *pkt, struct protocol_info *proto)
{
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_tcp_hdr *tcp_hdr;
    struct rte_udp_hdr *udp_hdr;
    struct port_key key;
    struct port_protocol_entry *entry;
    void *data;
    int ret;
    
    if (unlikely(g_protocol_engine == NULL || pkt == NULL || proto == NULL)) {
        return -1;
    }
    
    g_protocol_engine->total_lookups++;
    
    /* 清零结果结构 */
    memset(proto, 0, sizeof(struct protocol_info));
    
    /* 获取以太网头 */
    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    
    /* 只处理IPv4包 */
    if (unlikely(rte_be_to_cpu_16(eth_hdr->ether_type) != RTE_ETHER_TYPE_IPV4)) {
        return -1;
    }
    
    /* 获取IPv4头 */
    ipv4_hdr = (struct rte_ipv4_hdr *)((char *)eth_hdr + sizeof(struct rte_ether_hdr));
    uint8_t ip_hdr_len = (ipv4_hdr->version_ihl & 0x0F) * 4;
    
    /* 根据协议类型获取端口信息 */
    key.protocol_type = ipv4_hdr->next_proto_id;
    
    switch (ipv4_hdr->next_proto_id) {
    case IPPROTO_TCP:
        if (unlikely(rte_pktmbuf_data_len(pkt) < sizeof(struct rte_ether_hdr) + ip_hdr_len + sizeof(struct rte_tcp_hdr))) {
            return -1;
        }
        tcp_hdr = (struct rte_tcp_hdr *)((char *)ipv4_hdr + ip_hdr_len);
        
        /* 尝试匹配源端口和目的端口 */
        key.port = rte_be_to_cpu_16(tcp_hdr->dst_port);
        ret = rte_hash_lookup_data(g_protocol_engine->port_hash, &key, &data);
        if (ret >= 0) {
            entry = (struct port_protocol_entry *)data;
            goto found_match;
        }
        
        key.port = rte_be_to_cpu_16(tcp_hdr->src_port);
        ret = rte_hash_lookup_data(g_protocol_engine->port_hash, &key, &data);
        if (ret >= 0) {
            entry = (struct port_protocol_entry *)data;
            goto found_match;
        }
        break;
        
    case IPPROTO_UDP:
        if (unlikely(rte_pktmbuf_data_len(pkt) < sizeof(struct rte_ether_hdr) + ip_hdr_len + sizeof(struct rte_udp_hdr))) {
            return -1;
        }
        udp_hdr = (struct rte_udp_hdr *)((char *)ipv4_hdr + ip_hdr_len);
        
        /* 尝试匹配源端口和目的端口 */
        key.port = rte_be_to_cpu_16(udp_hdr->dst_port);
        ret = rte_hash_lookup_data(g_protocol_engine->port_hash, &key, &data);
        if (ret >= 0) {
            entry = (struct port_protocol_entry *)data;
            goto found_match;
        }
        
        key.port = rte_be_to_cpu_16(udp_hdr->src_port);
        ret = rte_hash_lookup_data(g_protocol_engine->port_hash, &key, &data);
        if (ret >= 0) {
            entry = (struct port_protocol_entry *)data;
            goto found_match;
        }
        break;
        
    default:
        /* 其他协议暂不支持端口识别 */
        return -1;
    }
    
    /* 未找到匹配 */
    g_protocol_engine->failed_matches++;
    return -ENOENT;
    
found_match:
    /* 找到匹配，复制协议信息 */
    proto->protocol_id = entry->protocol_id;
    strncpy(proto->protocol_name, entry->protocol_name, MAX_PROTOCOL_NAME - 1);
    proto->protocol_name[MAX_PROTOCOL_NAME - 1] = '\0';
    proto->confidence = entry->confidence;
    
    g_protocol_engine->successful_matches++;
    
    return 0;
}

/* 打印协议识别统计信息 */
void print_protocol_stats(void)
{
    if (g_protocol_engine == NULL) {
        printf("Protocol engine not initialized\n");
        return;
    }
    
    printf("\n=== Protocol Identification Statistics ===\n");
    printf("Total entries:       %u\n", g_protocol_engine->num_entries);
    printf("Total lookups:       %" PRIu64 "\n", g_protocol_engine->total_lookups);
    printf("Successful matches:  %" PRIu64 "\n", g_protocol_engine->successful_matches);
    printf("Failed matches:      %" PRIu64 "\n", g_protocol_engine->failed_matches);
    
    if (g_protocol_engine->total_lookups > 0) {
        double hit_rate = (double)g_protocol_engine->successful_matches * 100.0 / g_protocol_engine->total_lookups;
        printf("Hit rate:            %.2f%%\n", hit_rate);
    }
    
    printf("==========================================\n\n");
}

/* 清理协议识别引擎 */
void protocol_engine_cleanup(void)
{
    if (g_protocol_engine == NULL) {
        return;
    }
    
    RTE_LOG(INFO, PROTOCOL, "Cleaning up protocol identification engine...\n");
    
    /* 打印最终统计信息 */
    print_protocol_stats();
    
    /* 清理哈希表 */
    if (g_protocol_engine->port_hash) {
        rte_hash_free(g_protocol_engine->port_hash);
        g_protocol_engine->port_hash = NULL;
    }
    
    /* 清理条目数组 */
    if (g_protocol_engine->entries) {
        rte_free(g_protocol_engine->entries);
        g_protocol_engine->entries = NULL;
    }
    
    /* 清理引擎 */
    rte_free(g_protocol_engine);
    g_protocol_engine = NULL;
    
    /* 清理全局配置指针 */
    if (g_app_config) {
        g_app_config->protocol_engine = NULL;
    }
    
    RTE_LOG(INFO, PROTOCOL, "Protocol engine cleanup completed\n");
}
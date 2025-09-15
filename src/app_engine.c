/*
 * 基于Hyperscan的应用识别模块
 * 支持HTTP/HTTPS域名规则匹配，识别新浪、微信、QQ等应用
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
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>

#include <hs.h>
#include "dpdk_multi_port.h"

#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

#define HTTP_METHOD_GET     "GET "
#define HTTP_METHOD_POST    "POST "
#define HTTP_METHOD_PUT     "PUT "
#define HTTP_METHOD_DELETE  "DELETE "
#define HTTP_HOST_HEADER    "Host: "
#define HTTP_USER_AGENT     "User-Agent: "

/* 应用规则结构 */
struct app_rule {
    uint16_t app_id;                        /* 应用ID */
    char app_name[MAX_APP_NAME];            /* 应用名称 */
    char domain_pattern[MAX_DOMAIN_LENGTH]; /* 域名模式 */
    uint8_t confidence;                     /* 识别置信度 */
    uint32_t flags;                         /* Hyperscan标志 */
} __rte_packed;

/* 应用识别引擎 */
struct app_engine {
    hs_database_t *database;                /* Hyperscan数据库 */
    hs_scratch_t *scratch;                  /* Hyperscan临时空间 */

    struct app_rule *rules;                 /* 应用规则数组 */
    uint32_t num_rules;                     /* 规则数量 */
    uint32_t max_rules;                     /* 最大规则数 */

    /* 统计信息 */
    uint64_t total_scans;                   /* 总扫描次数 */
    uint64_t successful_matches;            /* 成功匹配次数 */
    uint64_t failed_matches;                /* 失败匹配次数 */
    uint64_t http_packets_processed;        /* HTTP包处理数量 */
} __rte_cache_aligned;

static struct app_engine *g_app_engine = NULL;

/* Hyperscan匹配回调函数 */
static int match_handler(unsigned int id, unsigned long long from, unsigned long long to,
                        unsigned int flags, void *context)
{
    struct app_info *app = (struct app_info *)context;

    if (id < g_app_engine->num_rules) {
        struct app_rule *rule = &g_app_engine->rules[id];

        /* 设置匹配结果 */
        app->app_id = rule->app_id;
        strncpy(app->app_name, rule->app_name, MAX_APP_NAME - 1);
        app->app_name[MAX_APP_NAME - 1] = '\0';
        app->confidence = rule->confidence;

        /* 复制匹配的域名模式作为匹配域名 */
        strncpy(app->matched_domain, rule->domain_pattern, MAX_DOMAIN_LENGTH - 1);
        app->matched_domain[MAX_DOMAIN_LENGTH - 1] = '\0';

        RTE_LOG(DEBUG, APP, "Matched app: %s (ID: %u, confidence: %u)\n",
                rule->app_name, rule->app_id, rule->confidence);

        /* 返回1表示停止继续匹配（如果只需要第一个匹配结果） */
        return 1;
    }

    return 0;
}

/* 解析应用规则配置文件 */
static int parse_app_rules_file(const char *filename)
{
    FILE *fp;
    char line[512];
    char app_name[MAX_APP_NAME];
    char domain_pattern[MAX_DOMAIN_LENGTH];
    uint8_t confidence;
    uint32_t rule_idx = 0;

    fp = fopen(filename, "r");
    if (fp == NULL) {
        RTE_LOG(ERR, APP, "Cannot open app rules file: %s\n", filename);
        return -1;
    }

    RTE_LOG(INFO, APP, "Loading application rules from %s\n", filename);

    while (fgets(line, sizeof(line), fp) != NULL && rule_idx < g_app_engine->max_rules) {
        /* 跳过注释和空行 */
        char *p = line;
        while (isspace(*p)) p++;
        if (*p == '#' || *p == '\0' || *p == '\n') {
            continue;
        }

        /* 解析格式: app_name,domain_pattern,confidence */
        if (sscanf(line, "%63[^,],%255[^,],%hhu", app_name, domain_pattern, &confidence) == 3) {
            struct app_rule *rule = &g_app_engine->rules[rule_idx];

            rule->app_id = rule_idx + 1;
            strncpy(rule->app_name, app_name, MAX_APP_NAME - 1);
            rule->app_name[MAX_APP_NAME - 1] = '\0';
            strncpy(rule->domain_pattern, domain_pattern, MAX_DOMAIN_LENGTH - 1);
            rule->domain_pattern[MAX_DOMAIN_LENGTH - 1] = '\0';
            rule->confidence = confidence;
            rule->flags = HS_FLAG_CASELESS | HS_FLAG_MULTILINE;

            rule_idx++;

            RTE_LOG(DEBUG, APP, "Loaded app rule: %s -> %s (confidence: %u)\n",
                    app_name, domain_pattern, confidence);
        } else {
            RTE_LOG(WARNING, APP, "Invalid rule line: %s", line);
        }
    }

    fclose(fp);

    g_app_engine->num_rules = rule_idx;
    RTE_LOG(INFO, APP, "Loaded %u application rules\n", rule_idx);

    return 0;
}

/* 创建默认应用规则 */
static int create_default_app_rules(void)
{
    struct {
        const char *app_name;
        const char *domain_pattern;
        uint8_t confidence;
    } default_rules[] = {
        /* 社交媒体 */
        {"WeChat", ".*\\.weixin\\.qq\\.com", 95},
        {"WeChat", ".*\\.wechat\\.com", 95},
        {"WeChat", ".*\\.tenpay\\.com", 85},
        {"QQ", ".*\\.qq\\.com", 95},
        {"QQ", ".*\\.gtimg\\.com", 80},
        {"QQ", ".*\\.qpic\\.cn", 80},
        {"Weibo", ".*\\.weibo\\.(com|cn)", 95},
        {"Weibo", ".*\\.sina\\.com\\.cn", 90},
        {"Weibo", ".*\\.sinaimg\\.cn", 85},

        /* 电商 */
        {"Taobao", ".*\\.taobao\\.com", 95},
        {"Taobao", ".*\\.tmall\\.com", 95},
        {"Taobao", ".*\\.alicdn\\.com", 85},
        {"JD", ".*\\.jd\\.com", 95},
        {"JD", ".*\\.360buyimg\\.com", 85},
        {"PDD", ".*\\.pinduoduo\\.com", 95},
        {"PDD", ".*\\.yangkeduo\\.com", 95},

        /* 搜索引擎 */
        {"Baidu", ".*\\.baidu\\.com", 95},
        {"Baidu", ".*\\.bdimg\\.com", 85},
        {"Baidu", ".*\\.bdstatic\\.com", 85},
        {"Google", ".*\\.google\\.(com|cn|com\\.hk)", 95},
        {"Google", ".*\\.googleapis\\.com", 90},
        {"Google", ".*\\.gstatic\\.com", 85},
        {"Bing", ".*\\.bing\\.com", 95},
        {"Bing", ".*\\.live\\.com", 80},

        /* 视频网站 */
        {"YouTube", ".*\\.youtube\\.com", 95},
        {"YouTube", ".*\\.ytimg\\.com", 85},
        {"Bilibili", ".*\\.bilibili\\.com", 95},
        {"Bilibili", ".*\\.hdslb\\.com", 85},
        {"iQiyi", ".*\\.iqiyi\\.com", 95},
        {"iQiyi", ".*\\.qy\\.net", 85},
        {"Youku", ".*\\.youku\\.com", 95},
        {"Youku", ".*\\.alikunlun\\.com", 85},
        {"Tencent Video", ".*\\.v\\.qq\\.com", 95},
        {"Tencent Video", ".*\\.gtimg\\.com", 75},

        /* 新闻媒体 */
        {"Sina", ".*\\.sina\\.com\\.cn", 95},
        {"NetEase", ".*\\.163\\.com", 95},
        {"NetEase", ".*\\.126\\.net", 85},
        {"Sohu", ".*\\.sohu\\.com", 95},
        {"Sohu", ".*\\.itc\\.cn", 85},
        {"Tencent News", ".*\\.qq\\.com", 80},

        /* 云服务 */
        {"Aliyun", ".*\\.aliyun\\.com", 95},
        {"Aliyun", ".*\\.aliyuncs\\.com", 90},
        {"Tencent Cloud", ".*\\.qcloud\\.com", 95},
        {"Tencent Cloud", ".*\\.myqcloud\\.com", 90},
        {"Baidu Cloud", ".*\\.baidubce\\.com", 95},

        /* 游戏 */
        {"Steam", ".*\\.steampowered\\.com", 95},
        {"Steam", ".*\\.steamstatic\\.com", 85},
        {"Riot Games", ".*\\.riotgames\\.com", 95},
        {"Epic Games", ".*\\.epicgames\\.com", 95},

        /* 工具软件 */
        {"GitHub", ".*\\.github\\.com", 95},
        {"GitHub", ".*\\.githubusercontent\\.com", 90},
        {"Stack Overflow", ".*\\.stackoverflow\\.com", 95},
        {"CSDN", ".*\\.csdn\\.net", 95},
    };

    uint32_t num_defaults = sizeof(default_rules) / sizeof(default_rules[0]);
    uint32_t i;

    for (i = 0; i < num_defaults && i < g_app_engine->max_rules; i++) {
        struct app_rule *rule = &g_app_engine->rules[i];

        rule->app_id = i + 1;
        strncpy(rule->app_name, default_rules[i].app_name, MAX_APP_NAME - 1);
        rule->app_name[MAX_APP_NAME - 1] = '\0';
        strncpy(rule->domain_pattern, default_rules[i].domain_pattern, MAX_DOMAIN_LENGTH - 1);
        rule->domain_pattern[MAX_DOMAIN_LENGTH - 1] = '\0';
        rule->confidence = default_rules[i].confidence;
        rule->flags = HS_FLAG_CASELESS | HS_FLAG_MULTILINE;
    }

    g_app_engine->num_rules = i;
    RTE_LOG(INFO, APP, "Created %u default application rules\n", i);

    return 0;
}

/* 编译Hyperscan数据库 */
static int compile_hyperscan_database(void)
{
    const char **patterns;
    unsigned int *flags;
    unsigned int *ids;
    hs_compile_error_t *compile_err;
    uint32_t i;
    int ret;

    if (g_app_engine->num_rules == 0) {
        RTE_LOG(ERR, APP, "No application rules to compile\n");
        return -1;
    }

    /* 分配模式数组 */
    patterns = malloc(g_app_engine->num_rules * sizeof(char *));
    flags = malloc(g_app_engine->num_rules * sizeof(unsigned int));
    ids = malloc(g_app_engine->num_rules * sizeof(unsigned int));

    if (!patterns || !flags || !ids) {
        RTE_LOG(ERR, APP, "Failed to allocate memory for pattern compilation\n");
        free(patterns);
        free(flags);
        free(ids);
        return -1;
    }

    /* 填充模式数组 */
    for (i = 0; i < g_app_engine->num_rules; i++) {
        patterns[i] = g_app_engine->rules[i].domain_pattern;
        flags[i] = g_app_engine->rules[i].flags;
        ids[i] = i;
    }

    /* 编译数据库 */
    ret = hs_compile_multi(patterns, flags, ids, g_app_engine->num_rules,
                          HS_MODE_BLOCK, NULL, &g_app_engine->database, &compile_err);

    if (ret != HS_SUCCESS) {
        RTE_LOG(ERR, APP, "Failed to compile Hyperscan database: %s\n",
                compile_err ? compile_err->message : "Unknown error");
        if (compile_err) {
            hs_free_compile_error(compile_err);
        }
        free(patterns);
        free(flags);
        free(ids);
        return -1;
    }

    /* 分配临时空间 */
    ret = hs_alloc_scratch(g_app_engine->database, &g_app_engine->scratch);
    if (ret != HS_SUCCESS) {
        RTE_LOG(ERR, APP, "Failed to allocate Hyperscan scratch space\n");
        hs_free_database(g_app_engine->database);
        g_app_engine->database = NULL;
        free(patterns);
        free(flags);
        free(ids);
        return -1;
    }

    free(patterns);
    free(flags);
    free(ids);

    RTE_LOG(INFO, APP, "Hyperscan database compiled successfully with %u patterns\n",
            g_app_engine->num_rules);

    return 0;
}

/* 初始化应用识别引擎 */
int app_engine_init(void)
{
    RTE_LOG(INFO, APP, "Initializing application identification engine...\n");

    /* 分配应用引擎内存 */
    g_app_engine = rte_zmalloc("app_engine", sizeof(struct app_engine), RTE_CACHE_LINE_SIZE);
    if (g_app_engine == NULL) {
        RTE_LOG(ERR, APP, "Cannot allocate memory for application engine\n");
        return -1;
    }

    g_app_engine->max_rules = MAX_APP_RULES;

    /* 分配规则数组 */
    g_app_engine->rules = rte_zmalloc("app_rules",
                                    sizeof(struct app_rule) * g_app_engine->max_rules,
                                    RTE_CACHE_LINE_SIZE);
    if (g_app_engine->rules == NULL) {
        RTE_LOG(ERR, APP, "Cannot allocate memory for application rules\n");
        rte_free(g_app_engine);
        g_app_engine = NULL;
        return -1;
    }

    /* 尝试加载配置文件，如果失败则使用默认配置 */
    if (parse_app_rules_file(APP_RULES_FILE) < 0) {
        RTE_LOG(INFO, APP, "Rules file not found, using default application rules\n");
        if (create_default_app_rules() < 0) {
            RTE_LOG(ERR, APP, "Failed to create default application rules\n");
            app_engine_cleanup();
            return -1;
        }
    }

    /* 编译Hyperscan数据库 */
    if (compile_hyperscan_database() < 0) {
        RTE_LOG(ERR, APP, "Failed to compile Hyperscan database\n");
        app_engine_cleanup();
        return -1;
    }

    /* 设置全局配置指针 */
    g_app_config->app_database = g_app_engine->database;
    g_app_config->app_scratch = g_app_engine->scratch;

    RTE_LOG(INFO, APP, "Application engine initialized with %u rules\n\n", g_app_engine->num_rules);

    return 0;
}

/* 从HTTP头中提取Host信息 */
static int extract_http_host(const char *http_data, size_t data_len, char *host, size_t host_size)
{
    const char *host_start = strstr(http_data, HTTP_HOST_HEADER);
    if (host_start == NULL) {
        return -1;
    }

    host_start += strlen(HTTP_HOST_HEADER);
    const char *host_end = strstr(host_start, "\r\n");
    if (host_end == NULL) {
        host_end = strstr(host_start, "\n");
    }
    if (host_end == NULL) {
        host_end = http_data + data_len;
    }

    size_t host_len = host_end - host_start;
    if (host_len >= host_size) {
        host_len = host_size - 1;
    }

    strncpy(host, host_start, host_len);
    host[host_len] = '\0';

    /* 移除端口号 */
    char *port_sep = strchr(host, ':');
    if (port_sep) {
        *port_sep = '\0';
    }

    return 0;
}

/* 判断是否为HTTP数据包 */
static int is_http_packet(const char *payload, size_t payload_len)
{
    if (payload_len < 4) {
        return 0;
    }

    /* 检查HTTP方法 */
    if (strncmp(payload, HTTP_METHOD_GET, 4) == 0 ||
        strncmp(payload, HTTP_METHOD_POST, 5) == 0 ||
        strncmp(payload, "HTTP/", 5) == 0) {
        return 1;
    }

    return 0;
}

/* 应用识别 */
int app_identify(struct rte_mbuf *pkt, struct app_info *app)
{
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_tcp_hdr *tcp_hdr;
    const char *payload;
    uint32_t payload_len;
    char host[MAX_DOMAIN_LENGTH];
    int ret;

    if (unlikely(g_app_engine == NULL || pkt == NULL || app == NULL)) {
        return -1;
    }

    g_app_engine->total_scans++;

    /* 清零结果结构 */
    memset(app, 0, sizeof(struct app_info));

    /* 获取以太网头 */
    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);

    /* 只处理IPv4 TCP包 */
    if (unlikely(rte_be_to_cpu_16(eth_hdr->ether_type) != RTE_ETHER_TYPE_IPV4)) {
        return -1;
    }

    ipv4_hdr = (struct rte_ipv4_hdr *)((char *)eth_hdr + sizeof(struct rte_ether_hdr));
    if (ipv4_hdr->next_proto_id != IPPROTO_TCP) {
        return -1;
    }

    uint8_t ip_hdr_len = (ipv4_hdr->version_ihl & 0x0F) * 4;
    tcp_hdr = (struct rte_tcp_hdr *)((char *)ipv4_hdr + ip_hdr_len);
    uint8_t tcp_hdr_len = (tcp_hdr->data_off >> 4) * 4;

    /* 计算payload位置和长度 */
    uint32_t headers_len = sizeof(struct rte_ether_hdr) + ip_hdr_len + tcp_hdr_len;
    if (rte_pktmbuf_data_len(pkt) <= headers_len) {
        return -1;  /* 没有payload */
    }

    payload = (const char *)eth_hdr + headers_len;
    payload_len = rte_pktmbuf_data_len(pkt) - headers_len;

    /* 检查是否为HTTP数据包 */
    if (!is_http_packet(payload, payload_len)) {
        return -1;
    }

    g_app_engine->http_packets_processed++;

    /* 提取Host头信息 */
    if (extract_http_host(payload, payload_len, host, sizeof(host)) < 0) {
        return -1;
    }

    /* 使用Hyperscan扫描Host */
    ret = hs_scan(g_app_engine->database, host, strlen(host), 0,
                  g_app_engine->scratch, match_handler, app);

    if (ret == HS_SUCCESS) {
        if (app->app_id > 0) {
            /* 成功匹配 */
            g_app_engine->successful_matches++;

            /* 复制实际匹配的域名 */
            strncpy(app->matched_domain, host, MAX_DOMAIN_LENGTH - 1);
            app->matched_domain[MAX_DOMAIN_LENGTH - 1] = '\0';

            RTE_LOG(DEBUG, APP, "Application identified: %s (host: %s)\n",
                    app->app_name, host);

            return 0;
        }
    } else {
        RTE_LOG(ERR, APP, "Hyperscan scan error: %d\n", ret);
    }

    g_app_engine->failed_matches++;
    return -ENOENT;
}

/* 打印应用识别统计信息 */
void print_application_stats(void)
{
    if (g_app_engine == NULL) {
        printf("Application engine not initialized\n");
        return;
    }

    printf("\n=== Application Identification Statistics ===\n");
    printf("Total rules:         %u\n", g_app_engine->num_rules);
    printf("Total scans:         %" PRIu64 "\n", g_app_engine->total_scans);
    printf("HTTP packets:        %" PRIu64 "\n", g_app_engine->http_packets_processed);
    printf("Successful matches:  %" PRIu64 "\n", g_app_engine->successful_matches);
    printf("Failed matches:      %" PRIu64 "\n", g_app_engine->failed_matches);

    if (g_app_engine->total_scans > 0) {
        double hit_rate = (double)g_app_engine->successful_matches * 100.0 / g_app_engine->total_scans;
        printf("Hit rate:            %.2f%%\n", hit_rate);
    }

    if (g_app_engine->http_packets_processed > 0) {
        double http_rate = (double)g_app_engine->http_packets_processed * 100.0 / g_app_engine->total_scans;
        printf("HTTP rate:           %.2f%%\n", http_rate);
    }

    printf("============================================\n\n");
}

/* 清理应用识别引擎 */
void app_engine_cleanup(void)
{
    if (g_app_engine == NULL) {
        return;
    }

    RTE_LOG(INFO, APP, "Cleaning up application identification engine...\n");

    /* 打印最终统计信息 */
    print_application_stats();

    /* 清理Hyperscan资源 */
    if (g_app_engine->scratch) {
        hs_free_scratch(g_app_engine->scratch);
        g_app_engine->scratch = NULL;
    }

    if (g_app_engine->database) {
        hs_free_database(g_app_engine->database);
        g_app_engine->database = NULL;
    }

    /* 清理规则数组 */
    if (g_app_engine->rules) {
        rte_free(g_app_engine->rules);
        g_app_engine->rules = NULL;
    }

    /* 清理引擎 */
    rte_free(g_app_engine);
    g_app_engine = NULL;

    /* 清理全局配置指针 */
    if (g_app_config) {
        g_app_config->app_database = NULL;
        g_app_config->app_scratch = NULL;
    }

    RTE_LOG(INFO, APP, "Application engine cleanup completed\n");
}
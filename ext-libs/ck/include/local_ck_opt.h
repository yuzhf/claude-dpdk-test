#ifndef __LOCAL_CK_OPT_H
#define __LOCAL_CK_OPT_H

#ifdef __cplusplus
extern "C" {
#endif

enum
{
    RSN_CK_TYPE_UINT64 = 1,
    RSN_CK_TYPE_UINT32 = 2,
    RSN_CK_TYPE_UINT16 = 3,
    RSN_CK_TYPE_UINT8 = 4,
    RSN_CK_TYPE_STRING = 5,
    RSN_CK_TYPE_DATETIME = 6,   // 数据类型为unsigned int，表示的是秒数
    RSN_CK_TYPE_UUID = 7,       // 数据类型为t_rsn_ck_uuid
    RSN_CK_TYPE_IPV6 = 8,       // 数据类型为struct in6_addr
    RSN_CK_TYPE_IPV4 = 9,       // 数据类型为unsigned int，网络序
    RSN_CK_TYPE_INT32 = 10,
    RSN_CK_TYPE_MAX,
};

typedef struct {
    unsigned long value1;
    unsigned long value2;
}t_rsn_ck_uuid;

typedef struct
{
    unsigned int  type;     // 对应的字段类型
    unsigned int  cnt;      // 当前该字段待插入的数量
    char *field_name;       // 对应的字段名称
    void *values;           // 当前该字段待插入的数据，需要和cnt的数量一致
}t_rsn_ck_data;

extern void *rsn_ck_create_client(char *host,
                                      unsigned short port,
                                      char *username,
                                      char *passwd,
                                      char *db_name,
                                      char **err);

int rsn_ck_add_one_batch_data(void *client,
                                      char *table_name,
                                      unsigned int field_cnt,
                                      t_rsn_ck_data *data_list,
                                      char **err);


#ifdef __cplusplus
}
#endif

#endif

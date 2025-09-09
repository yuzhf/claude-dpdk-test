#include <clickhouse/client.h>
#include <vector>
#include <chrono>
#include <thread>
#include <future>
#include <memory>
#include <netinet/in.h>
#include <unistd.h>
#include "local_ck_opt.h"

static char g_rsn_ck_err[512];

static int add_one_column_uint64(clickhouse::Block *block, t_rsn_ck_data *one_field_data)
{
    unsigned int cnt = one_field_data->cnt;
    unsigned long *values = (unsigned long *)one_field_data->values;

    auto col_value = std::make_shared<clickhouse::ColumnUInt64>();
    // 预分配内存
    col_value->Reserve(cnt);

    // 填充列数据
    unsigned int i = 0;
    for (i = 0; i < cnt; i++)
    {
        col_value->Append(values[i]);
    }

    // 将列添加到块中
    block->AppendColumn(one_field_data->field_name, col_value);
    return 0;
}

static int add_one_column_uint32(clickhouse::Block *block, t_rsn_ck_data *one_field_data)
{
    unsigned int cnt = one_field_data->cnt;
    unsigned int *values = (unsigned int *)one_field_data->values;

    auto col_value = std::make_shared<clickhouse::ColumnUInt32>();
    // 预分配内存
    col_value->Reserve(cnt);

    // 填充列数据
    unsigned int i = 0;
    for (i = 0; i < cnt; i++)
    {
        col_value->Append(values[i]);
    }

    // 将列添加到块中
    block->AppendColumn(one_field_data->field_name, col_value);
    return 0;
}

static int add_one_column_uint16(clickhouse::Block *block, t_rsn_ck_data *one_field_data)
{
    unsigned int cnt = one_field_data->cnt;
    unsigned short *values = (unsigned short *)one_field_data->values;

    auto col_value = std::make_shared<clickhouse::ColumnUInt16>();
    // 预分配内存
    col_value->Reserve(cnt);

    // 填充列数据
    unsigned int i = 0;
    for (i = 0; i < cnt; i++)
    {
        col_value->Append(values[i]);
    }

    // 将列添加到块中
    block->AppendColumn(one_field_data->field_name, col_value);
    return 0;
}

static int add_one_column_uint8(clickhouse::Block *block, t_rsn_ck_data *one_field_data)
{
    unsigned int cnt = one_field_data->cnt;
    unsigned char *values = (unsigned char *)one_field_data->values;

    auto col_value = std::make_shared<clickhouse::ColumnUInt8>();
    // 预分配内存
    col_value->Reserve(cnt);

    // 填充列数据
    unsigned int i = 0;
    for (i = 0; i < cnt; i++)
    {
        col_value->Append(values[i]);
    }

    // 将列添加到块中
    block->AppendColumn(one_field_data->field_name, col_value);
    return 0;
}

static int add_one_column_int32(clickhouse::Block *block, t_rsn_ck_data *one_field_data)
{
    unsigned int cnt = one_field_data->cnt;
    int *values = (int *)one_field_data->values;

    auto col_value = std::make_shared<clickhouse::ColumnInt32>();
    // 预分配内存
    col_value->Reserve(cnt);

    // 填充列数据
    unsigned int i = 0;
    for (i = 0; i < cnt; i++)
    {
        col_value->Append(values[i]);
    }

    // 将列添加到块中
    block->AppendColumn(one_field_data->field_name, col_value);
    return 0;

}

static int add_one_column_string(clickhouse::Block *block, t_rsn_ck_data *one_field_data)
{
    unsigned int cnt = one_field_data->cnt;
    char **values = (char **)one_field_data->values;

    auto col_value = std::make_shared<clickhouse::ColumnString>();
    // 预分配内存
    col_value->Reserve(cnt);

    // 填充列数据
    unsigned int i = 0;
    for (i = 0; i < cnt; i++)
    {
        col_value->Append(values[i]);
    }

    // 将列添加到块中
    block->AppendColumn(one_field_data->field_name, col_value);
    return 0;
}

// 时间单位为s,输入为uint32
static int add_one_column_datetime(clickhouse::Block *block, t_rsn_ck_data *one_field_data)
{
    unsigned int cnt = one_field_data->cnt;
    unsigned int *values = (unsigned int *)one_field_data->values;

    auto col_value = std::make_shared<clickhouse::ColumnDateTime>();
    // 预分配内存
    col_value->Reserve(cnt);

    // 填充列数据
    unsigned int i = 0;
    for (i = 0; i < cnt; i++)
    {
        col_value->Append(values[i]);
    }

    // 将列添加到块中
    block->AppendColumn(one_field_data->field_name, col_value);
    return 0;
}

static int add_one_column_uuid(clickhouse::Block *block, t_rsn_ck_data *one_field_data)
{
    unsigned int cnt = one_field_data->cnt;
    t_rsn_ck_uuid *values = (t_rsn_ck_uuid *)one_field_data->values;

    auto col_value = std::make_shared<clickhouse::ColumnUUID>();
    // 预分配内存
    col_value->Reserve(cnt);

    // 填充列数据
    unsigned int i = 0;
    for (i = 0; i < cnt; i++)
    {
        col_value->Append(clickhouse::UUID{values[i].value1, values[i].value2});
    }

    // 将列添加到块中
    block->AppendColumn(one_field_data->field_name, col_value);
    return 0;
}

static int add_one_column_ipv6(clickhouse::Block *block, t_rsn_ck_data *one_field_data)
{
    unsigned int cnt = one_field_data->cnt;
    struct in6_addr *values = (struct in6_addr *)one_field_data->values;

    auto col_value = std::make_shared<clickhouse::ColumnIPv6>();
    // 预分配内存
    col_value->Reserve(cnt);

    // 填充列数据
    unsigned int i = 0;
    for (i = 0; i < cnt; i++)
    {
        col_value->Append(&values[i]);
    }

    // 将列添加到块中
    block->AppendColumn(one_field_data->field_name, col_value);

    return 0;
}

// 入参的ipv4地址是网络序
static int add_one_column_ipv4(clickhouse::Block *block, t_rsn_ck_data *one_field_data)
{
    unsigned int cnt = one_field_data->cnt;
    unsigned int *ip = (unsigned int *)one_field_data->values;

    auto col_value = std::make_shared<clickhouse::ColumnIPv4>();
    // 预分配内存
    col_value->Reserve(cnt);

    // 填充列数据
    unsigned int i = 0;
    for (i = 0; i < cnt; i++)
    {
        // append的ipv4地址需要是主机序
        col_value->Append(ntohl(ip[i]));
    }

    // 将列添加到块中
    block->AppendColumn(one_field_data->field_name, col_value);
    return 0;
}

// port为主机序
void *rsn_ck_create_client(char *host, unsigned short port, char *username, char *passwd, char *db_name, char **err)
{
    clickhouse::ClientOptions options;
    try
    {
        options.SetHost(host)
               .SetPort(port)
               .SetDefaultDatabase(db_name);

        if (NULL != username)
        {
            options.SetUser(username);
            options.SetPassword(passwd);

        }

        clickhouse::Client *client = new clickhouse::Client(options);
        return client;
    }
    catch (...)
    {
        snprintf(g_rsn_ck_err, sizeof(g_rsn_ck_err), "rsn_ck_create_client err for host: %s, port: %d, username: %s, passwd: %s, db: %s!\n",
                host, port, username, passwd, db_name);
        *err = g_rsn_ck_err;
    }
    return NULL;
}

int add_one_column(clickhouse::Block *block, t_rsn_ck_data *one_field_data)
{
    int ret = 0;
    switch (one_field_data->type)
    {
        case RSN_CK_TYPE_UINT64:
        {
            ret = add_one_column_uint64(block, one_field_data);
            break;
        }
        case RSN_CK_TYPE_UINT32:
        {
            ret = add_one_column_uint32(block, one_field_data);
            break;
        }
        case RSN_CK_TYPE_UINT16:
        {
            ret = add_one_column_uint16(block, one_field_data);
            break;
        }
        case RSN_CK_TYPE_UINT8:
        {
            ret = add_one_column_uint8(block, one_field_data);
            break;
        }
        case RSN_CK_TYPE_STRING:
        {
            ret = add_one_column_string(block, one_field_data);
            break;
        }
        case RSN_CK_TYPE_DATETIME:
        {
            // 时间单位为s,输入为uint32
            ret = add_one_column_datetime(block, one_field_data);
            break;
        }
        case RSN_CK_TYPE_UUID:
        {
            ret = add_one_column_uuid(block, one_field_data);
            break;
        }
        case RSN_CK_TYPE_IPV6:
        {
            ret = add_one_column_ipv6(block, one_field_data);
            break;
        }
        case RSN_CK_TYPE_IPV4:
        {
            // 入参的ipv4地址是网络序
            ret = add_one_column_ipv4(block, one_field_data);
            break;
        }
        case RSN_CK_TYPE_INT32:
        {
            // 入参的ipv4地址是网络序
            ret = add_one_column_int32(block, one_field_data);
            break;
        }
        default:
        {
            break;
        }
    }
    return ret;
}


int rsn_ck_add_one_batch_data(void *client, char *table_name, unsigned int field_cnt, t_rsn_ck_data *data_list, char **err)
{
    int ret = 0;
    long data_cnt = -1;
    unsigned int i = 0;
    clickhouse::Block block;

    for (i = 0; i < field_cnt; i++)
    {
        if (data_cnt < 0)
        {
            data_cnt = data_list[i].cnt;
        }
        else if (data_cnt != data_list[i].cnt)
        {
            // 不同field的数据的数量不一样多
            return -1;
        }

        try
        {
            ret = add_one_column(&block, &data_list[i]);
            if (ret < 0)
            {
                return -1;
            }
        }
        catch (...)
        {
            snprintf(g_rsn_ck_err, sizeof(g_rsn_ck_err), "rsn_ck_add_one_batch_data err for add column %s!\n", data_list[i].field_name);
            if (NULL != err)
            {
                *err = g_rsn_ck_err;
            }
            return -2;
        }
    }
    clickhouse::Client *ck_client = (clickhouse::Client *)client;
    try
    {
        ck_client->Insert(table_name, block);
    }
    catch (const std::exception& e)
    {
        // 捕获所有 std::exception 类型的异常
        snprintf(g_rsn_ck_err, sizeof(g_rsn_ck_err), "rsn_ck_add_one_batch_data err for insert data: err %s!\n", e.what());
        *err = g_rsn_ck_err;
        if (NULL != err)
        {
            *err = g_rsn_ck_err;
        }
        ret = -3;
    }
    catch (...)
    {
        snprintf(g_rsn_ck_err, sizeof(g_rsn_ck_err), "rsn_ck_add_one_batch_data err for insert data!\n");
        *err = g_rsn_ck_err;
        if (NULL != err)
        {
            *err = g_rsn_ck_err;
        }
        ret = -4;
    }

    try
    {
        // 尝试重连
        if (ret < 0)
        {
            ck_client->ResetConnection();
        }
    }
    catch (...)
    {
        // do nothing
    }
    return ret;
}


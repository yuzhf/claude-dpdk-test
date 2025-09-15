/*
 * 统计信息写入模块头文件
 */

#ifndef _STATS_WRITER_H_
#define _STATS_WRITER_H_

#include <stdio.h>
#include <stdarg.h>

/* 函数声明 */
int stats_writer_init(void);
void stats_writer_cleanup(void);
void write_all_stats_to_file(void);

/* 内联函数 - 写入格式化字符串到统计文件 */
static inline void write_to_stats_file(const char *format, ...)
{
    extern FILE *stats_file;
    if (stats_file) {
        va_list args;
        va_start(args, format);
        vfprintf(stats_file, format, args);
        va_end(args);
        fflush(stats_file);
    }
}

#endif /* _STATS_WRITER_H_ */
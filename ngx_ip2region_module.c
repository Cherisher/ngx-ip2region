#include <ngx_config.h>
#include <ngx_core.h>

#include "ip2region.h"
#include "ngx_ip2region.h"


static void *ngx_ip2region_create_conf(ngx_cycle_t *cycle);
static char *ngx_ip2region_init_conf(ngx_cycle_t *cycle, void *conf);

static ngx_int_t ngx_ip2region_init_process(ngx_cycle_t *cycle);
static void ngx_ip2region_exit_process(ngx_cycle_t *cycle);

static ip2region_entry g_ip2region_entry;

static ngx_command_t ngx_ip2region_commands[] = {

    {
        ngx_string("ip2region_db_file"),
        NGX_MAIN_CONF | NGX_DIRECT_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        0,
        offsetof(ngx_ip2region_conf_t, db_file),
        NULL
    },

    ngx_null_command
};


static ngx_core_module_t  ngx_ip2region_module_ctx = {
    ngx_string("ip2region"),
    ngx_ip2region_create_conf,
    ngx_ip2region_init_conf,
};


ngx_module_t  ngx_ip2region_module = {
    NGX_MODULE_V1,
    &ngx_ip2region_module_ctx,             /* module context */
    ngx_ip2region_commands,                /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_ip2region_init_process,            /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_ip2region_exit_process,            /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *
ngx_ip2region_create_conf(ngx_cycle_t *cycle)
{
    ngx_ip2region_conf_t  *ip2region_conf;
    ip2region_conf = ngx_pcalloc(cycle->pool, sizeof(ngx_ip2region_conf_t));

    if(ip2region_conf == NULL) {
        return NULL;
    }

    return ip2region_conf;
}

static char *
ngx_ip2region_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_ip2region_conf_t  *ip2region_conf = (ngx_ip2region_conf_t *)conf;

    if(ip2region_conf->db_file.len == 0) {
        ngx_str_set(&ip2region_conf->db_file, "conf/ip2region.db");
    }

    if(ngx_conf_full_name(cycle, &ip2region_conf->db_file, 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    ngx_log_debug1(NGX_LOG_INFO, ngx_cycle->log, 0, "%V", &ip2region_conf->db_file);
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_ip2region_init_process(ngx_cycle_t *cycle)
{
    ngx_ip2region_conf_t *conf = (ngx_ip2region_conf_t *)ngx_get_conf(ngx_cycle->conf_ctx, ngx_ip2region_module);

    if(!ip2region_create(&g_ip2region_entry, (char *)conf->db_file.data)) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ip2region create failed: %V", &conf->db_file);
        return NGX_ERROR;
    }

    ngx_log_debug0(NGX_LOG_INFO, ngx_cycle->log, 0, "ip2region create succcess");
    search_func_ptr = ip2region_binary_search;
#if 0
    ngx_str_t addr_text, isp = ngx_null_string, city = ngx_null_string;
    ngx_str_set(&addr_text, "183.230.102.103");

    if(NGX_OK == ngx_ip2region_search(&addr_text, &isp, &city)) {
        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0, "ip2region: %V %V", &isp, &city);
    }

#endif
    return NGX_OK;
}

static void
ngx_ip2region_exit_process(ngx_cycle_t *cycle)
{
    ip2region_destroy(&g_ip2region_entry);
    ngx_log_debug0(NGX_LOG_INFO, ngx_cycle->log, 0, "ip2region destroy");
}

static ngx_inline u_char *
ngx_strrchr(u_char *first, u_char *p, u_char c)
{
    while(p >= first) {
        if(*p == c) {
            return p;
        }

        p--;
    }

    return NULL;
}

static ngx_inline uint32_t
ngx_inet_aton(u_char *data, ngx_uint_t len)
{
    long long  result = 0;
    long long  temp = 0;
    u_char      *last = data + len;
    int        point = 0;

    while(data <= last) {
        if(*data == '.' || data == last) {
            if(temp > 255) {
                return NGX_ERROR;
            }

            result = (result << 8) + temp;
            temp = 0;
            ++point;

            if(point == 4) {
                break;
            }

        } else if(*data <= '9' && *data >= '0') {
            temp = temp * 10 + (*data - '0');

        } else {
            return NGX_ERROR;
        }

        ++data;
    }

    if(point != 4) {
        return NGX_ERROR;
    }

    return result;
}

ngx_int_t
ngx_ip2region_search(ngx_str_t *addr_text, ngx_str_t *isp, ngx_str_t *city)
{
    if(g_ip2region_entry.dbHandler == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "search error ip %V, ip2region doesn't create", addr_text);
        return NGX_ERROR;
    }

    uint32_t addr_binary = ngx_inet_aton(addr_text->data, addr_text->len);

    if(addr_binary == (uint32_t)NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "search error ip %V: bad ip address", addr_text);
        return NGX_ERROR;
    }

    if(!search_func_ptr) {
        ngx_log_debug(NGX_LOG_DEBUG, ngx_cycle->log, 0, "set method ip2region_memory_search");
        search_func_ptr = ip2region_memory_search;
    }

    datablock_entry datablock;
    ngx_memzero(&datablock, sizeof(datablock));
    uint_t rc = search_func_ptr(&g_ip2region_entry, (uint_t)addr_binary, &datablock);

    if(!rc) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "search failed");
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "%s", datablock.region);
#if 0
    //城市Id 国家|区域|省份|城市|ISP
    u_char *end = (u_char *)(datablock.region + ngx_strlen(datablock.region));
    u_char *pos = ngx_strrchr((u_char *)datablock.region, end, '|');

    if(!pos) {
        ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0, "search isp failed");
        return NGX_ERROR;
    }

    u_char isp_buffer[64] = {0};
    ngx_snprintf(isp_buffer, sizeof(isp_buffer), "%*s%Z", end - pos, pos + 1);
    end = pos - 1;
    u_char *pos_city = ngx_strrchr((u_char *)datablock.region, end, '|');

    if(!pos_city) {
        ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0, "search city failed");
        return NGX_ERROR;
    }

    u_char city_buffer[64] = {0};
    ngx_snprintf(city_buffer, sizeof(city_buffer), "%*s%Z", end - pos_city, pos_city + 1);

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "[%s(%V)] [%s]", isp_buffer, isp, city_buffer);
#endif
    return NGX_OK;
}

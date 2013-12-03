typedef struct {
    ngx_flag_t                     enable;
    ngx_flag_t                     trylock;
    ngx_array_t                    dy_upstreams;/* ngx_http_dyups_srv_conf_t */
    ngx_str_t                      conf_path;
    ngx_str_t                      shm_name;
    ngx_uint_t                     shm_size;
    ngx_msec_t                     read_msg_timeout;
    ngx_resolver_t                *resolver;
    ngx_msec_t                     resolver_timeout;
} ngx_http_dyups_main_conf_t;


typedef struct {
    ngx_uint_t                     idx;
    ngx_uint_t                    *count;
    ngx_uint_t                     deleted;
    ngx_flag_t                     dynamic;
    ngx_pool_t                    *pool;
    ngx_http_conf_ctx_t           *ctx;
    ngx_http_upstream_srv_conf_t  *upstream;
} ngx_http_dyups_srv_conf_t;

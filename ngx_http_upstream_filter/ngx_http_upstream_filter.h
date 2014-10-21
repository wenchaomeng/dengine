#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_upstream.h>
#include <ngx_regex.h>


#define DEFAULT_AUTH_FILTER_EXCEPTION_PASS 1
#define DEFAULT_AUTH_FILTER_TIMEOUT 10000
#define DEFAULT_AUTH_FILTER_OPEN 0
#define DEFAULT_MAX_URL_LENGTH 1024
#define DEFAULT_MAX_REQUEST_DATA_LENGTH 10240
#define DEFAULT_MAX_RECEIVE_DATA_LENGTH 10240
#define DEFAULT_BODY_FILTER_CAPTUR_SIZE 60
#define UPSTREAM_FILTER_UNPASS_HEADER_KEY "X-DENGINE-UPSTREAM-FILTER-UNPASS"

typedef struct {

}ngx_http_upstream_filter_main_conf_t;

typedef struct {

	ngx_flag_t  auth_filter_open;

	ngx_flag_t  auth_filter_exception_pass;

	ngx_array_t	*auth_filter_pass_pattern;

	ngx_array_t  *upstream_filter_config; /*ngx_http_upstream_filter_config*/

	//以下配置由上面的配置生成
	ngx_array_t	*auth_filter_pass_pattern_regex; /*ngx_regex_compile_t*/


}ngx_http_upstream_filter_srv_conf_t;

typedef enum {
	SSO,
	OAUTH
}ngx_http_upstream_filter_config_type;


typedef struct {

	ngx_http_upstream_filter_config_type type;
	ngx_int_t 	on;
	ngx_msec_t  timeout;
	ngx_str_t   key; //
	ngx_str_t   url_pattern; //对于匹配的url采用此规则
	ngx_str_t	server_url;

	ngx_regex_compile_t   *body_filter_regex; //提取消息体中关心的内容
	ngx_int_t 	body_filter_regex_group_count; //提取消息体中关心的内容

	//以下配置由上面的配置生成
	ngx_regex_compile_t   *url_pattern_regex; //对于匹配的url采用此规则
	ngx_url_t  url;

#if (NGX_HTTP_SSL)
	ngx_ssl_t  *ssl;
#endif

}ngx_http_upstream_filter_config;

typedef struct {
	ngx_http_upstream_filter_srv_conf_t *usfscf;
	ngx_http_upstream_filter_config *usfc;
	ngx_http_request_t  *r;
	ngx_str_t		value;
	ngx_buf_t 	*write_buf;
	ngx_buf_t 	*read_buf;
	ngx_flag_t  closed;
}ngx_http_upstream_filter_connection_data;




ngx_int_t   ngx_http_upstream_filter_postconfiguration(ngx_conf_t *cf);
void * ngx_http_upstream_filter_create_main_conf(ngx_conf_t *cf);
void * ngx_http_upstream_filter_create_srv_conf(ngx_conf_t *cf);
char * ngx_conf_set_auth_filter_config(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_auth_filter_pass_pattern(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char * ngx_conf_set_auth_filter_config_off(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_auth_filter_config_timeout(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_flag_slot_override(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
void ngx_http_upstream_filter_upstream_init_mock(ngx_http_request_t *r);
#if (NGX_HTTP_SSL)
	ngx_int_t ngx_http_upstream_filter_init_ssl(ngx_http_upstream_filter_config  *usfc, ngx_conf_t *cf);
	void ngx_http_upstream_filter_begin_ssl(ngx_http_upstream_filter_config *usfc, ngx_http_request_t *r, ngx_connection_t *c);
#endif

static void ngx_http_upstream_filter_merge_config(ngx_http_upstream_filter_srv_conf_t *parent,
		ngx_http_upstream_filter_srv_conf_t *child, ngx_conf_t *cf);
void ngx_http_upstream_filter_not_pass(ngx_http_request_t *r, ngx_connection_t *c, ngx_http_upstream_filter_srv_conf_t *usfscf, ngx_str_t body, char *error_message);
void ngx_http_upstream_filter_exception(ngx_http_request_t *r, ngx_connection_t *c, ngx_http_upstream_filter_srv_conf_t *usfscf, char *message);
void ngx_http_upstream_filter_send_request(ngx_http_upstream_filter_connection_data *data, ngx_connection_t *c);



ngx_http_upstream_srv_conf_t *
ngx_http_upstream_rbtree_lookup(ngx_http_upstream_main_conf_t *umcf,
    ngx_str_t *host);

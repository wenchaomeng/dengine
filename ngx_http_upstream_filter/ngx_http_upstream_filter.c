#include "ngx_http_upstream_filter.h"

static void ngx_http_upstream_filter_cleanup(void *cln_data);

extern ngx_http_client_body_handler_pt ngx_http_upstream_init_mock;
static ngx_regex_compile_t  content_length_regex;
static ngx_regex_compile_t  content_split_regex;
static ngx_str_t content_length_pattern = ngx_string("(?i)Content-Length:.*?(\\d+)");
static ngx_str_t content_split_pattern = ngx_string("\r\n\r\n((?s).*)");


ngx_http_client_body_handler_pt   ngx_http_upstream_init_next;

static ngx_command_t ngx_http_upstream_filter_commands[] = {

	{
        ngx_string("auth_filter_open"), // The command name
        NGX_HTTP_MAIN_CONF | NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot_override, // The command handler
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_upstream_filter_srv_conf_t, auth_filter_open),
        NULL
    },
    {
        ngx_string("auth_filter_exception_pass"), // The command name
        NGX_HTTP_MAIN_CONF | NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot_override, // The command handler
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_upstream_filter_srv_conf_t, auth_filter_exception_pass),
        NULL
    },
	{
		ngx_string("auth_filter_pass_pattern"), // The command name
	    NGX_HTTP_MAIN_CONF | NGX_HTTP_UPS_CONF | NGX_CONF_1MORE,
	    ngx_conf_set_auth_filter_pass_pattern, // The command handler
	    NGX_HTTP_SRV_CONF_OFFSET,
	    0,
	    NULL
	 },
	{
		ngx_string("auth_filter_config"), // The command name
	    NGX_HTTP_MAIN_CONF | NGX_HTTP_UPS_CONF | NGX_CONF_TAKE4,
	    ngx_conf_set_auth_filter_config, // The command handler
	    NGX_HTTP_SRV_CONF_OFFSET,
	    0,
	    NULL
	 },
	{
		ngx_string("auth_filter_config_off"), // The command name
		NGX_HTTP_MAIN_CONF | NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_auth_filter_config_off, // The command handler
		NGX_HTTP_SRV_CONF_OFFSET,
		0,
		NULL
	},
	{
		ngx_string("auth_filter_config_timeout"), // The command name
		NGX_HTTP_MAIN_CONF | NGX_HTTP_UPS_CONF | NGX_CONF_TAKE2,
		ngx_conf_set_auth_filter_config_timeout, // The command handler
		NGX_HTTP_SRV_CONF_OFFSET,
		0,
		NULL
	}

};

static ngx_http_module_t ngx_http_upstream_filter_ctx = {
    NULL,
    ngx_http_upstream_filter_postconfiguration,
    ngx_http_upstream_filter_create_main_conf,
    NULL,
    ngx_http_upstream_filter_create_srv_conf,
    NULL,
    NULL,
    NULL,
};

ngx_module_t ngx_http_upstream_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_filter_ctx,
    ngx_http_upstream_filter_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};


void *
ngx_http_upstream_filter_create_main_conf(ngx_conf_t *cf){

	ngx_http_upstream_filter_main_conf_t *ufmcf;

	ufmcf = ngx_palloc(cf->pool, sizeof(ngx_http_upstream_filter_main_conf_t));
	if(ufmcf == NULL){
		return NULL;
	}

	return ufmcf;
}

void * ngx_http_upstream_filter_create_srv_conf(ngx_conf_t *cf){

	ngx_http_upstream_filter_srv_conf_t *ufscf;
	ngx_http_upstream_filter_srv_conf_t *parent;
	ngx_uint_t i;

	ufscf = ngx_palloc(cf->pool, sizeof(ngx_http_upstream_filter_srv_conf_t));
	if(ufscf == NULL){
		return NULL;
	}
	ngx_memset(ufscf, 0 , sizeof(ngx_http_upstream_filter_srv_conf_t));
	ufscf->auth_filter_exception_pass = NGX_CONF_UNSET;
	ufscf->auth_filter_open = NGX_CONF_UNSET;
	ufscf->auth_filter_pass_pattern = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
	ufscf->auth_filter_pass_pattern_regex = ngx_array_create(cf->pool, 4, sizeof(ngx_regex_compile_t));
	ufscf->upstream_filter_config = ngx_array_create(cf->pool, 4, sizeof(ngx_http_upstream_filter_config));

	if(cf->module_type == NGX_HTTP_MODULE){

		parent = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_filter_module);

		ngx_conf_merge_value(ufscf->auth_filter_exception_pass, parent->auth_filter_exception_pass, DEFAULT_AUTH_FILTER_EXCEPTION_PASS);
		ngx_conf_merge_value(ufscf->auth_filter_open, parent->auth_filter_open, DEFAULT_AUTH_FILTER_OPEN);

		if(parent->auth_filter_pass_pattern->nelts != parent->auth_filter_pass_pattern_regex->nelts){
			ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "pass_pattern != pass_pattern_regex");
			return NULL;
		}
		ngx_str_t *parent_pattern = (ngx_str_t *)parent->auth_filter_pass_pattern->elts;
		ngx_regex_compile_t *parent_regex_pattern = (ngx_regex_compile_t *)parent->auth_filter_pass_pattern_regex->elts;

		for(i=0; i < parent->auth_filter_pass_pattern->nelts; i++){
			ngx_str_t *data = ngx_array_push(ufscf->auth_filter_pass_pattern);
			*data = parent_pattern[i];

			ngx_regex_compile_t *regex = ngx_array_push(ufscf->auth_filter_pass_pattern_regex);
			*regex = parent_regex_pattern[i];
		}

		ngx_http_upstream_filter_merge_config(parent, ufscf, cf);

	}

	return ufscf;
}

static void ngx_http_upstream_filter_merge_config(ngx_http_upstream_filter_srv_conf_t *parent,
		ngx_http_upstream_filter_srv_conf_t *child, ngx_conf_t *cf){

	ngx_uint_t i, j;
	ngx_http_upstream_filter_config *usfc_parent, *usfc_child, *usfc_add;

	usfc_parent = parent->upstream_filter_config->elts;
	usfc_child = child->upstream_filter_config->elts;

	for(i=0;i<parent->upstream_filter_config->nelts;i++){
		if(usfc_parent[i].on){
			for(j=0;j<child->upstream_filter_config->nelts;j++){
				if(usfc_child[j].type == usfc_parent[i].type){
					break;
				}
			}
			if(j == child->upstream_filter_config->nelts){//not found, add it to child
				usfc_add = ngx_array_push(child->upstream_filter_config);
				*usfc_add = usfc_parent[i];
			}
		}
	}
}
ngx_int_t ngx_http_upstream_filter_ngx_regex_compile(ngx_regex_compile_t *regex, ngx_str_t pattern, ngx_pool_t *pool){
	u_char error[NGX_MAX_CONF_ERRSTR];
	ngx_int_t rc;

	ngx_memset(regex, 0, sizeof(ngx_regex_compile_t));
	regex->pattern = pattern;
	regex->pool = pool;
	regex->err.data = error;
	regex->err.len = NGX_MAX_CONF_ERRSTR;

	rc = ngx_regex_compile(regex);
	if(rc != NGX_OK){
		ngx_log_error(NGX_LOG_ERR, regex->pool->log, 0, "error compile %V, message: %V", &regex->pattern, &regex->err);
	}
	return rc;
}

ngx_int_t   ngx_http_upstream_filter_postconfiguration(ngx_conf_t *cf){

    ngx_http_upstream_main_conf_t  *umcf;
	ngx_http_upstream_filter_srv_conf_t *child;
    ngx_http_upstream_srv_conf_t   **uscfp;
    ngx_uint_t i, j;
    ngx_http_upstream_filter_config  *usfc_child;

    //merge upstream conf
    umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);

    uscfp = umcf->upstreams.elts;
    for( i=0 ; i < umcf->upstreams.nelts ; i++ ){

    	if(uscfp[i]->srv_conf == NULL){
    		//like proxy_pass http://www.baidu.com
    		continue;
    	}
    	child = ngx_http_conf_upstream_srv_conf(uscfp[i], ngx_http_upstream_filter_module);

		ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
	                   "upstream: %V, auth_filter_exception_pass:%i, auth_filter_open:%i, auth_filter_pass_pattern count:%ui, upstream_filter_config count:%ui",
	                   &uscfp[i]->host, child->auth_filter_exception_pass, child->auth_filter_open
	                   , child->auth_filter_pass_pattern->nelts, child->upstream_filter_config->nelts
	                    );

		usfc_child = child->upstream_filter_config->elts;
		for(j=0;j<child->upstream_filter_config->nelts;j++){
			ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "upstream: %V, type: %i, on:%i, pattern: %V, key:%V, server_url:%V, timeout:%i",
					&uscfp[i]->host, usfc_child[j].type, usfc_child[j].on, &usfc_child[j].url_pattern, &usfc_child[j].key, &usfc_child[j].server_url, usfc_child[j].timeout);
		}
    }


    if(ngx_http_upstream_filter_ngx_regex_compile(&content_length_regex, content_length_pattern, cf->pool) != NGX_OK){
    	return NGX_ERROR;
    }

    if(ngx_http_upstream_filter_ngx_regex_compile(&content_split_regex, content_split_pattern, cf->pool) != NGX_OK){
    	return NGX_ERROR;
    }

    ngx_http_upstream_init_next = ngx_http_upstream_init_mock;
    ngx_http_upstream_init_mock = ngx_http_upstream_filter_upstream_init_mock;
    return NGX_OK;
}

char * ngx_conf_get_http_upstream_filter_config_type(ngx_str_t type_desc, ngx_http_upstream_filter_config_type *type){

	if(ngx_strcasecmp(type_desc.data, (u_char*)"sso") == 0){
		*type = SSO;
	}else if(ngx_strcasecmp(type_desc.data, (u_char*)"oauth") == 0){
		*type = OAUTH;
	}else{//unknown
		return "unrecognised type, should in (sso, oauth)";
	}

	return NGX_CONF_OK;
}


char *
ngx_conf_set_auth_filter_pass_pattern(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){

	ngx_http_upstream_filter_srv_conf_t *usfscf = conf;
	ngx_uint_t i;
	ngx_str_t  *pattern, *elts;
	ngx_regex_compile_t  *pattern_regex;

	elts = cf->args->elts;
	for(i=1; i<cf->args->nelts ; i++){

		pattern = (ngx_str_t*)ngx_array_push(usfscf->auth_filter_pass_pattern);
		if(pattern == NULL){
			return NGX_CONF_ERROR;
		}
		*pattern = elts[i];

		pattern_regex = (ngx_regex_compile_t*)ngx_array_push(usfscf->auth_filter_pass_pattern_regex);
		if(pattern_regex == NULL){
			return NGX_CONF_ERROR;
		}
		if(ngx_http_upstream_filter_ngx_regex_compile(pattern_regex, elts[i], cf->pool) != NGX_OK){
			return "compile regex error";
		}
	}

	return NGX_CONF_OK;
}

char *
ngx_conf_set_auth_filter_config(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){

	ngx_http_upstream_filter_srv_conf_t *usfscf = conf;
	ngx_str_t *args;
	ngx_http_upstream_filter_config_type type;
	ngx_http_upstream_filter_config *usfc;
	ngx_uint_t i;
	char *result;

	args = cf->args->elts;

	result = ngx_conf_get_http_upstream_filter_config_type(args[1], &type);
	if(result != NGX_CONF_OK){
		return result;
	}

	usfc =  usfscf->upstream_filter_config->elts;
	for(i = 0; i < usfscf->upstream_filter_config->nelts; i++){
		if(usfc[i].type == type){
			ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "override auth filter config %i", i);
			break;
		}

	}
	if(i == usfscf->upstream_filter_config->nelts){
		usfc = ngx_array_push(usfscf->upstream_filter_config);
		ngx_memset(usfc, 0, sizeof(ngx_http_upstream_filter_config));
	}else{
		usfc = &usfc[i];
	}
	usfc->on = 1;
	usfc->type = type;
	usfc->url_pattern = args[2];
	usfc->key = args[3];
	usfc->server_url = args[4];
	usfc->timeout = DEFAULT_AUTH_FILTER_TIMEOUT;

	char *format = ngx_strstr((const char *)(usfc->server_url.data), "%s");
	if(format == NULL){
		return "url should hava %s";
	}
	*(format+1) = 'V';

	//config processing
	usfc->url_pattern_regex = ngx_palloc(cf->pool, sizeof(ngx_regex_compile_t));
	if(usfc->url_pattern_regex == NULL){
		return NGX_CONF_ERROR;
	}
	if(ngx_http_upstream_filter_ngx_regex_compile(usfc->url_pattern_regex, usfc->url_pattern, cf->pool) != NGX_OK){
		return "comile regex error";
	}


	//body filter
	usfc->body_filter_regex = ngx_palloc(cf->pool, sizeof(ngx_regex_compile_t));
	if( usfc->body_filter_regex == NULL ){
		return NGX_CONF_ERROR;
	}
	ngx_str_t body_filter_pattern = ngx_string("\\{.*?\"code\":(-?\\d+).*?\\}");
	usfc->body_filter_regex_group_count = 2;
	if(ngx_http_upstream_filter_ngx_regex_compile(usfc->body_filter_regex, body_filter_pattern, cf->pool) != NGX_OK){
		return "comile regex error";
	}

	ngx_int_t add, port;
	//url parse
	if(ngx_strncasecmp(usfc->server_url.data, (u_char*)"http://", 7) == 0){
		add = 7;
		port = 80;
	}else if(ngx_strncasecmp(usfc->server_url.data, (u_char*)"https://", 8) == 0){
		add = 8;
		port = 443;
	}else{
		ngx_log_error(NGX_LOG_ERR, cf->log, 0, "url unrecognised:%V", &usfc->url);
		return NGX_CONF_ERROR;
	}

	usfc->url.url.data = usfc->server_url.data + add;
	usfc->url.url.len = usfc->server_url.len - add;
	usfc->url.default_port = port;
	usfc->url.uri_part = 1;
	if(ngx_parse_url(cf->pool, &usfc->url) != NGX_OK){
		if(usfc->url.err){
			ngx_log_error(NGX_LOG_ERR, cf->log, 0, "%s, parse url:%V", usfc->url.err, &usfc->url);
		}else{
			ngx_log_error(NGX_LOG_ERR, cf->log, 0, "parse url error:%V", &usfc->url);
		}
		return NGX_CONF_ERROR;
	}

	//ssl
	if(ngx_strncasecmp(usfc->server_url.data, (u_char*)"https", 5) == 0){

		#if (NGX_HTTP_SSL)
			if(ngx_http_upstream_filter_init_ssl(usfc, cf) != NGX_OK){
				ngx_log_error(NGX_LOG_ERR, cf->log, 0, "init https failed, parse url:%V", &usfc->url);
				return NGX_CONF_ERROR;
			}
		#else
			ngx_log_error(NGX_LOG_ERR, cf->log, 0, "https unsupported!, parse url:%V", &usfc->url);
			return NGX_CONF_ERROR;
		#endif
	}

	return NGX_CONF_OK;
}

char *
ngx_conf_set_auth_filter_config_off(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){

	ngx_http_upstream_filter_srv_conf_t *usfscf = conf;
	ngx_http_upstream_filter_config_type type;
	ngx_http_upstream_filter_config *usfc;
	ngx_str_t 	*args;
	ngx_uint_t i, found;
	char *result;

	args = cf->args->elts;
	result = ngx_conf_get_http_upstream_filter_config_type(args[1], &type);
	if(result != NGX_CONF_OK){
		return result;
	}

	usfc = usfscf->upstream_filter_config->elts;
	found = 0;
	for( i=0; i<usfscf->upstream_filter_config->nelts ; i++ ){
		if(usfc[i].type == type){
			usfc[i].on = 0;
			found = 1;
			break;
		}
	}

	if(!found){
		return "unfound auth_filter_config_off type ";
	}

	return NGX_CONF_OK;
}

char *
ngx_conf_set_flag_slot_override(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_str_t        *value;
    ngx_flag_t       *fp;
    ngx_conf_post_t  *post;

    fp = (ngx_flag_t *) (p + cmd->offset);

//如果设置，覆盖原来的数据
//    if (*fp != NGX_CONF_UNSET) {
//        return "is duplicate";
//    }

    value = cf->args->elts;

    if (ngx_strcasecmp(value[1].data, (u_char *) "on") == 0) {
        *fp = 1;

    } else if (ngx_strcasecmp(value[1].data, (u_char *) "off") == 0) {
        *fp = 0;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                     "invalid value \"%s\" in \"%s\" directive, "
                     "it must be \"on\" or \"off\"",
                     value[1].data, cmd->name.data);
        return NGX_CONF_ERROR;
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, fp);
    }

    return NGX_CONF_OK;
}

char *
ngx_conf_set_auth_filter_config_timeout(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){

	ngx_http_upstream_filter_srv_conf_t *usfscf = conf;
	ngx_http_upstream_filter_config_type type;
	ngx_http_upstream_filter_config *usfc;
	ngx_str_t 	*args;
	ngx_uint_t i, found;
	ngx_int_t 	timeout;
	char *result;

	args = cf->args->elts;
	result = ngx_conf_get_http_upstream_filter_config_type(args[1], &type);
	if(result != NGX_CONF_OK){
		return result;
	}

	timeout = ngx_atoi(args[2].data, args[2].len);
	if(timeout < 0){
		return "invalid number";
	}

	usfc = usfscf->upstream_filter_config->elts;
	found = 0;
	for( i=0; i<usfscf->upstream_filter_config->nelts ; i++ ){
		if(usfc[i].type == type){
			usfc[i].timeout = (ngx_msec_t)timeout;
			found = 1;
			break;
		}
	}

	if(!found){
		return "unfound auth_filter_config_timeout type ";
	}

	return NGX_CONF_OK;
}

ngx_int_t ngx_http_upstream_filter_get(ngx_peer_connection_t *pc,
    void *data){

	return NGX_OK;
}

ngx_int_t ngx_http_respose_finished(ngx_buf_t *buf, ngx_pool_t *pool){

	ngx_str_t response;
	int  captures[DEFAULT_BODY_FILTER_CAPTUR_SIZE];
	response.data = buf->pos;
	response.len = buf->last - buf->pos;
	ngx_int_t rc;

	rc = ngx_regex_exec(content_length_regex.regex, &response, captures, DEFAULT_BODY_FILTER_CAPTUR_SIZE);
	if(rc < 0){
		if(ngx_regex_exec(content_split_regex.regex, &response, captures, DEFAULT_BODY_FILTER_CAPTUR_SIZE) >= 0){
			return 1;
		}
		return 0;
	}
	if(rc != 2){
		return 0;
	}

	ngx_str_t content_length_str;
	ngx_int_t content_length, real_length;
	content_length_str.data = buf->pos + captures[2];
	content_length_str.len = captures[3] - captures[2];

	 content_length = ngx_atoi(content_length_str.data, content_length_str.len);
	if(content_length < 0){
		ngx_log_error(NGX_LOG_ERR, pool->log, 0, "[ngx_http_respose_finished][content_length error]%V", content_length_str);
		return 0;
	}

	ngx_log_error(NGX_LOG_INFO, pool->log, 0, "[ngx_http_respose_finished][content_length:%i]", content_length);

	rc = ngx_regex_exec(content_split_regex.regex, &response, captures, DEFAULT_BODY_FILTER_CAPTUR_SIZE);
	if(rc <= 0){
		return 0;
	}
	real_length = captures[3] - captures[2];
	ngx_log_error(NGX_LOG_INFO, pool->log, 0, "[ngx_http_respose_finished][real length:%i]", real_length);
	if(real_length >= content_length){
		return 1;
	}

	return 0;
}

void
ngx_http_upstream_filter_read_handler(ngx_event_t *ev)
{
	ngx_connection_t *c = ev->data;
	ngx_http_upstream_filter_connection_data *data = c->data;
	ngx_http_upstream_filter_config *usfc = data->usfc;
	ngx_http_upstream_filter_srv_conf_t *usfscf = data->usfscf;
	ngx_http_request_t *r = data->r;
	char *error_message;

	ngx_log_error(NGX_LOG_INFO, ev->log, 0, "[ngx_http_upstream_filter_read_handler]");

	if(ev->timedout){
		error_message = "read time out";
		goto exception;
	}

	if (ev->timer_set) {
        ngx_del_timer(ev);
    }

	ngx_buf_t *buf = data->read_buf;
	if(buf == NULL){
		buf = ngx_create_temp_buf(r->pool, DEFAULT_MAX_RECEIVE_DATA_LENGTH);
		data->read_buf = buf;
	}

	ssize_t  size, n;

	while(1){
		n = buf->end - buf->last;
		if(n == 0){
			size = buf->end - buf->start;
			buf = ngx_create_temp_buf(r->pool, 2*size);
			ngx_memcpy(buf, data->read_buf, size);
			buf->last = buf->pos + size;
			data->read_buf = buf;
		}

		size = c->recv(c, buf->last, buf->end - buf->last);

		if(size > 0){

			ngx_str_t print;
			print.data = buf->last;
			print.len = size;
			ngx_log_error(NGX_LOG_INFO, ev->log, 0, "[ngx_http_upstream_filter_read_handler][read]%V",&print);

			buf->last += size;
			continue;
		}
		if(size == 0){
			//remote closed
			ngx_log_error(NGX_LOG_INFO, ev->log, 0, "[ngx_http_upstream_filter_read_handler][remote closed]");
			data->closed = 1;
			break;
		}
		if(size == NGX_AGAIN){
			ngx_log_error(NGX_LOG_INFO, ev->log, 0, "[ngx_http_upstream_filter_read_handler][again]");
			break;
		}
		error_message = "read error";
		goto exception;
	}

	int capture[DEFAULT_BODY_FILTER_CAPTUR_SIZE];
	ngx_str_t received;
	ngx_int_t regex_rc, finished = 0;
	ngx_uint_t i;

	received.data = buf->pos;
	received.len = buf->last - buf->pos;

	regex_rc = ngx_regex_exec(usfc->body_filter_regex->regex, &received, capture, DEFAULT_BODY_FILTER_CAPTUR_SIZE);
	finished = ngx_http_respose_finished(buf, r->pool);

	if(regex_rc <= 0){
		if(data->closed){
			error_message = "socket closed, but we can not find result";
			goto exception;
		}
		if(finished){
			error_message = "http response finished, but we can not find result";
			goto exception;
		}
        ngx_add_timer(ev, usfc->timeout);
		return;
	}

	if(regex_rc > 0){
		//found
		if(regex_rc != usfc->body_filter_regex_group_count){
			error_message = "match result not correct";
			goto exception;
		}

		ngx_str_t *result = ngx_palloc(r->pool, regex_rc);

		for(i=0; i<(ngx_uint_t)regex_rc ;i++){
			result[i].data = buf->pos + capture[2*i];
			result[i].len = capture[2*i + 1] - capture[2*i];
		}

		if(*result[regex_rc - 1].data == (u_char)'0' && result[regex_rc - 1].len == 1){
			ngx_http_upstream_filter_cleanup(c);
			ngx_http_upstream_init_next(r);
		}else{
			ngx_http_upstream_filter_not_pass(r, c, usfscf, result[0], "auth server return code not 0");
		}
	}

	return;

exception:
	ngx_http_upstream_filter_exception(r, c, usfscf, error_message);
}


void
ngx_http_upstream_filter_write_handler(ngx_event_t *ev)
{
	ngx_connection_t *c = ev->data;
	ngx_http_upstream_filter_connection_data *data = c->data;
	ngx_http_upstream_filter_config *usfc = data->usfc;
	ngx_http_upstream_filter_srv_conf_t *usfscf = data->usfscf;
	ngx_http_request_t *r = data->r;
	char *error_message;

	ngx_log_error(NGX_LOG_INFO, ev->log, 0, "[ngx_http_upstream_filter_write_handler]");

	if(ev->timedout){
		error_message = "connect time out";
		goto exception;
	}

	if (ev->timer_set) {
        ngx_del_timer(ev);
    }


#if (NGX_HTTP_SSL)
	if(usfc->ssl && c->ssl == NULL){
    	ngx_http_upstream_filter_begin_ssl(usfc, r, c);
    	return;
	}
#endif

	ngx_http_upstream_filter_send_request(data, c);
	return;

exception:
	ngx_http_upstream_filter_exception(r, c, usfscf, error_message);
}

void ngx_http_upstream_filter_send_request(ngx_http_upstream_filter_connection_data *data, ngx_connection_t *c){

	ngx_http_request_t  *r = data->r;
	ngx_url_t	url = data->usfc->url;
	ngx_str_t value = data->value, temp;
	ngx_http_upstream_filter_config *usfc = data->usfc;
	ngx_http_upstream_filter_srv_conf_t *usfscf = data->usfscf;
	char *error_message;

	ngx_log_error(NGX_LOG_INFO, c->log, 0, "[ngx_http_upstream_filter_send_request]");

	ngx_buf_t *buf = data->write_buf;

	if(buf == NULL){
		u_char *real_url = ngx_palloc(r->pool, DEFAULT_MAX_URL_LENGTH);
		u_char *last = ngx_snprintf(real_url, DEFAULT_MAX_URL_LENGTH, (const char*)url.uri.data, &value);
		temp.data = real_url;
		temp.len = last - real_url;
		buf = ngx_create_temp_buf(r->pool, DEFAULT_MAX_REQUEST_DATA_LENGTH);
		buf->last = ngx_slprintf(buf->last, buf->end,
							"GET %V  HTTP/1.1\r\n"
							"Host: %V\r\n"
							"Accept: */*\r\n"
							"\r\n\r\n", &temp
							, &url.host
							);
		data->write_buf = buf;
	}

	if(buf->pos == buf->last){
		ngx_log_error(NGX_LOG_INFO, c->log, 0, "[ngx_http_upstream_filter_send_request][already finished]");
		return;
	}

	ssize_t size ;
	while(buf->pos < buf->last){

		size = c->send(c, buf->pos, buf->last - buf->pos);

		if( size >= 0){

			ngx_str_t print;
			print.data = buf->pos;
			print.len = size;
			ngx_log_error(NGX_LOG_INFO, c->log, 0, "[ngx_http_upstream_filter_send_request]%V", &print);

			buf->pos += size;
		}else if(size == NGX_AGAIN){
			ngx_add_timer(c->write, usfc->timeout);
			return;
		}else{
			error_message = "write error";
			goto exception;
		}
	}

	if(buf->pos == buf->last){
		ngx_add_timer(c->read, usfc->timeout);
	}
	return;

exception:
	ngx_http_upstream_filter_exception(r, c, usfscf, error_message);
}

void ngx_http_upstream_filter_add_fail_header(ngx_http_request_t *r, char *error_message){

	ngx_str_t key = ngx_string(UPSTREAM_FILTER_UNPASS_HEADER_KEY);
	ngx_str_t value = {ngx_strlen(error_message), (u_char*)error_message};
	ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
	if(h == NULL){
		return;
	}

	ngx_memset(h, 0, sizeof(ngx_table_elt_t));
	h->key = key;
	h->value = value;

	h->hash = ngx_hash_key_lc(key.data, key.len);

	h->lowcase_key = ngx_palloc(r->pool, key.len);
	if(h->lowcase_key == NULL){
		return;
	}
	ngx_strlow(h->lowcase_key, key.data, key.len);
}


void ngx_http_upstream_filter_not_pass(ngx_http_request_t *r, ngx_connection_t *c, ngx_http_upstream_filter_srv_conf_t *usfscf, ngx_str_t body, char *error_message){

	ngx_str_t type = ngx_string("text/plain");
	ngx_chain_t  chain;
	ngx_buf_t	buf;
	ngx_int_t	rc;

	ngx_log_error(NGX_LOG_ERR, r->pool->log, 0, "[ngx_http_upstream_filter][unpass][authrization failed]%s", error_message);



	ngx_http_upstream_filter_cleanup(c);

	r->headers_out.status = NGX_HTTP_UNAUTHORIZED;
	r->headers_out.content_type = type;
	r->headers_out.content_length_n = body.len;

	ngx_http_upstream_filter_add_fail_header(r, error_message);

	memset(&buf, 0, sizeof(ngx_buf_t));

	buf.last_buf = 1;
	buf.temporary = 1;
	buf.start = body.data;
	buf.pos = body.data;
	buf.last = body.data + body.len;
	buf.end = buf.last;

	chain.buf = &buf;
	chain.next = NULL;

	if(body.len == 0){
		r->header_only = 1;
	}
	rc = ngx_http_send_header(r);
	if(rc == NGX_ERROR || rc > NGX_OK || r->header_only){
		ngx_http_finalize_request(r, rc);
		return;
	}

	rc = ngx_http_output_filter(r, &chain);
	ngx_http_finalize_request(r, rc);
}

//异常情况下，处理
void ngx_http_upstream_filter_exception(ngx_http_request_t *r, ngx_connection_t *c, ngx_http_upstream_filter_srv_conf_t *usfscf, char *error_message){

	ngx_http_upstream_filter_cleanup(c);

	if(usfscf->auth_filter_exception_pass){
		ngx_log_error(NGX_LOG_ERR, r->pool->log, 0, "[ngx_http_upstream_filter][pass][exception default pass]%s", error_message);
		ngx_http_upstream_init_next(r);
	}else{
		ngx_log_error(NGX_LOG_ERR, r->pool->log, 0, "[ngx_http_upstream_filter][unpass][exception default unpass]%s", error_message);
		ngx_http_upstream_filter_add_fail_header(r, error_message);
		ngx_http_finalize_request(r, NGX_HTTP_UNAUTHORIZED);
	}
}


#if (NGX_HTTP_SSL)
ngx_int_t ngx_http_upstream_filter_init_ssl(ngx_http_upstream_filter_config  *usfc, ngx_conf_t *cf){

    ngx_pool_cleanup_t  *cln;

    usfc->ssl = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
    if (usfc->ssl == NULL) {
        return NGX_ERROR;
    }

    usfc->ssl->log = cf->log;

    if (ngx_ssl_create(usfc->ssl,
                       NGX_SSL_SSLv2|NGX_SSL_TLSv1
                                    |NGX_SSL_TLSv1_1,
                       NULL)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_ssl_cleanup_ctx;
    cln->data = usfc->ssl;

    return NGX_OK;
}

void ngx_http_upstream_filter_ssl_handshake(ngx_connection_t *c){

	if(c->ssl->handshaked){

		ngx_log_error(NGX_LOG_INFO, c->log, 0, "[ngx_http_upstream_filter_ssl_handshake]");
		c->read->handler = ngx_http_upstream_filter_read_handler;
		c->write->handler = ngx_http_upstream_filter_write_handler;

		ngx_http_upstream_filter_connection_data *data = (ngx_http_upstream_filter_connection_data *)c->data;
		ngx_http_request_t *r = data->r;
        r->connection->log->action = "negotiate with auth system";
		ngx_http_upstream_filter_send_request(data, c);
		return;
	}

	ngx_http_upstream_filter_connection_data *data = c->data;
	ngx_http_upstream_filter_exception(data->r, c, data->usfscf, "ssl handshake fail");

}

void ngx_http_upstream_filter_begin_ssl(ngx_http_upstream_filter_config *usfc, ngx_http_request_t *r, ngx_connection_t *c){

	ngx_int_t rc;

	ngx_log_error(NGX_LOG_INFO, r->pool->log, 0, "[ngx_http_upstream_filter_begin_ssl]");

	ngx_add_timer(c->write, usfc->timeout);

    if(usfc->ssl != NULL){

        if (ngx_ssl_create_connection(usfc->ssl, c,
                                      NGX_SSL_BUFFER|NGX_SSL_CLIENT)
            != NGX_OK)
        {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        r->connection->log->action = "SSL handshaking to auth";

        rc = ngx_ssl_handshake(c);

        if (rc == NGX_AGAIN) {
            c->ssl->handler = ngx_http_upstream_filter_ssl_handshake;
            return;
        }

        ngx_http_upstream_filter_ssl_handshake(c);
    }
}

#endif


ngx_str_t ngx_http_upstream_filter_find_key_value(ngx_http_upstream_filter_config *usfc, ngx_http_request_t *r){
	ngx_list_part_t *part;
	ngx_uint_t i;
	ngx_table_elt_t *headers;
	ngx_str_t value = ngx_null_string;
	//send request

	//find key in headers
	part = &r->headers_in.headers.part;
	headers = r->headers_in.headers.part.elts;
	for(i=0 ; ; i++){

		if(i >= part->nelts){
			if(part->next == NULL){
				break;
			}
			part = part->next;
			headers = part->elts;
			i = 0;
		}
		if(ngx_strncasecmp(usfc->key.data, headers[i].key.data, usfc->key.len) == 0){
			value = headers[i].value;
			break;
		}
	}
	return value;
}

static void
ngx_http_upstream_filter_cleanup(void *data)
{
	ngx_connection_t *c = data;

	if(c == NULL){
		return ;
	}

	#if (NGX_HTTP_SSL)

        if (c->ssl) {

            c->ssl->no_wait_shutdown = 1;

            (void) ngx_ssl_shutdown(c);
        }
	#endif


	ngx_log_error(NGX_LOG_INFO, c->log, 0, "[ngx_http_upstream_filter_cleanup]");
	ngx_close_connection(c);
}

void ngx_http_upstream_filter(ngx_http_upstream_filter_srv_conf_t *usfscf, ngx_http_upstream_filter_config *usfc, ngx_http_request_t *r){

	ngx_peer_connection_t *pc;
	ngx_connection_t	*c;
	ngx_int_t rc;
	ngx_str_t value = ngx_null_string;

	ngx_log_error(NGX_LOG_INFO, r->pool->log, 0, "[ngx_http_upstream_filter]");

	value = ngx_http_upstream_filter_find_key_value(usfc, r);
	if(value.len == 0){
		ngx_http_upstream_filter_not_pass(r, NULL, usfscf, value, "cat not find token in request");
		return;
	}

	pc = ngx_palloc(r->pool, sizeof(ngx_peer_connection_t));
	if(pc == NULL){
		ngx_http_upstream_filter_exception(r, NULL, usfscf, "alloc peer_connector fail");
		return ;
	}

	ngx_memset(pc, 0, sizeof(ngx_peer_connection_t));
	pc->sockaddr = usfc->url.addrs->sockaddr;
	pc->socklen = usfc->url.addrs->socklen;
	pc->name = &usfc->url.addrs->name;

	pc->log = r->pool->log;
	pc->log_error = NGX_ERROR_ERR;

	pc->get = ngx_http_upstream_filter_get;

	ngx_log_error(NGX_LOG_INFO, r->pool->log, 0, "[ngx_http_upstream_filter][connect]");
    rc = ngx_event_connect_peer(pc);

    if(rc == NGX_ERROR || rc == NGX_DECLINED){
    	//
		ngx_log_error(NGX_LOG_ERR, r->pool->log, 0, "[ngx_http_upstream_filter]connect error");
		ngx_http_upstream_filter_exception(r, pc->connection, usfscf, "connect error");
		return;
    }

    c = pc->connection;

	c->read->handler = ngx_http_upstream_filter_read_handler;
	c->write->handler = ngx_http_upstream_filter_write_handler;

	ngx_http_upstream_filter_connection_data *data = ngx_palloc(r->pool, sizeof(ngx_http_upstream_filter_connection_data));
	if(data == NULL){
		ngx_http_upstream_filter_exception(r, pc->connection, usfscf, "alloc connection_data error");
		return;
	}
	ngx_memset(data, 0, sizeof(ngx_http_upstream_filter_connection_data));
	data->r = r;
	data->usfc = usfc;
	data->value = value;
	data->usfscf = usfscf;

	c->data = data;
	c->pool = r->pool;

    if(rc == NGX_AGAIN){
    	ngx_add_timer(c->write, usfc->timeout);
    	return;
    }

	#if (NGX_HTTP_SSL)
    	ngx_http_upstream_filter_begin_ssl(usfc, r, c);
	#endif
}

ngx_http_upstream_srv_conf_t    *ngx_http_upstream_filter_get_uscf(ngx_http_request_t *r, ngx_http_upstream_t *u){

	ngx_http_upstream_srv_conf_t    *uscf = NULL;
	ngx_str_t *host;
	ngx_http_upstream_main_conf_t *umcf;
	ngx_list_part_t *part;
	ngx_http_upstream_srv_conf_t **uscfp;
	ngx_uint_t i;

    if (u->resolved == NULL) {

        return u->conf->upstream;

    } else {

        if (u->resolved->sockaddr) {
            return NULL;
        }

        host = &u->resolved->host;

        umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

#if (NGX_HTTP_UPSTREAM_RBTREE)

        uscf = ngx_http_upstream_rbtree_lookup(umcf, host);

        if (uscf != NULL && ((uscf->port == 0 && u->resolved->no_port)
            || uscf->port == u->resolved->port))
        {
            goto found;
        }

        part = &umcf->implicit_upstreams.part;
        uscfp = part->elts;

        for (i = 0; /* void */ ; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                uscfp = part->elts;
                i = 0;
            }

#else

        uscfp = umcf->upstreams.elts;

        for (i = 0; i < umcf->upstreams.nelts; i++) {

#endif

            uscf = uscfp[i];

            if (uscf->host.len == host->len
                && ((uscf->port == 0 && u->resolved->no_port)
                     || uscf->port == u->resolved->port)
                && ngx_memcmp(uscf->host.data, host->data, host->len) == 0)
            {
                goto found;
            }
        }
    }

found:
	return uscf;
}
void ngx_http_upstream_filter_upstream_init_mock(ngx_http_request_t *r){

    ngx_http_upstream_srv_conf_t    *upstream;
    ngx_http_upstream_filter_srv_conf_t *usfscf;
    ngx_uint_t  i;
    ngx_str_t url;
    ngx_regex_compile_t  *pass_pattern;
    ngx_http_upstream_filter_config *usfc;

	ngx_log_error(NGX_LOG_INFO, r->pool->log, 0, "[ngx_http_upstream_filter_upstream_init_mock]");

	if(r->upstream == NULL){
		ngx_log_error(NGX_LOG_INFO, r->pool->log, 0, "[ngx_http_upstream_filter_upstream_init_mock][upstream null]");
		goto next;
	}

	upstream = ngx_http_upstream_filter_get_uscf(r, r->upstream);

	if(upstream == NULL){
		ngx_log_error(NGX_LOG_INFO, r->pool->log, 0, "[ngx_http_upstream_filter_upstream_init_mock][upstream srv_cf null]");
		goto next;
	}

	if(upstream->srv_conf == NULL){
		ngx_log_error(NGX_LOG_INFO, r->pool->log, 0, "[ngx_http_upstream_filter_upstream_init_mock][srv_conf_null]");
		goto next;
	}

	usfscf = ngx_http_conf_upstream_srv_conf(upstream, ngx_http_upstream_filter_module);
	if(!usfscf->auth_filter_open){
		ngx_log_error(NGX_LOG_INFO, r->pool->log, 0, "[ngx_http_upstream_filter_upstream_init_mock][filter_off]");
		goto next;
	}

	//is pass
	ngx_log_error(NGX_LOG_INFO, r->pool->log, 0, "[ngx_http_upstream_filter_upstream_init_mock][pass_pattern]");
	url = r->uri;
	pass_pattern = (ngx_regex_compile_t*)usfscf->auth_filter_pass_pattern_regex->elts;
	for(i=0; i<usfscf->auth_filter_pass_pattern_regex->nelts ;i++){

		if(ngx_regex_exec(pass_pattern[i].regex, &url, NULL, 0) >= 0){
			//pass
			ngx_log_error(NGX_LOG_INFO, r->pool->log, 0, "[ngx_http_upstream_filter_upstream_init_mock]%V pass", &url);
			goto next;
		}
	}

	//
	ngx_log_error(NGX_LOG_INFO, r->pool->log, 0, "[ngx_http_upstream_filter_upstream_init_mock][filter_type]");
	usfc = usfscf->upstream_filter_config->elts;
	for(i=0;i<usfscf->upstream_filter_config->nelts;i++){
		if(usfc[i].on && ngx_regex_exec(usfc[i].url_pattern_regex->regex, &url, NULL, 0) >= 0){
			break;
		}
	}

	if(i < usfscf->upstream_filter_config->nelts){
		//send request and get return
		ngx_log_error(NGX_LOG_INFO, r->pool->log, 0, "[ngx_http_upstream_filter_upstream_init_mock]%V to be filted", &url);
		ngx_http_upstream_filter(usfscf, &usfc[i], r);
		return;
	}

next:
	ngx_log_error(NGX_LOG_INFO, r->pool->log, 0, "[ngx_http_upstream_filter_upstream_init_mock][next]");
	ngx_http_upstream_init_next(r);
}

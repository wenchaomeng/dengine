#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "ngx_http_dyups_module.h"

#define DEFAULT_LB_LUA_FILE "/usr/local/nginx/conf/phoenix-slb/rule.lua"
#define DEFAULT_DYPP_KEY "dypp_key"
#define DEFAULT_MAX_SERVER 200

typedef struct {
	ngx_str_t dp_domain;
	ngx_str_t dypp_lua_file;
	ngx_str_t dypp_key;
	lua_State *L;
} ngx_http_dypp_loc_conf_t;

typedef struct {
	ngx_uint_t dypp_key_generate;	
} ngx_http_dypp_filter_loc_conf_t;

ngx_http_request_t *cur_r;
ngx_str_t *cur_dp_domain;
ngx_str_t *dypp_key;
unsigned long uid = 0;
int weight_list[DEFAULT_MAX_SERVER];
int weight_list_on = 0;

//static ngx_http_output_body_filter_pt  ngx_http_next_body_filter;
static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;

static void* ngx_http_dypp_create_loc_conf(ngx_conf_t* cf);

static char* ngx_http_dypp_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_dypp_preconfig(ngx_conf_t *cf);

ngx_int_t ngx_http_dypp_get_variable (ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static u_char* call_lua(ngx_http_request_t *r, lua_State *L);

static int get_cookie(lua_State *L) ;

static int get_upstream_list(lua_State *L) ;

static int get_ngx_http_variable(lua_State *L);

static ngx_int_t ngx_dynamic_proxy_pass_filter_init(ngx_conf_t *cf);

static ngx_int_t ngx_dynamic_proxy_pass_header_filter(ngx_http_request_t *r);

static void *ngx_dynamic_proxy_pass_filter_create_conf(ngx_conf_t *cf);

static char *ngx_dynamic_proxy_pass_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t set_header(ngx_http_request_t* r, ngx_str_t* key, ngx_str_t* value);

static unsigned long generate_uid();

static unsigned long get_uid();

static ngx_int_t has_generate_uid(ngx_http_request_t* r);

static char * set_weight(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t ngx_dynamic_proxy_pass_module_commands[] = {
	{
		ngx_string("dp_domain"), // The command name
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot, // The command handler
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_dypp_loc_conf_t, dp_domain),
		NULL
	},

	{ ngx_string("dypp_lua_file"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_dypp_loc_conf_t, dypp_lua_file),
		NULL },

	{
		ngx_string("dypp_key"), // The command name
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot, // The command handler
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_dypp_loc_conf_t, dypp_key),
		NULL
	},

	{
		ngx_string("dypp_weight"), // The command name
		NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
		set_weight, // The command handler
		0,
		0,
		NULL
	},

	ngx_null_command
};

static ngx_command_t  ngx_dynamic_proxy_pass_filter_commands[] = {

	{ 
		ngx_string("dypp_key_generate"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_dypp_filter_loc_conf_t, dypp_key_generate),
		NULL 
	},

	ngx_null_command
};

static ngx_http_module_t ngx_dynamic_proxy_pass_module_ctx = {
	ngx_http_dypp_preconfig,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	ngx_http_dypp_create_loc_conf,
	ngx_http_dypp_merge_loc_conf
};

static ngx_http_module_t  ngx_dynamic_proxy_pass_filter_module_ctx = {
	NULL,           /* preconfiguration */
	ngx_dynamic_proxy_pass_filter_init,             /* postconfiguration */

	NULL,                                  /* create main configuration */
	NULL,                                  /* init main configuration */

	NULL,                                  /* create server configuration */
	NULL,                                  /* merge server configuration */

	ngx_dynamic_proxy_pass_filter_create_conf,             /* create location configuration */
	ngx_dynamic_proxy_pass_filter_merge_conf               /* merge location configuration */
};

ngx_module_t ngx_dynamic_proxy_pass_module = {
	NGX_MODULE_V1,
	&ngx_dynamic_proxy_pass_module_ctx,
	ngx_dynamic_proxy_pass_module_commands,
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

ngx_module_t  ngx_dynamic_proxy_pass_filter_module = {
	NGX_MODULE_V1,
	&ngx_dynamic_proxy_pass_filter_module_ctx,      /* module context */
	ngx_dynamic_proxy_pass_filter_commands,         /* module directives */
	NGX_HTTP_MODULE,                       /* module type */
	NULL,                                  /* init master */
	NULL,                                  /* init module */
	NULL,                                  /* init process */
	NULL,                                  /* init thread */
	NULL,                                  /* exit thread */
	NULL,                                  /* exit process */
	NULL,                                  /* exit master */
	NGX_MODULE_V1_PADDING
};

static void* ngx_http_dypp_create_loc_conf(ngx_conf_t* cf) {
	ngx_http_dypp_loc_conf_t* conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dypp_loc_conf_t));
	if (conf == NULL) {
		return NGX_CONF_ERROR;
	}
	conf->dp_domain.len = 0;
	conf->dp_domain.data = NULL;
	conf->dypp_lua_file.data = NULL;
	conf->dypp_lua_file.len = 0;
	conf->dypp_key.data = NULL;
	conf->dypp_key.len = 0;

	return conf;
}

static char* ngx_http_dypp_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child){
	ngx_http_dypp_loc_conf_t *prev = parent;
	ngx_http_dypp_loc_conf_t *conf = child;

	ngx_conf_merge_str_value(conf->dp_domain, prev->dp_domain, "");
	ngx_conf_merge_str_value(conf->dypp_lua_file, prev->dypp_lua_file, "");
	ngx_conf_merge_str_value(conf->dypp_key, prev->dypp_key, "");

	return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_dypp_preconfig(ngx_conf_t *cf){
	ngx_http_variable_t           *var;
	ngx_str_t name;

	char* char_name = "dp_upstream";
	name.len = strlen(char_name);
	name.data = ngx_pcalloc(cf->pool, name.len);
	ngx_memcpy(name.data, char_name, name.len);

	var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_CHANGEABLE);
	if (var == NULL) {
		return NGX_ERROR;
	}
	//设置回调
	var->get_handler = ngx_http_dypp_get_variable;
	//var->data = (uintptr_t) ctx;
	return NGX_OK;
}

static int get_cookie(lua_State *L) {
	ngx_str_t cookie_name;
	cookie_name.data = (u_char*)lua_tolstring(L, 1, &cookie_name.len);
	ngx_str_t *value = ngx_pnalloc(cur_r->pool, sizeof(ngx_str_t));
	ngx_http_parse_multi_header_lines(&cur_r->headers_in.cookies, &cookie_name, value);
	lua_pushlstring(L, (char*)value->data, value->len);
	ngx_log_debug1(NGX_LOG_DEBUG, cur_r->connection->log, 0, "parameter from lua %V", &cookie_name);
	return 1;	
}

static int get_ngx_http_variable(lua_State *L) {
	u_char *lowcase;
	ngx_uint_t hash;
	ngx_str_t name;
	ngx_http_variable_value_t *vv;

	//	p = (u_char*)lua_tolstring(L, 1, &len);
	lowcase = ngx_pnalloc(cur_r->pool, dypp_key->len);
	hash = ngx_hash_strlow(lowcase, dypp_key->data, dypp_key->len);

	name.len = dypp_key->len;
	name.data = lowcase;
	vv = ngx_http_get_variable(cur_r, &name, hash);

	if(!vv || vv->len == 0 || !vv->data || vv->not_found == 1){
		char buf[200];
		memset(buf, 0, 200);
		sprintf(buf, "%lu", generate_uid());
		lua_pushlstring(L, buf, 1);//TODO
		return 1;
//		lowcase = ngx_pnalloc(cur_r->pool, ngx_strlen(DEFAULT_COOKIE_UUID));
//		hash = ngx_hash_strlow(lowcase, DEFAULT_COOKIE_UUID, ngx_strlen(DEFAULT_COOKIE_UUID));//TODO
//		name.len = ngx_strlen(DEFAULT_COOKIE_UUID);
//		name.data = lowcase;
//		vv = ngx_http_get_variable(cur_r, &name, hash);
	}
	if(vv && vv->len > 0 && vv->data && vv->not_found != 1) {
		lua_pushlstring(L, (char*)vv->data, vv->len);
		return 1;
	} else {
		char buf[2];
		buf[0] = '0';
		buf[1] = '\0';
		lua_pushlstring(L, buf, 1);//TODO
		return 1;
	}
}

extern ngx_module_t  ngx_http_dyups_module;
static int get_upstream_list(lua_State *L) {
	ngx_http_dyups_main_conf_t  *dumcf;
	dumcf = ngx_http_get_module_main_conf(cur_r, ngx_http_dyups_module);

	ngx_uint_t i, chosen_upstream_cnt;
	chosen_upstream_cnt = 0;
	ngx_http_dyups_srv_conf_t *duscfs, *duscf;
	duscfs = dumcf->dy_upstreams.elts;
	for (i = 0; i < dumcf->dy_upstreams.nelts; i++) {
		duscf = &duscfs[i];

		ngx_str_t *upstream_name = &duscf->upstream->host;
		//ngx_log_error(NGX_LOG_ERR, cur_r->connection->log, 0, "hupengtest %s", (char*)upstream_name->data);
		if(ngx_strncmp(upstream_name->data, cur_dp_domain->data, cur_dp_domain->len) == 0) {
			if(ngx_strncmp(upstream_name->data, cur_dp_domain->data, upstream_name->len) == 0) {
				chosen_upstream_cnt++;
				lua_pushlstring(L, (char*)duscf->upstream->host.data, duscf->upstream->host.len);
				if(weight_list_on){
					if(weight_list[i] == 0){
						lua_pushinteger(L, weight_list[i] + 1);
					}
					else{
						lua_pushinteger(L, weight_list[i]);
					}
				}
				else{
					lua_pushinteger(L, duscf->upstream->servers->nelts);
				}
			}
			else{
				if(upstream_name->data[cur_dp_domain->len] == '@') {
					chosen_upstream_cnt++;
					lua_pushlstring(L, (char*)duscf->upstream->host.data, duscf->upstream->host.len);
					if(weight_list_on){
						if(weight_list[i] == 0){
							lua_pushinteger(L, weight_list[i] + 1);
						}
						else{
							lua_pushinteger(L, weight_list[i]);
						}
					}
					else{
						lua_pushinteger(L, duscf->upstream->servers->nelts);
					}

				}
			}
		}

	}

	return 2 * chosen_upstream_cnt;
}

static u_char* call_lua(ngx_http_request_t *r, lua_State *L) {
	cur_r = r;
	lua_getglobal(L, "choose_upstream");
	lua_pcall(L, 0, 0, 0);
	// TODO can we use lua_tostring(L, -1) and is it faster?
	lua_getglobal(L, "upstream");
	const char *lua_result = lua_tostring(L, -1);
	if(!lua_result){
		return NULL;
	}
	char* chosen_upstream = ngx_pcalloc(r->pool, strlen(lua_result) + 1);
	strcpy(chosen_upstream, lua_result);
	ngx_log_debug1(NGX_LOG_DEBUG, r->connection->log, 0, "[dypp] lua result %s", chosen_upstream);
	//lua_close(L);
	lua_pop(L, 1);
	return (u_char*)chosen_upstream;
}

ngx_int_t ngx_http_dypp_get_variable (ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data){
	ngx_http_dypp_loc_conf_t *hdlc;
	hdlc = ngx_http_get_module_loc_conf(r, ngx_dynamic_proxy_pass_module);
	if(hdlc->L == NULL){
		hdlc->L = luaL_newstate();
		if(hdlc->L == NULL) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Can not init lua");
			return NGX_ERROR;
		}
		luaL_openlibs(hdlc->L);
		lua_register(hdlc->L, "get_cookie", get_cookie);
		lua_register(hdlc->L, "get_upstream_list", get_upstream_list);
		lua_register(hdlc->L, "get_ngx_http_variable", get_ngx_http_variable);

		if ((char*)hdlc->dypp_lua_file.data == NULL || hdlc->dypp_lua_file.len == 0){
			if (luaL_loadfile(hdlc->L, DEFAULT_LB_LUA_FILE) || lua_pcall(hdlc->L,0,0,0)) {
				return NGX_ERROR;
			}
		}
		else{
			if (luaL_loadfile(hdlc->L, (char*)hdlc->dypp_lua_file.data) || lua_pcall(hdlc->L,0,0,0)) {
				return NGX_ERROR;
			}
		}

		if (hdlc->dypp_key.data == NULL || hdlc->dypp_key.len == 0) {
			dypp_key = malloc(sizeof(ngx_str_t));
			if(dypp_key){
				memset(dypp_key, 0, sizeof(ngx_str_t));
				dypp_key->data = malloc(strlen("cookie_") + strlen(DEFAULT_DYPP_KEY) + 1);
				if(dypp_key->data){
					memset(dypp_key->data, 0, strlen("cookie_") + strlen(DEFAULT_DYPP_KEY) + 1);
					ngx_sprintf(dypp_key->data, "%s%s", "cookie_", DEFAULT_DYPP_KEY);
					//ngx_memcpy(dypp_key->data, DEFAULT_DYPP_KEY, strlen(DEFAULT_DYPP_KEY));
				}
				dypp_key->len = strlen("cookie_") + strlen(DEFAULT_DYPP_KEY);
			}
		}
		else{
			dypp_key = malloc(sizeof(ngx_str_t));
			if(dypp_key){
				memset(dypp_key, 0, sizeof(ngx_str_t));
				dypp_key->data = malloc(strlen("cookie_") + hdlc->dypp_key.len + 1);
				if(dypp_key->data){
					memset(dypp_key->data, 0, strlen("cookie_") + hdlc->dypp_key.len + 1);
					ngx_memcpy(dypp_key->data, "cookie_", strlen("cookie_"));
					ngx_memcpy(dypp_key->data + strlen("cookie_"), hdlc->dypp_key.data, hdlc->dypp_key.len);
				}
			}
			dypp_key->len = hdlc->dypp_key.len + strlen("cookie_");	
		}

	}
	cur_dp_domain = &hdlc->dp_domain;

	//ngx_str_t baidu = ngx_string("baidu");
	//ngx_str_t dianping = ngx_string("dianping");

	u_char *chosen_upstream = call_lua(r, hdlc->L);
	if(!chosen_upstream){
		return NGX_ERROR;
	}
	/*
	   if(ahlf == NULL) {
	   call_lua(r);
	   }
	   char* chosen_upstream = ngx_pcalloc(r->pool, 6);
	   strcpy(chosen_upstream, "six@0");
	   */

	if(r->headers_in.cookies.nelts > 0){

		/*
		   ngx_str_t *value = ngx_pnalloc(r->pool, sizeof(ngx_str_t));
		   ngx_str_t cookie_name = ngx_string("UID");
		   ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &cookie_name, value);
		   ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "UID %V", value);
		   */

		/*	
			if (ngx_strncasecmp(value->data, baidu.data, baidu.len) == 0) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "GOTO BIDU");
			chosen_pool = &baidu;
			} else {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "GOTO DP");
			chosen_pool = &dianping;
			}
			*/

		/*
		   ngx_table_elt_t** cookies = r->headers_in.cookies.elts;
		   int i = 0;
		   for(i = 0; i < (int)r->headers_in.cookies.nelts; i++){
		   ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "COOKIE %V", &cookies[i]->value);
		   }
		   */
	}
	v->len = strlen((char*)chosen_upstream);
	v->data = (u_char*)chosen_upstream;
	/*
	   if (v->data == NULL) {
	   return NGX_ERROR;
	   }
	   ngx_memcpy(v->data, chosen_pool->data, chosen_pool->len);
	   */
	v->valid = 1;

	return NGX_OK;
}

	static ngx_int_t
ngx_dynamic_proxy_pass_filter_init(ngx_conf_t *cf)
{
	//	ngx_http_next_body_filter = ngx_http_top_body_filter;
	//	ngx_http_top_body_filter = ngx_cat_body_filter;

	ngx_http_next_header_filter = ngx_http_top_header_filter;
	ngx_http_top_header_filter = ngx_dynamic_proxy_pass_header_filter;

	return NGX_OK;
}

static ngx_int_t ngx_dynamic_proxy_pass_header_filter(ngx_http_request_t *r){
	ngx_http_dypp_filter_loc_conf_t  *conf;
	conf = ngx_http_get_module_loc_conf(r, ngx_dynamic_proxy_pass_filter_module);

	if(conf->dypp_key_generate == 1){
		if(has_generate_uid(r) == NGX_OK){
			return ngx_http_next_header_filter(r);
		}
		ngx_str_t key, value;
		key.data = ngx_pcalloc(r->pool, ngx_strlen("Set-Cookie") + 1);
		if(key.data == NULL){
			return ngx_http_next_header_filter(r);
		}
		ngx_memcpy(key.data, "Set-Cookie", ngx_strlen("Set-Cookie"));
		key.len = ngx_strlen("Set-Cookie");

		value.data = ngx_pcalloc(r->pool, 1000 + 1);
		if(value.data == NULL){
			return ngx_http_next_header_filter(r);
		}
		ngx_sprintf(value.data, "%s%s%l", DEFAULT_DYPP_KEY, " = ", get_uid());
		value.len = ngx_strlen(value.data);
		set_header(r, &key, &value);

		//ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "hupengtest dynamic proxy module!!!!!!!!!!!!");
	}

	return ngx_http_next_header_filter(r);
}

	static void *
ngx_dynamic_proxy_pass_filter_create_conf(ngx_conf_t *cf)
{
	ngx_http_dypp_filter_loc_conf_t  *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dypp_filter_loc_conf_t));
	if (conf == NULL) {
		return NULL;
	}

	conf->dypp_key_generate = NGX_CONF_UNSET_UINT;
	return conf;
}


	static char *
ngx_dynamic_proxy_pass_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_dypp_filter_loc_conf_t *prev = parent;
	ngx_http_dypp_filter_loc_conf_t *conf = child;

	ngx_conf_merge_uint_value(conf->dypp_key_generate, prev->dypp_key_generate, 1);
	return NGX_CONF_OK;
}

static ngx_int_t set_header(ngx_http_request_t* r, ngx_str_t* key, ngx_str_t* value){
	ngx_table_elt_t             *h;
	ngx_list_part_t             *part;
	unsigned int i;
	int matched = 0;


	part = &r->headers_out.headers.part;
	h = part->elts;

	for (i = 0; /* void */; i++) {

		if (i >= part->nelts) {
			if (part->next == NULL) {
				break;
			}

			part = part->next;
			h = part->elts;
			i = 0;
		}

		if (h[i].hash == 0) {
			continue;
		}

		if (h[i].key.len == key->len && ngx_strncasecmp(h[i].key.data, key->data, h[i].key.len) == 0)
		{
			goto matched;
		}

		/* not matched */
		continue;

matched:
		if (value->len == 0 || matched) {
			h[i].value.len = 0;
			h[i].hash = 0;

		} else {
			h[i].value = *value;
			h[i].hash = ngx_hash_key_lc(key->data, key->len);
		}
		matched = 1;
	}

	if (matched || value->len == 0){
		return NGX_OK;
	}

	h = ngx_list_push(&r->headers_out.headers);
	if (h == NULL) {
		return NGX_ERROR;
	}

	if (value->len == 0) {
		h->hash = 0;
	} else {
		h->hash = ngx_hash_key_lc(key->data, key->len);
	}

	h->key = *key;
	h->value = *value;

	h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
	if (h->lowcase_key == NULL) {
		return NGX_ERROR;
	}

	ngx_strlow(h->lowcase_key, h->key.data, h->key.len);

	return NGX_OK;

}

static unsigned long generate_uid(){
	return ++uid;
}

static unsigned long get_uid(){
	return uid;
}

static ngx_int_t has_generate_uid(ngx_http_request_t* r){
	ngx_table_elt_t** cookies = r->headers_in.cookies.elts;
	int i = 0;
	for(i = 0; i < (int)r->headers_in.cookies.nelts; i++){
		if(strstr((char*)(cookies[i])->value.data, DEFAULT_DYPP_KEY) == NULL){
			continue;
		}
		else{
			return NGX_OK;
		}
	}
	return NGX_ERROR;
}

static char *
set_weight(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
	weight_list_on = 1;
	ngx_int_t        np;
	ngx_str_t        *value;
	ngx_conf_post_t  *post;

	value = cf->args->elts;
	np = ngx_atoi(value[1].data, value[1].len);
	if (np == NGX_ERROR) {
		return "invalid number";
	}

	int i = 0;
	while(weight_list[i] != 0){
		i++;
	}
	weight_list[i] = np;

	if (cmd->post) {
		post = cmd->post;
		return post->post_handler(cf, post, (void*)&np);
	}
	return NGX_CONF_OK;
}

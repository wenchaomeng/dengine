#include "ngx_upstream_degrade.h"

extern ngx_module_t ngx_dynamic_proxy_pass_module;
extern ngx_http_upstream_check_peers_t *check_peers_ctx;
extern ngx_module_t  ngx_http_upstream_module;
static ngx_uint_t ngx_upstream_shm_generation = 0;

ngx_http_dypp_main_conf_t     *dmcf_global;

static char * ngx_http_dypp_init_shm(ngx_conf_t *cf, void *conf);
static ngx_int_t ngx_http_dypp_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data);
static ngx_int_t ngx_http_dypp_get_shm_name(ngx_str_t *shm_name, ngx_pool_t *pool,
    ngx_uint_t generation);
static void ngx_http_upstream_degrade_create_return_str(ngx_buf_t *buf);
static ngx_int_t ngx_http_upstream_degrade_add_unchecked_pools(ngx_rbtree_t tree, ngx_pool_t *pool, ngx_log_t *log);
void *
ngx_http_dypp_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_dypp_main_conf_t  *dmcf;

    dmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dypp_main_conf_t));

    if (dmcf == NULL) {
        return NULL;
    }

	//set global reference
	dmcf_global = dmcf;
    return dmcf;
}

void	*ngx_http_dypp_create_srv_conf(ngx_conf_t *cf){

    ngx_http_dypp_srv_conf_t  *dscf, *parent;
    ngx_uint_t 	parent_value = NGX_CONF_UNSET_UINT;

    dscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dypp_srv_conf_t));
	if(dscf == NULL){
		return NULL;
	}

	dscf->degrade_rate = NGX_CONF_UNSET_UINT;

	if(cf->module_type == NGX_HTTP_MODULE){

		parent = ngx_http_conf_get_module_srv_conf(cf, ngx_dynamic_proxy_pass_module);
		parent_value = parent->degrade_rate;
	}


	ngx_conf_merge_uint_value(dscf->degrade_rate, parent_value, UPSTREA_DEGRATE_DEFAULT_RATE);
	ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0, " after create and merge, dypp_rate_rate: %ui", dscf->degrade_rate);

    return dscf;
}

char * ngx_http_dypp_set_degrade_rate(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){

    ngx_http_dypp_srv_conf_t  *dscf = conf;
    ngx_str_t	*value = cf->args->elts;
    ngx_int_t 	rate;

    if(cf->args->nelts != 2){

    	return " dypp_degrade_rate should have one and only one parameter.";
    }

    rate = ngx_atoi(value[1].data, value[1].len);
    if(rate < 0 || rate > 100){
    	return "upstream_degrade_rate should between 0 and 100";
    }
    dscf->degrade_rate = rate;
	ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0, " dypp_rate_rate: %ui", dscf->degrade_rate);


    return NGX_CONF_OK;
}

char *
ngx_http_dypp_init_main_conf(ngx_conf_t *cf, void *conf)
{
	ngx_http_upstream_main_conf_t 			*umcf;	
    ngx_http_dypp_main_conf_t  *dmcf = conf;

    dmcf->ctx = cf->ctx;
	//upstream大小
	umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);

	dmcf->static_upstream_size = umcf->upstreams.nelts;
	//采用默认值
	dmcf->degrade_interval = UPSTREAM_DEGRADE_INTERVAL;

    return ngx_http_dypp_init_shm(cf, conf);
}

static char *
ngx_http_dypp_init_shm(ngx_conf_t *cf, void *conf)
{
    ngx_str_t                            shm_name;
    ngx_uint_t                           shm_size;
    ngx_shm_zone_t                       *shm_zone;
    ngx_http_dypp_main_conf_t  *dmcf = conf;

	ngx_upstream_shm_generation++;

	ngx_http_dypp_get_shm_name(&shm_name, cf->pool, ngx_upstream_shm_generation);

    /* The default shared memory size is 1M */
    shm_size = 1024*1024;

    shm_size = shm_size < dmcf->degrade_shm_size ?
                          dmcf->degrade_shm_size : shm_size;

    shm_zone = ngx_shared_memory_add(cf, &shm_name, shm_size,
                                     &ngx_dynamic_proxy_pass_module);

	ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                   "http degrade, shm_name:%V, shm_zone size:%ui",
                   &shm_name, shm_size);

    shm_zone->data = cf->pool;

    shm_zone->init = ngx_http_dypp_init_shm_zone;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_dypp_get_shm_name(ngx_str_t *shm_name, ngx_pool_t *pool,
    ngx_uint_t generation)
{
    u_char  *last;

    shm_name->data = ngx_palloc(pool, UPSTREAM_DEGRADE_SHM_NAME_LENGTH);
    if (shm_name->data == NULL) {
        return NGX_ERROR;
    }

    last = ngx_snprintf(shm_name->data, UPSTREAM_DEGRADE_SHM_NAME_LENGTH, "%s#%ui",
                        "ngx_http_upstream_degrade_shm", generation);

    shm_name->len = last - shm_name->data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_dypp_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    size_t                               size;
    ngx_pool_t                          *pool;
    ngx_slab_pool_t                     *shpool;
	ngx_http_upstream_degrades_shm_t 	*udshm;
    u_char  *file;


    pool = shm_zone->data;
    if (pool == NULL) {
        pool = ngx_cycle->pool;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
	

    size = sizeof(ngx_http_upstream_degrades_shm_t) +
               (dmcf_global->static_upstream_size + UPSTREAM_DEGRADE_SHM_MAX_DYNAMIC_UPSTREAM_SIZE) * sizeof(ngx_http_upstream_degrade_shm_t);

     udshm = ngx_slab_alloc(shpool, size);

     if (udshm == NULL) {
            goto failure;
     }

	ngx_memzero(udshm, size);

    udshm->generation =  ngx_upstream_shm_generation;

    shm_zone->data = udshm;

    //lock
	#if (NGX_HAVE_ATOMIC_OPS)

		file = NULL;

	#else
	    ngx_str_t lock_file_name = ngx_string("degrade");

		file = ngx_pnalloc(pool, ngx_cycle->lock_file.len + lock_file_name.len + 1);
		if (file == NULL) {
			return NGX_ERROR;
		}

		(void) ngx_sprintf(file, "%V%V%Z", &ngx_cycle->lock_file, &lock_file_name);

	#endif

		if (ngx_shmtx_create(&udshm->mutex, &udshm->lock, file) != NGX_OK) {
			return NGX_ERROR;
		}

	//全局变量，定时器调用直接引用
	dmcf_global->udshm = udshm;
	dmcf_global->shpool = shpool;

	return NGX_OK;

failure:
    ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                  "http upstream degrade_shm_size is too small, "
                  "you should specify a larger size.");
    return NGX_ERROR;
}

char *
ngx_http_dypp_degrade_shm_size(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                            *value;
    ngx_http_dypp_main_conf_t  *dmcf;

    dmcf = ngx_http_conf_get_module_main_conf(cf, 
                                               ngx_dynamic_proxy_pass_module );
    if (dmcf->degrade_shm_size) {
        return "is duplicate";
    }

    value = cf->args->elts;

    dmcf->degrade_shm_size = ngx_parse_size(&value[1]);
    if (dmcf->degrade_shm_size == (size_t) NGX_ERROR) {
        return "invalid value";
    }

    return NGX_CONF_OK;
}

ngx_int_t
ngx_http_dypp_add_timers(ngx_cycle_t *cycle){

    ngx_msec_t                           t, delay;
    ngx_http_dypp_main_conf_t *dmcf = dmcf_global;
	ngx_event_t *event;

    srandom(ngx_pid);

    event = ngx_palloc(cycle->pool, sizeof(ngx_event_t));
    if(event == NULL){
    	return NGX_ERROR;
    }
    //初始随机化，防止拥堵
    delay = dmcf->degrade_interval > 1000 ? dmcf->degrade_interval : 1000;
	t = ngx_random() % delay;


	event->handler = ngx_http_upstream_degrade_timer;
	event->log = cycle->log;
	event->data = dmcf;
	event->timer_set = 0;

	ngx_log_error(NGX_LOG_NOTICE, event->log, 0, "add timer %M", t);

	ngx_event_add_timer(event, t);
    return NGX_OK;
}


//便利红黑树，添加数据
ngx_int_t ngx_http_upstream_degrade_update_shm(ngx_rbtree_node_t *current, ngx_rbtree_node_t *sentinel){

	ngx_http_upstream_degrade_shm_t *uds;
	ngx_http_upstream_degrade_rbtree_node_t *node = (ngx_http_upstream_degrade_rbtree_node_t *)current;
	ngx_str_t upstream_name;

	if(current == sentinel){
		return NGX_OK;
	}
	ngx_http_upstream_degrade_update_shm(current->left, sentinel);

	uds = &dmcf_global->udshm->uds[dmcf_global->udshm->upstream_count];

	uds->degrade_rate = node->degrade_rate;
	uds->server_count = node->server_count;
	uds->degrate_up_count = node->degrate_up_count;
	uds->upstream_checked = node->upstream_checked;
	upstream_name = node->str;

	uds->upstream_name.len = upstream_name.len;
	uds->upstream_name.data = ngx_slab_alloc_locked(dmcf_global->shpool, upstream_name.len);
	if(uds->upstream_name.data == NULL){
		ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "[ngx_http_upstream_uds_update_shm][no share memory]");
		return NGX_ERROR_ERR;
	}
	ngx_memcpy(uds->upstream_name.data, upstream_name.data, upstream_name.len);
	dmcf_global->udshm->upstream_count++;
	ngx_http_upstream_degrade_update_shm(current->right, sentinel);
	return NGX_OK;
}

void ngx_http_upstream_degrade_free_shm(ngx_uint_t count){

	ngx_http_upstream_degrade_shm_t *uds = dmcf_global->udshm->uds;
	ngx_uint_t i;

	for(i=0 ; i<count ; i++){
		ngx_slab_free_locked(dmcf_global->shpool, uds[i].upstream_name.data);
	}

}
void ngx_http_upstream_degrade_calculate_state(){

	ngx_http_upstream_degrade_shm_t *uds = dmcf_global->udshm->uds;
	ngx_uint_t i, count = dmcf_global->udshm->upstream_count;
	ngx_uint_t rate;

	for(i=0 ; i<count ; i++){

		rate = uds[i].degrate_up_count*100/uds[i].server_count;
		uds[i].degrate_state = rate >= uds[i].degrade_rate ? UPSTREAM_DEGRADE_STATE_ON : UPSTREAM_DEGRADE_STATE_OFF;
		ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0, "upstream:%V, total: %ui, upcount: %ui, rate: %ui, degrade_rate:%ui",
				&uds[i].upstream_name, uds[i].server_count, uds[i].degrate_up_count, rate, uds[i].degrade_rate);
	}

}

void ngx_http_upstream_degrade_timer(ngx_event_t *event){

	ngx_http_upstream_check_peers_t *peers = check_peers_ctx;
	ngx_http_upstream_check_peer_t *peer;
	ngx_http_dypp_main_conf_t 	*dmcf = dmcf_global;
	ngx_http_dypp_srv_conf_t 	*dscf;
	ngx_uint_t  i, hash, count;
	ngx_pool_t *pool;
	ngx_str_t  *upstream_name;
	ngx_http_upstream_degrade_rbtree_node_t *degrade_node;

	peer = peers->peers.elts;
	ngx_rbtree_t tree;
	ngx_rbtree_node_t sentinel;

	pool = ngx_create_pool(512, event->log);


	//计算
	ngx_rbtree_init(&tree, &sentinel, ngx_str_rbtree_insert_value);

	for(i=0; i< peers->peers.nelts ;i++){

		if( peer[i].delete ){
			//ignored
			continue;
		}

		upstream_name = peer[i].upstream_name;
		hash = ngx_crc32_long(upstream_name->data, upstream_name->len);
		degrade_node = (ngx_http_upstream_degrade_rbtree_node_t*)ngx_str_rbtree_lookup(&tree, upstream_name, hash);

		if(degrade_node == NULL){
			degrade_node = ngx_pcalloc(pool, sizeof(ngx_http_upstream_degrade_rbtree_node_t));
			if(degrade_node == NULL){
				ngx_log_error(NGX_LOG_ERR, event->log, 0 ,"[ngx_http_upstream_degrade_timer]not enough memory.");
				goto fail;
			}
			degrade_node->str = *upstream_name;
			degrade_node->node.key = hash;
			degrade_node->upstream_checked = 1;
			ngx_rbtree_insert(&tree, (ngx_rbtree_node_t *)degrade_node);
		}

		dscf = ngx_http_conf_upstream_srv_conf(peer[i].uscf, ngx_dynamic_proxy_pass_module);

		degrade_node->degrade_rate = dscf->degrade_rate;
		degrade_node->server_count++;
		if(!peer[i].shm->down){
			degrade_node->degrate_up_count++;
		}
	}
	//增加未做健康监测的pool
	ngx_http_upstream_degrade_add_unchecked_pools(tree, pool, event->log);


	//更新共享内存
    ngx_shmtx_lock(&dmcf->udshm->mutex);

    count = dmcf->udshm->upstream_count;
    dmcf->udshm->upstream_count = 0;
    ngx_http_upstream_degrade_free_shm(count);
    ngx_http_upstream_degrade_update_shm(tree.root, tree.sentinel);
    ngx_http_upstream_degrade_calculate_state();

	ngx_shmtx_unlock(&dmcf->udshm->mutex);


fail:
	ngx_event_add_timer(event, dmcf_global->degrade_interval);
	ngx_destroy_pool(pool);
}

static ngx_int_t ngx_http_upstream_degrade_add_unchecked_pools(ngx_rbtree_t tree, ngx_pool_t *pool, ngx_log_t *log){

    ngx_http_upstream_main_conf_t  *umcf;
    ngx_http_upstream_srv_conf_t	**uscfp;
	ngx_str_t  *upstream_name;
	ngx_http_upstream_degrade_rbtree_node_t *degrade_node;

    ngx_uint_t 	i, hash;

    umcf = ngx_http_get_module_main_conf(dmcf_global->ctx, ngx_http_upstream_module);
    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

    	if(uscfp[i]->servers == NULL){
    		/**
    		 * like proxy_pass http://www.baidu.com
    		 */
    		continue;

    	}
    	upstream_name = &uscfp[i]->host;
		hash = ngx_crc32_long(upstream_name->data, upstream_name->len);
		degrade_node = (ngx_http_upstream_degrade_rbtree_node_t*)ngx_str_rbtree_lookup(&tree, upstream_name, hash);
		if(degrade_node){
			continue;
		}
		degrade_node = ngx_pcalloc(pool, sizeof(ngx_http_upstream_degrade_rbtree_node_t));
		if(degrade_node == NULL){
			ngx_log_error(NGX_LOG_ERR, log, 0 ,"[ngx_http_upstream_degrade_add_unchecked_pools]not enough memory.");
			return NGX_ERROR;
		}
		degrade_node->str = *upstream_name;
		degrade_node->node.key = hash;
		degrade_node->upstream_checked = 0;
		//unchecked

		degrade_node->server_count = uscfp[i]->servers->nelts;
		degrade_node->degrate_up_count = uscfp[i]->servers->nelts;
		ngx_rbtree_insert(&tree, (ngx_rbtree_node_t *)degrade_node);
    }

    return NGX_OK;
}


ngx_int_t ngx_http_upstream_degrade_interface_handler(ngx_http_request_t *r)
{
    ngx_int_t       rc;
    ngx_uint_t		size;
    ngx_str_t		type = ngx_string("text/plain");
    ngx_buf_t 		*buf;
    ngx_chain_t 	chain;

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    size = dmcf_global->udshm->upstream_count * ngx_pagesize/4;

    buf = ngx_create_temp_buf(r->pool, size);
    if(buf == NULL){
    	return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    chain.buf = buf;
    chain.next = NULL;

    ngx_http_upstream_degrade_create_return_str(buf);
    buf->last_buf = 1;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_type = type;
    r->headers_out.content_length_n = buf->last - buf->pos;

    rc = ngx_http_send_header(r);
    if(rc == NGX_ERROR || rc > NGX_OK || r->header_only){
    	return rc;
    }

    return ngx_http_output_filter(r, &chain);

}

static void ngx_http_upstream_degrade_create_return_str(ngx_buf_t *buf){

	ngx_http_upstream_degrades_shm_t *dshm = dmcf_global->udshm;
	ngx_uint_t i;

	buf->last = ngx_slprintf(buf->last, buf->end, "%s,%s,%s,%s,%s, %s\n",
			"UPSTREAM_NAME",
			"IS_CHECKED",
			"DEGRADE_STATE",
			"SERVER_COUNT",
			"UP_COUNT",
			"DEGRADE_RATE");

	for(i=0; i<dshm->upstream_count;i++){

		buf->last = ngx_slprintf(buf->last, buf->end, "%V,%s,%ui,%ui,%ui, %ui%%\n",
				&dshm->uds[i].upstream_name,
				dshm->uds[i].upstream_checked ? "checked" : "unchecked",
				dshm->uds[i].degrate_state,
				dshm->uds[i].server_count,
				dshm->uds[i].degrate_up_count,
				dshm->uds[i].degrade_rate);
	}
}

char *
ngx_http_upstream_degrade_interface(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                           *value;
    ngx_http_core_loc_conf_t            *clcf;

    value = cf->args->elts;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_upstream_degrade_interface_handler;

    return NGX_CONF_OK;
}


ngx_dynamic_proxy_pass_module
=============================

A nginx module which supports dynamic proxy_pass
	


降级配置选项：

	Syntax:	upstream_degrade_rate 比率
	Default: 60
	Context:	http, upstream

	Syntax:	upstream_degrate_shm_size	共享内存大小
	Default: 10M
	Context:	http

	Syntax: upstream_degrate_interface
	Default:
	Context: location

	1、查询
		GET http://localhost:port/degrade/status
		或者
		GET http://localhost:port/degrade/status/detail
	2、设置降级状态
		POST http://localhost:port/degrade/force/down?upstreams=${upstreamName},...
		POST http://localhost:port/degrade/force/up?upstreams=${upstreamName},...
		POST http://localhost:port/degrade/force/auto?upstreams=${upstreamName},...






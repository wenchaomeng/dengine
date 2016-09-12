ngx_dynamic_proxy_pass_module
=============================

A nginx module which supports dynamic proxy_pass
	


降级配置选项：

	Syntax:	upstream_degrade_rate 比率
	Default: 60
	Context:	http, upstream

	Syntax: upstream_degrade_force_state 
	Default: 0
	Context: upstream
	取值：0  自动升降级
		  1  强制升级
		  -1 强制降级

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



使用说明：

在下面的配置中，在pool1的可用server比率低于60%时，会自动降级到pool1#BACKUP

upstream pool1{
	server ...;
	upstream_degrade_rate  60;
	upstream_degrade_force_state 0;

 	check interval=3000 rise=2 fall=5 timeout=1000 type=http;
    check_http_send "HEAD / HTTP/1.0\r\n\r\n";
	check_http_expect_alive http_2xx http_3xx;
}

upstream pool1#BACKUP{
}

server {
	dp_domain pool1;
	
	location / {
		proxy_pass http://$dp_upstream;
	}
}


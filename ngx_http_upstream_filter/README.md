upstream过滤
===================================  

支持在upstream调用之前进行请求过滤
过滤方式：调用第三方模块，查看返回值


配置指令
-----------------------------------  
Syntax: auth_filter_config type urlpattern keyname url
Default:
Context: http, upstream

例如：auth_filter_config  oauth ".*" authorization "https://sso.51ping.com/oauth2.0/profile?access_token=%s"

Syntax: auth_filter_config_off type
Default: 
Context: http, upstream


Syntax: auth_filter_config_timeout type timeout
Default: 
Context: http, upstream

timeout: 毫秒

Syntax: auth_filter_open on/off
Default: 
Context: http, upstream

拦截模块是否关闭

Syntax: auth_filter_exception_pass  on/off
Default: 
Context: http, upstream

如果调用第三方模块时出现异常，默认是通过还是不通过

Syntax: auth_filter_pass_pattern pattern1
Default: 
Context: http, upstream

可以通过的url pattern，可以配置多个
upstream中如果配置，将集成http模块中得配置



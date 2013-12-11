--uid = get_cookie("UID");
dp_domain_weight = {};
--f=io.open("/Users/hupeng/log", "a");
--f:write(string.format("%s\n", package.cpath));
local json = require "cjson";
--f:write(string.format("%s\n", "hupengtest!"));
--dp_domain_weight = json.decode("{\"six@1\":\"1\",\"six@2\":\"1\"}");
--for key, value in pairs(dp_domain_weight) do
--	f:write(string.format("%s %s\n", key, value));
--end
--f:close();

function choose_upstream()
	--f=io.open("/Users/hupeng/log", "aw");
	uid = get_ngx_http_variable("cookie_uid");

	--uid = "test";
	--f:write(string.format("%d %d %d\n", uid, #dp_domain_weight, 1));
	--f:write(string.format("%s\n", "hupeng"));
	--f:close();
	if #dp_domain_weight == 0 then
		ups = {get_upstream_list()};
		--for key, value in pairs(ups) do
		--	f:write(string.format("%s %s %d %d\n", key, value, 1, 1));
		--end
		if #ups == 0 then
			return;
		end
		ups_cnt = #ups;
		i = 2;
		bucket_cnt = 0;
		while i <= ups_cnt do
			bucket_cnt = bucket_cnt + ups[i]	
			i = i + 2;
		end
		modus = uid % bucket_cnt;
		--modus = 0;
		--f:write(string.format("%d %d\n", modus, uid));
		i = 2;
		j = 1;
		bucket_search = ups[i];
		while j < ups_cnt do
			if modus < bucket_search then
				upstream = ups[j];
				break;
			end
			i = i + 2;
			bucket_search = bucket_search + ups[i];
			j = j + 2;
		end
	else
		dp_domain_weight_cnt = #dp_domain_weight;
		bucket_cnt = 0;
		for key, value in pairs(dp_domain_weight) do
			bucket_cnt = bucket_cnt + value;
		end
		modus = uid % bucket_cnt;
		bucket_search = 0;
		for key, value in pairs(dp_domain_weight) do
			bucket_search = bucket_search + value;
			if modus < value then
				upstream = key;
				break;
			end
		end

	end
end

function set_dp_domain_weight(str)
	dp_domain_weight = json.decode(str);
end

--f:write(string.format("%s\n", upstream));
--f:write(string.format("%d %d %d\n", uid, bucket_cnt, modus));
--i = 1;
--while i <= #ups do
--	f:write(string.format("%s\n", ups[i]));
--	i = i + 1;
--end
--f:write(string.format("arg_name=%s\n", get_ngx_http_variable("arg_name")));
--f:close();
--upstream = "six@0";

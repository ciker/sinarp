//
//  simply replace the http response data with our costrom data
// Content-Type	text/html; <-- to find 
/*
可配置项：
	替换的次数 -> 标识是 hash(源 ip 源端口 目标 ip 目标端口)  默认一次
	需要替换的 server ip <-- 只替换这个 ip 返回的 http 数据
*/
#include "../../sinarp.h"

/*
check content type info 
*/
BOOL is_right_packet(char *http_header)
{
		
}

BOOL plugin_init()
{
	return TRUE;
}

void *plugin_unload()
{
	return NULL;
}

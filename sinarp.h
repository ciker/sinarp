//这个头文件用于给 插件来调用 。。。
// 把生成的 obj 文件打包成一个 lib 文件来给插件调用
#ifdef WIN32
#define _WSPIAPI_COUNTOF
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
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

typedef unsigned int uint32;
typedef unsigned short uint16;
typedef unsigned char uint8;

#ifndef WIN32
typedef uint32 BOOL;
#define TRUE 1
#define FALSE 0
#define ZeroMemory(Destination,Length) memset((Destination),0,(Length))
#define stricmp strcasecmp
#else
#define snprintf _snprintf
#endif

#define MTU 1500  //网络最大传输单元

//#define  DBG_MSG(fmt,...) {\  // VS 2010 才支持这个 宏
// fprintf(stderr,"[DEBUG] "fmt,__VA_ARGS__);}

#define SAFE_FREE(x) do{ if(x) { free(x); x = NULL; } }while(0)
#define LLADDR(s) ((caddr_t)((s)->sdl_data + (s)->sdl_nlen))

/*
wpcap.dll
pcap_perror
pcap_sendpacket
pcap_next_ex
pcap_freealldevs
pcap_close
pcap_breakloop
pcap_open_live
pcap_findalldevs
*/

//-------- pcap func define -----


//--- proto define -----

#define ETHERTYPE_IP    0x0800
#define ETHERTYPE_ARP   0x0806
#define ARP_REPLY    0x0002         /* ARP reply */
#define ARP_REQUEST  0x0001  /* arp request */
#define ARPHRD_ETHER    1
#define ARP_LEN        60  //  抓包看了下 都是 60 啊
#define HEAD_LEN           54
#define TCP_MAXLEN       1460
#define PACKET_MAXLEN    1514
// 协议
#define PROTO_TCP     0x6
#define PROTO_UDP     0x11

typedef uint8 u_char;

#pragma pack(push, 1)//取消内存大小自动对齐

typedef struct ip_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
} ip_address;

typedef struct _ETHeader         // 14字节的以太头
{
    uint8   dhost[6];           // 目的MAC地址destination mac address
    uint8   shost[6];           // 源MAC地址source mac address
    uint16  type;               // 下层协议类型，如IP（ETHERTYPE_IP）、ARP（ETHERTYPE_ARP）等
} ETHeader, *PETHeader;

typedef struct _ARPHeader       // 28字节的ARP头
{
    uint16  hrd;                //  硬件地址空间，以太网中为ARPHRD_ETHER
    uint16  eth_type;           //  以太网类型，ETHERTYPE_IP ？？
    uint8   maclen;             //  MAC地址的长度，为6
    uint8   iplen;              //  IP地址的长度，为4
    uint16  opcode;             //  操作代码，ARPOP_REQUEST为请求，ARPOP_REPLY为响应
    uint8   smac[6];            //  源MAC地址
    uint32  saddr;          //  源IP地址
    uint8   dmac[6];            //  目的MAC地址
    uint32  daddr;          //  目的IP地址
} ARPHeader, *PARPHeader;

typedef struct _ARP_PACKET
{
    ETHeader ethdr;
    ARPHeader arphdr;
    uint8 unused[6];//填充ARP_PACKET 到ARP_LEN
} ARP_PACKET;

typedef struct _IPHeader        // 20字节的IP头
{
    uint8     iphVerLen;      // 版本号和头长度（各占4位）
    uint8     ipTOS;          // 服务类型
    uint16    ipLength;       // 封包总长度，即整个IP报的长度
    uint16    ipID;           // 封包标识，惟一标识发送的每一个数据报
    uint16    ipFlags;        // 标志
    uint8     ipTTL;          // 生存时间，就是TTL
    uint8     ipProtocol;     // 协议，可能是TCP、UDP、ICMP等
    uint16    ipChecksum;     // 校验和
    union
    {
        unsigned int   ipSource;
        ip_address ipSourceByte;
    };
    union
    {
        unsigned int   ipDestination;
        ip_address ipDestinationByte;
    };
} IPHeader, *PIPHeader;

typedef struct _TCPHeader       // 20字节的TCP头
{
    uint16  sourcePort;         // 16位源端口号
    uint16  destinationPort;    // 16位目的端口号
    uint32  sequenceNumber;     // 32位序列号
    uint32  acknowledgeNumber;  // 32位确认号
    uint8   dataoffset;         // 高4位表示数据偏移
    uint8   flags;              // 6位标志位
    //FIN - 0x01
    //SYN - 0x02
    //RST - 0x04
    //PUSH- 0x08
    //ACK- 0x10
    //URG- 0x20
    //ACE- 0x40
    //CWR- 0x80
    uint16  windows;            // 16位窗口大小
    uint16  checksum;           // 16位校验和
    uint16  urgentPointer;      // 16位紧急数据偏移量
} TCPHeader, *PTCPHeader;

typedef struct _udphdr  //定义UDP首部
{
    unsigned short uh_sport;    //16位源端口
    unsigned short uh_dport;    //16位目的端口
    unsigned short uh_len;  //16位长度
    unsigned short uh_sum;  //16位校验和
} UDPHEADER, *PUDPHeader;

typedef struct _ACKPacket
{
    ETHeader    eh;
    IPHeader    ih;
    TCPHeader   th;
} ACKPacket;

typedef struct _psd
{
    unsigned int   saddr;
    unsigned int   daddr;
    char           mbz;
    char           ptcl;
    unsigned short udpl;
} PSD, *PPSD;

typedef struct _dns
{
    unsigned short id;  //标识，通过它客户端可以将DNS的请求与应答相匹配；
    unsigned short flags;  //标志：[QR | opcode | AA| TC| RD| RA | zero | rcode ]
    //1 & htons(0x8000)
    //4 & htons(0x7800)
    //1 & htons(0x400)
    //1 & htons(0x200)
    //1 & htons(0x100)
    //1 & htons(0x80)
    //3
    //4 & htons(0xF)
    unsigned short quests;  //问题数目；
    unsigned short answers;  //资源记录数目；
    unsigned short author;  //授权资源记录数目；
    unsigned short addition;  //额外资源记录数目；
} TCPIP_DNS, *PDNS;
//在16位的标志中：QR位判断是查询/响应报文，opcode区别查询类型，AA判断是否为授权回答，TC判断是否可截断，RD判断是否期望递归查询，RA判断是否为可用递归，zero必须为0，rcode为返回码字段。

//DNS查询数据报：
typedef struct query
{
    //unsigned char  *name;  //查询的域名,不定长,这是一个大小在0到63之间的字符串；
    unsigned short type;  //查询类型，大约有20个不同的类型
    unsigned short classes;  //查询类,通常是A类既查询IP地址。
} QUERY, *PQUERY;

//DNS响应数据报：
typedef struct response
{
    unsigned short name;   //查询的域名
    unsigned short type;  //查询类型
    unsigned short classes;  //类型码
    unsigned int   ttl;  //生存时间
    unsigned short length;  //资源数据长度
    unsigned int   addr;  //资源数据
} RESPONSE, *PRESPONSE;

#pragma pack(pop)


typedef enum _host_type
{
    HOST_UNKNOWN = 0,
    HOST_A,
    HOST_B
} host_type;

typedef enum _spoof_type
{
    SPOOF_A,
    SPOOF_AB,
    SPOOF_NONE // no arp spoof 
} spoof_type;


typedef struct _Host
{
    uint32    ip;
    uint8     mac[6];
    uint8     active;
    host_type type;
} Host;

typedef struct _HostList
{
    Host *pHost;
    uint32 HostCount;
} HostList;

typedef struct _plugin_info
{
    const char *name;
    BOOL ( *process_packet)(ETHeader *, uint32); //插件过滤数据包的函数
    BOOL (* plugin_init)();//插件初始化
    void *(* plugin_unload)();//插件被卸载
} plugin_info;

typedef struct _plugin_list
{
    plugin_info *plugin;
    uint32 count;
} plugin_list;

//pcap 的函数调用类型是的
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



char    *sinarp_iptos(u_long in);
BOOL  sinarp_build_tcp_response_packet(ETHeader *ethdr, uint8 *packet, uint32 *psize, uint8 *data, uint32 size);
/*
构建一个 ARP 数据包
*/
int  sinarp_build_arp_packet(\
                             ARP_PACKET *arp_packet,
                             uint16 arp_opcode,//要发送的ARP包的类型
                             uint8 src_mac[6],
                             uint8 dst_mac[6],
                             uint8 arp_src_mac[6],
                             uint32 arp_src_ip,
                             uint8 arp_dst_mac[6],
                             uint32 arp_dst_ip);
/*
发送 ARP 请求包 用于重新获得 DestIp 的MAC地址
*/
BOOL  sinarp_send_arp(uint32 DestIP);
/*
告诉 spoof_ip ip 对应的 MAC 是 mac
*/
BOOL   sinarp_arp_spoof(uint32 spoof_ip, uint8 *spoof_mac, uint32 ip, uint8 *mac);

//
// 计算tcp udp检验和的函数
//
void  sinarp_checksum(IPHeader *pIphdr);

// from NetFuke Source
// 内存匹配函数memfind
// 基于BM算法
// 作者:周霖 KCN
// modified by shadow @2007/03/18
void  *sinarp_memfind( const void      *in_block,       /* 数据块 */
                       const size_t  block_size,     /* 数据块长度 */
                       const void       *in_pattern,     /* 需要查找的数据 */
                       const size_t  pattern_size,   /* 查找数据的长度 */
                       size_t           *shift_table,    /* 移位表，应该是256*size_t的数组 */
                       BOOL          b_init );       /* 是否需要初始化移位表 */

/*
根据输入的 数据包 生成一个回复包 。
packet 是传入的缓冲区大小用于存放数据包  最后的数据包大小不会超过 MTU 即 1500
psize 用于接收数据包的大小
data 要写入的 tcp 数据
size 是tcp数据的长度
*/
BOOL  sinarp_build_tcp_response_packet(ETHeader *ethdr, uint8 *packet, uint32 *psize, uint8 *data, uint32 size);
/*
处理要转发的数据包
*/
BOOL  sinarp_process_packet(ETHeader *ethdr , uint32 packet_len);

//修正包的mac地址 用于转发
void  sinarp_forward_fix_packet(ETHeader *packet);

uint32  sinarp_hostname_to_ip(char *hostname);

int  sinarp_parse_host_string(const char *host_string, host_type type);

char   *sinarp_iptos(u_long in);  //ip 到 字符串形式的 ip

const char   *sinarp_take_out_string_by_char(const char *Source, char *Dest, int buflen, char ch);

void  sinarp_printf(const char *fmt, ...);

BOOL  sinarp_find_string_by_flag(
    const char        *p_szContent,
    const char        *p_szFlag1,
    const char        *p_szFlag2,
    char          *p_szValue,
    const uint32   i4_ValuseSize
);

char   *sinarp_get_mac_by_ip(uint32 ip);

/*
加载插件
*/
BOOL  sinarp_load_plugin(const char *szPluginName);
void  sinarp_ifprint(pcap_if_t *d);

/*
加载文件的内容到内存 返回申请的内存 要使用 free 释放 ~~
*/
uint8 *sinarp_load_file_into_mem(const char *file);

#ifdef WIN32
void sinarp_create_thread(DWORD (__stdcall *func)(void *), void *lparam);
#else //for Linux 
void sinarp_create_thread(void * ( *func)(void *), void *lparam);
#endif

#ifdef WIN32
#else
void Sleep(uint32 msec);
#endif

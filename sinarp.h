//���ͷ�ļ����ڸ� ��������� ������
// �����ɵ� obj �ļ������һ�� lib �ļ������������ 

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

#define MTU 1500  //��������䵥Ԫ

void DBG_MSG(const char *fmt,...)
{
    va_list args;
    int n;
    char TempBuf[8192];
    va_start(args, fmt);
    n = vsprintf(TempBuf, fmt, args);
    printf("%s",TempBuf);
    va_end(args);
}

//#define  DBG_MSG(fmt,...) {\  // VS 2010 ��֧����� �� 
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
#define	ARP_REPLY	 0x0002			/* ARP reply */
#define ARP_REQUEST  0x0001  /* arp request */
#define ARPHRD_ETHER 	1
#define ARP_LEN		 48
#define HEAD_LEN           54
#define TCP_MAXLEN       1460
#define PACKET_MAXLEN    1514
// Э��
#define PROTO_TCP     0x6
#define PROTO_UDP     0x11

typedef uint8 u_char;

#pragma pack(push, 1)//ȡ���ڴ��С�Զ�����

typedef struct ip_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

typedef struct _ETHeader         // 14�ֽڵ���̫ͷ
{
    uint8	dhost[6];			// Ŀ��MAC��ַdestination mac address
    uint8	shost[6];			// ԴMAC��ַsource mac address
    uint16	type;				// �²�Э�����ͣ���IP��ETHERTYPE_IP����ARP��ETHERTYPE_ARP����
} ETHeader, *PETHeader;

typedef struct _ARPHeader		// 28�ֽڵ�ARPͷ
{
    uint16	hrd;				//	Ӳ����ַ�ռ䣬��̫����ΪARPHRD_ETHER
    uint16	eth_type;			//  ��̫�����ͣ�ETHERTYPE_IP ����
    uint8	maclen;				//	MAC��ַ�ĳ��ȣ�Ϊ6
    uint8	iplen;				//	IP��ַ�ĳ��ȣ�Ϊ4
    uint16	opcode;				//	�������룬ARPOP_REQUESTΪ����ARPOP_REPLYΪ��Ӧ
    uint8	smac[6];			//	ԴMAC��ַ
    uint32	saddr;			//	ԴIP��ַ
    uint8	dmac[6];			//	Ŀ��MAC��ַ
    uint32	daddr;			//	Ŀ��IP��ַ
} ARPHeader, *PARPHeader;

typedef struct _ARP_PACKET
{
    ETHeader ethdr;
    ARPHeader arphdr;
    uint8 unused[6];//���ARP_PACKET ��ARP_LEN
}ARP_PACKET;

typedef struct _IPHeader		// 20�ֽڵ�IPͷ
{
    uint8     iphVerLen;      // �汾�ź�ͷ���ȣ���ռ4λ��
    uint8     ipTOS;          // �������� 
    uint16    ipLength;       // ����ܳ��ȣ�������IP���ĳ���
    uint16    ipID;			  // �����ʶ��Ωһ��ʶ���͵�ÿһ�����ݱ�
    uint16    ipFlags;	      // ��־
    uint8     ipTTL;	      // ����ʱ�䣬����TTL
    uint8     ipProtocol;     // Э�飬������TCP��UDP��ICMP��
    uint16    ipChecksum;     // У���
    union {
        unsigned int   ipSource;
        ip_address ipSourceByte;
    };
    union {
        unsigned int   ipDestination;
        ip_address ipDestinationByte;
    };
} IPHeader, *PIPHeader; 

typedef struct _TCPHeader		// 20�ֽڵ�TCPͷ
{
    uint16	sourcePort;			// 16λԴ�˿ں�
    uint16	destinationPort;	// 16λĿ�Ķ˿ں�
    uint32	sequenceNumber;		// 32λ���к�
    uint32	acknowledgeNumber;	// 32λȷ�Ϻ�
    uint8	dataoffset;			// ��4λ��ʾ����ƫ��
    uint8	flags;				// 6λ��־λ
    //FIN - 0x01
    //SYN - 0x02
    //RST - 0x04 
    //PUSH- 0x08
    //ACK- 0x10
    //URG- 0x20
    //ACE- 0x40
    //CWR- 0x80
    uint16	windows;			// 16λ���ڴ�С
    uint16	checksum;			// 16λУ���
    uint16	urgentPointer;		// 16λ��������ƫ���� 
} TCPHeader, *PTCPHeader;

typedef struct _udphdr	//����UDP�ײ� 
{ 
    unsigned short uh_sport;	//16λԴ�˿� 
    unsigned short uh_dport;	//16λĿ�Ķ˿� 
    unsigned short uh_len;	//16λ���� 
    unsigned short uh_sum;	//16λУ��� 
}UDPHEADER, *PUDPHeader;

typedef struct _ACKPacket
{
    ETHeader	eh;
    IPHeader	ih;
    TCPHeader	th;
}ACKPacket;

typedef struct _psd
{
    unsigned int   saddr;
    unsigned int   daddr;
    char           mbz;
    char           ptcl;
    unsigned short udpl;
}PSD,*PPSD;

typedef struct _dns
{
    unsigned short id;  //��ʶ��ͨ�����ͻ��˿��Խ�DNS��������Ӧ����ƥ�䣻
    unsigned short flags;  //��־��[QR | opcode | AA| TC| RD| RA | zero | rcode ]
    //1 & htons(0x8000)
    //4 & htons(0x7800)
    //1 & htons(0x400)
    //1 & htons(0x200)
    //1 & htons(0x100)
    //1 & htons(0x80)
    //3
    //4 & htons(0xF)
    unsigned short quests;  //������Ŀ��
    unsigned short answers;  //��Դ��¼��Ŀ��
    unsigned short author;  //��Ȩ��Դ��¼��Ŀ��
    unsigned short addition;  //������Դ��¼��Ŀ��
}TCPIP_DNS,*PDNS;
//��16λ�ı�־�У�QRλ�ж��ǲ�ѯ/��Ӧ���ģ�opcode�����ѯ���ͣ�AA�ж��Ƿ�Ϊ��Ȩ�ش�TC�ж��Ƿ�ɽضϣ�RD�ж��Ƿ������ݹ��ѯ��RA�ж��Ƿ�Ϊ���õݹ飬zero����Ϊ0��rcodeΪ�������ֶΡ�

//DNS��ѯ���ݱ���
typedef struct query
{
    //unsigned char  *name;  //��ѯ������,������,����һ����С��0��63֮����ַ�����
    unsigned short type;  //��ѯ���ͣ���Լ��20����ͬ������
    unsigned short classes;  //��ѯ��,ͨ����A��Ȳ�ѯIP��ַ��
}QUERY,*PQUERY;

//DNS��Ӧ���ݱ���
typedef struct response
{
    unsigned short name;   //��ѯ������
    unsigned short type;  //��ѯ����
    unsigned short classes;  //������
    unsigned int   ttl;  //����ʱ��
    unsigned short length;  //��Դ���ݳ���
    unsigned int   addr;  //��Դ����
}RESPONSE,*PRESPONSE;

#pragma pack(pop)


typedef enum _host_type
{
    HOST_UNKNOWN = 0,
		HOST_A,
		HOST_B
}host_type;

typedef enum _spoof_type
{
    SPOOF_A,
		SPOOF_AB
}spoof_type;


typedef struct _Host
{
    uint32    ip;
    uint8     mac[6];
    uint8     active;
    host_type type;
}Host;

typedef struct _HostList
{
    Host *pHost;
    uint32 HostCount;
}HostList;

typedef struct _plugin_info
{
    const char *name;
    BOOL ( *process_packet)(ETHeader *,uint32);//����������ݰ��ĺ���
	BOOL (* plugin_init)();//�����ʼ��
	void* (* plugin_unload)();//�����ж��
}plugin_info;

typedef struct _plugin_list
{
    plugin_info *plugin;
    uint32 count;
}plugin_list;

//pcap �ĺ������������ǵ�
void  ( * pf_pcap_perror)(pcap_t *p, char *prefix);
int  ( * pf_pcap_sendpacket)(pcap_t * p,u_char *  buf,int size);
int ( * pf_pcap_next_ex)(pcap_t *p, struct pcap_pkthdr **pkt_header, const u_char **pkt_data);
void ( * pf_pcap_freealldevs)( pcap_if_t *  alldevsp );
void ( * pf_pcap_close)(pcap_t *p);
void ( * pf_pcap_breakloop)(pcap_t * );
int	( * pf_pcap_loop)(pcap_t *, int, pcap_handler, u_char *);
pcap_t* ( * pf_pcap_open_live)(const char * device,
							   int  	snaplen,
							   int  	promisc,
							   int  	to_ms,
							   char *  	ebuf);
int	( * pf_pcap_findalldevs)(pcap_if_t **, char *);
int ( *pf_pcap_compile)(pcap_t *, struct bpf_program *, const char *, int, bpf_u_int32);
int ( *pf_pcap_setfilter)(pcap_t *, struct bpf_program *);


//----------  global var
pcap_t * g_adhandle = NULL; // �������
char g_opened_if_name[256] = {0};//�򿨵��������� ��Ϊ��ʱ������Ҫ֪�� �򿪵����Ŀ����� ��������Ҫ���������
uint32 g_interval = 3000;//3 s ��ƭһ��
spoof_type g_spoof_type = SPOOF_AB; //Ĭ����˫����ƭ
Host  g_HostList[256] = {0}; //ע��Ҫȫ����ʼ��Ϊ 0
uint32 g_my_ip = 0;  // �Լ��� ip Ҳ�����м��˵� ip
uint8  g_my_mac[6] = {0}; //�Լ��� mac Ҳ�����м��˵� mac
uint32 g_my_netmask = 0; //��������
uint32 g_my_boardcast_addr = 0; //�㲥��ַ
uint32	 g_my_gw_addr;//���صĵ�ַ
uint8   g_my_gw_mac[6]={0xFF}; //���ص� mac ��ַ
uint8	g_broadcast_mac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}; //���������ڹ㲥�� MAC ��ַ
uint8	g_zero_mac[6] = {0x00,0x00,0x00,0x00,0x00,0x00};
volatile uint32 g_is_capture_thread_active = 0;// ==0 �̷߳ǻ�� 
volatile uint32 g_is_spoof_thread_active = 0;
volatile uint32 g_is_time_shutdown = 0;//�������߳��ǲ�����Ҫ�ر�
volatile int64_t g_packet_count = 0;//���ݰ�����
volatile uint32 g_auto_ip_forward = 1;//Ĭ�Ͽ���ת��
plugin_list g_plugin_list={0};

char *   sinarp_iptos(u_long in);
BOOL  sinarp_build_tcp_response_packet(ETHeader *ethdr,uint8 *packet,uint32 * psize,uint8 *data,uint32 size);
/*
����һ�� ARP ���ݰ�
*/
int  sinarp_build_arp_packet(\
							 ARP_PACKET *arp_packet,
							 uint16 arp_opcode,//Ҫ���͵�ARP��������  
							 uint8 src_mac[6],
							 uint8 dst_mac[6],
							 uint8 arp_src_mac[6],
							 uint32 arp_src_ip,
							 uint8 arp_dst_mac[6],
							 uint32 arp_dst_ip);
							 /*
							 ���� ARP ����� �������»�� DestIp ��MAC��ַ
*/
BOOL  sinarp_send_arp(uint32 DestIP);
/*
���� spoof_ip ip ��Ӧ�� MAC �� mac
*/
BOOL   sinarp_arp_spoof(uint32 spoof_ip,uint8 *spoof_mac,uint32 ip,uint8 *mac);

//
// ����tcp udp����͵ĺ���
// 
void  sinarp_checksum(IPHeader *pIphdr);

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
					  BOOL			b_init );		/* �Ƿ���Ҫ��ʼ����λ�� */

													/*
													��������� ���ݰ� ����һ���ظ��� ��
													packet �Ǵ���Ļ�������С���ڴ�����ݰ�  �������ݰ���С���ᳬ�� MTU �� 1500
													psize ���ڽ������ݰ��Ĵ�С
													data Ҫд��� tcp ����
													size ��tcp���ݵĳ���
*/
BOOL  sinarp_build_tcp_response_packet(ETHeader *ethdr,uint8 *packet,uint32 * psize,uint8 *data,uint32 size);
/*
����Ҫת�������ݰ�
*/
BOOL  sinarp_process_packet(ETHeader *ethdr ,uint32 packet_len);

//��������mac��ַ ����ת��
void  sinarp_forward_fix_packet(ETHeader *packet);

uint32  sinarp_hostname_to_ip(char * hostname);

int  sinarp_parse_host_string(const char *host_string,host_type type);

char *  sinarp_iptos(u_long in);  //ip �� �ַ�����ʽ�� ip 

const char *  sinarp_take_out_string_by_char(const char *Source,char *Dest, int buflen, char ch);

void  sinarp_printf(const char * fmt,...);

BOOL  sinarp_find_string_by_flag(
								 const char*		p_szContent,
								 const char*		p_szFlag1,
								 const char*		p_szFlag2,
								 char*			p_szValue,
								 const uint32	i4_ValuseSize
								 );

char *  sinarp_get_mac_by_ip(uint32 ip);

/*
���ز��
*/
BOOL  sinarp_load_plugin(const char *szPluginName);
void  sinarp_ifprint(pcap_if_t *d);

/*
�����ļ������ݵ��ڴ� ����������ڴ� Ҫʹ�� free �ͷ� ~~
*/
uint8 *sinarp_load_file_into_mem(const char *file);

#ifdef WIN32
void sinarp_create_thread(DWORD (__stdcall *func)(void *),void *lparam);
#else //for Linux 
void sinarp_create_thread(void* ( *func)(void *),void *lparam);
#endif

#ifdef WIN32
#else
void Sleep(uint32 msec);
#endif

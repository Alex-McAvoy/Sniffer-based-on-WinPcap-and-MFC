
// SnifferDlg.h: 头文件
//

#pragma once
#include "pcap.h"
#include "protocol.h"


// CSnifferDlg 对话框
class CSnifferDlg : public CDialogEx
{
// 构造
public:
	CSnifferDlg(CWnd* pParent = nullptr);	// 标准构造函数

	/*********************************WinPcap抓包框架*********************************/
	int Sniffer_initCap();//初始化WinPcap
	int Sniffer_startCap();//捕获信息

	int devCount;//网卡计数器
	char errorBufffer[PCAP_ERRBUF_SIZE];//错误缓冲区
	pcap_if_t *allDevs;//设备列表指针
	pcap_if_t *dev;//设备指针
	pcap_t *catchHandle;//捕获句柄

	char filePath[1024];//文件路径
	char fileName[1024];//文件名称
	pcap_dumper_t *dumpFile;//存储网络数据的文件描述符

	/*********************************数据包接收线程*********************************/
	HANDLE m_ThreadHandle;//接收数据线程句柄
	struct packet_count packetCount;//各类包计数器
	int packetNum;//包统计
	CPtrList m_localDataList;//保存本地化的数据包
	CPtrList m_netDataList;//保存网络中获取的数据包

	int Sniffer_updatePacket();//更新数据包
	int Sniffer_updateList(struct pcap_pkthdr *data_header, struct data_packet *data, const u_char *pkt_data);//更新列表
	/*********************************GUI数据更新函数*********************************/
	int Sniffer_saveFile();//保存文件
	int Sniffer_readFile(CString path);//读取文件
	int Sniffer_updateEdit(int index);//更新编辑框
	void print_packet_hex(const u_char* packet, int packet_size, CString *bufffer);//编辑框数据格式化显示
	int Sniffer_updateTree(int index);//更新树形框

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SNIFFER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	/*********************************控件变量*********************************/
	CComboBox m_comboBoxNetCard;//网卡下拉框控件
	CComboBox m_comboBoxFilterRule;//过滤规则下拉框控件
	CListCtrl m_listCtrl;//列表控件
	CTreeCtrl m_treeCtrl;//树形控件
	CEdit m_edit;//编辑控件
	CButton m_buttonStart;//开始按钮控件
	CButton m_buttonStop;//结束按钮控件
	CButton m_buttonSave;//保存按钮控件
	CButton m_buttonRead;//读取按钮控件
	CEdit m_editARP;//ARP编辑控件
	CEdit m_editIPv4;//IPv4编辑控件
	CEdit m_editIPv6;//IPv6编辑控件
	CEdit m_editICMPv4;//ICMPv4编辑控件
	CEdit m_editICMPv6;//ICMPv6编辑控件
	CEdit m_editUDP;//UDP编辑控件
	CEdit m_editTCP;//TCP编辑控件
	CEdit m_editHTTP;//HTTP编辑控件
	CEdit m_editOther;//其他编辑控件
	CEdit m_editSum;//总计编辑控件
	
	/*********************************消息处理函数*********************************/
	afx_msg void OnBnClickedButton1();//开始按钮
	afx_msg void OnBnClickedButton2();//结束按钮
	afx_msg void OnBnClickedButton3();//保存按钮
	afx_msg void OnBnClickedButton4();//结束按钮
	afx_msg void OnLvnItemchangedList1(NMHDR *pNMHDR, LRESULT *pResult);//列表更新
	afx_msg void OnNMCustomdrawList1(NMHDR *pNMHDR, LRESULT *pResult);//列表项颜色变换
};

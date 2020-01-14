
// SnifferDlg.cpp: 实现文件
//

#include "stdafx.h"
#include "Sniffer.h"
#include "SnifferDlg.h"
#include "afxdialogex.h"
#include "pcap.h"
#include "protocol.h"
#include "analysis.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

DWORD WINAPI Sniffer_capThread(LPVOID lpParameter);//线程函数

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CSnifferDlg 对话框



CSnifferDlg::CSnifferDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_SNIFFER_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CSnifferDlg::DoDataExchange(CDataExchange* pDX) {
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO1, m_comboBoxNetCard);
	DDX_Control(pDX, IDC_COMBO2, m_comboBoxFilterRule);
	DDX_Control(pDX, IDC_LIST1, m_listCtrl);
	DDX_Control(pDX, IDC_TREE1, m_treeCtrl);
	DDX_Control(pDX, IDC_EDIT1, m_edit);
	DDX_Control(pDX, IDC_BUTTON1, m_buttonStart);
	DDX_Control(pDX, IDC_BUTTON2, m_buttonStop);
	DDX_Control(pDX, IDC_BUTTON3, m_buttonSave);
	DDX_Control(pDX, IDC_BUTTON4, m_buttonRead);
	DDX_Control(pDX, IDC_EDIT2, m_editARP);
	DDX_Control(pDX, IDC_EDIT3, m_editIPv4);
	DDX_Control(pDX, IDC_EDIT4, m_editIPv6);
	DDX_Control(pDX, IDC_EDIT5, m_editICMPv4);
	DDX_Control(pDX, IDC_EDIT6, m_editICMPv6);
	DDX_Control(pDX, IDC_EDIT7, m_editUDP);
	DDX_Control(pDX, IDC_EDIT8, m_editTCP);
	DDX_Control(pDX, IDC_EDIT9, m_editHTTP);
	DDX_Control(pDX, IDC_EDIT10, m_editOther);
	DDX_Control(pDX, IDC_EDIT11, m_editSum);
}

BEGIN_MESSAGE_MAP(CSnifferDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	/*********************************消息处理函数*********************************/
	ON_BN_CLICKED(IDC_BUTTON1, &CSnifferDlg::OnBnClickedButton1)//开始按钮
	ON_BN_CLICKED(IDC_BUTTON2, &CSnifferDlg::OnBnClickedButton2)//结束按钮
	ON_BN_CLICKED(IDC_BUTTON3, &CSnifferDlg::OnBnClickedButton3)//保存按钮
	ON_BN_CLICKED(IDC_BUTTON4, &CSnifferDlg::OnBnClickedButton4)//读取按钮
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST1, &CSnifferDlg::OnLvnItemchangedList1)//列表更新
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST1, &CSnifferDlg::OnNMCustomdrawList1)//列表项颜色变换
END_MESSAGE_MAP()


// CSnifferDlg 消息处理程序

/*********************************GUI初始化设置*********************************/
BOOL CSnifferDlg::OnInitDialog() {
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标



	// TODO: 在此添加额外的初始化代码

	//列表表项初始化设置
	m_listCtrl.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	m_listCtrl.InsertColumn(0, "编号", 2, 50);//1右对齐，2居中，3左对齐
	m_listCtrl.InsertColumn(1, "时间", 2, 200);
	m_listCtrl.InsertColumn(2, "长度", 2, 100);
	m_listCtrl.InsertColumn(3, "源MAC地址", 2, 200);
	m_listCtrl.InsertColumn(4, "目的MAC地址", 2, 200);
	m_listCtrl.InsertColumn(5, "协议", 2, 100);
	m_listCtrl.InsertColumn(6, "源IP地址", 2, 150);
	m_listCtrl.InsertColumn(7, "目的IP地址", 2, 150);

	//下拉框初始化设置
	m_comboBoxNetCard.AddString("请选择网卡接口");//网卡默认选项
	m_comboBoxFilterRule.AddString("请选择过滤规则");//过滤规则默认选项
	if (Sniffer_initCap() < 0) //初始化WinPcap
		return FALSE;
	for (dev = allDevs; dev; dev = dev->next) //将可用网卡添加进网卡候选栏
		if (dev->description)
			m_comboBoxNetCard.AddString(dev->description);
	
	m_comboBoxFilterRule.AddString("TCP");//将TCP添加进过滤规则候选栏
	m_comboBoxFilterRule.AddString("UDP");//将UDP添加进过滤规则候选栏
	m_comboBoxFilterRule.AddString("IP");//将IP添加进过滤规则候选栏
	m_comboBoxFilterRule.AddString("ICMP");//将ICMP添加进过滤规则候选栏
	m_comboBoxFilterRule.AddString("ARP");//将ARP添加进过滤规则候选栏

	m_comboBoxNetCard.SetCurSel(0);//显示默认选项
	m_comboBoxFilterRule.SetCurSel(0);//显示默认选项

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}


void CSnifferDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CSnifferDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CSnifferDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

/*********************************WinPcap抓包框架*********************************/
// 1).初始化WinPcap
int CSnifferDlg::Sniffer_initCap() {
	devCount = 0;
	if (pcap_findalldevs(&allDevs, errorBufffer) == -1)//获得网卡接口信息
		return -1;
	for (dev = allDevs; dev; dev = dev->next)//记录设备数
		devCount++;
	return 0;
}

// 2).捕获数据包
int CSnifferDlg::Sniffer_startCap() {
	//步骤①：网卡与过滤器设置
	int netCardIndex = this->m_comboBoxNetCard.GetCurSel();//网卡接口索引
	int filterIndex = this->m_comboBoxFilterRule.GetCurSel();//过滤器索引
	if (netCardIndex == 0 || netCardIndex == CB_ERR) {
		MessageBox("请选择网卡接口");
		return -1;
	}
	if (filterIndex == CB_ERR) {
		MessageBox("过滤器选择错误");
		return -1;
	}


	//步骤②：获取选中的网卡接口
	dev = allDevs;
	for (int i = 0; i < filterIndex - 1; i++)
		dev = dev->next;


	//步骤③：打开网卡指定接口
	int dataPackageLen = 65536;//捕获数据包长度
	int overtime = 1000;//读超时时间
	int flag = 1;//网卡混淆模式设置标志，非0即为混淆模式
	catchHandle = pcap_open_live(dev->name, dataPackageLen, flag, overtime, errorBufffer);//针对指定网络接口创建一捕获句柄，用于后续捕获数据
	if (catchHandle == NULL) {
		MessageBox("无法打开接口：" + CString(dev->description));
		pcap_freealldevs(allDevs);//释放设备列表
		return -1;
	}


	//步骤④：检查是否为非以太网
	if (pcap_datalink(catchHandle) != DLT_EN10MB) {
		MessageBox("不适合非以太网的网络");
		pcap_freealldevs(allDevs);//释放设备列表
		return -1;
	}


	//步骤⑤：设置子网掩码
	u_int netmask;//子网掩码
	if (dev->addresses != NULL)
		netmask = ((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		netmask = 0xffffff;


	//步骤⑥：编译过滤器
	struct bpf_program fcode;//BPF过滤代码结构
	if (filterIndex == 0) {
		char filter[] = "";
		if (pcap_compile(catchHandle, &fcode, filter, 1, netmask) < 0) {
			MessageBox("语法错误，无法编译过滤器");
			pcap_freealldevs(allDevs);//释放设备列表
			return -1;
		}
	}
	else {
		CString str;
		this->m_comboBoxFilterRule.GetLBText(filterIndex, str);
		int len = str.GetLength() + 1;
		char *filter = (char*)malloc(len);
		for (int i = 0; i < len; i++)
			filter[i] = str.GetAt(i);
		if (pcap_compile(catchHandle, &fcode, filter, 1, netmask) < 0) {
			MessageBox("语法错误，无法编译过滤器");
			pcap_freealldevs(allDevs);//释放设备列表
			return -1;
		}
	}


	//步骤⑦：设置过滤器
	if (pcap_setfilter(catchHandle, &fcode) < 0) {
		MessageBox("设置过滤器错误");
		pcap_freealldevs(allDevs);//释放设备列表
		return -1;
	}


	//步骤⑧：设置时间
	struct tm *localTime;//年月日结构的时间
	time_t secondTime;//自1970至今多少秒的时间
	time(&secondTime);
	localTime = localtime(&secondTime);
	char realTime[30];//当前时间
	strftime(realTime, sizeof(realTime), "%Y%m%d %H%M%S", localTime);//格式化本地时间


	//步骤⑨：设置数据包存储路径
	CFileFind file;
	if (!file.FindFile("Data"))
		CreateDirectory("Data", NULL);
	memset(filePath, 0, sizeof(filePath));
	memset(fileName, 0, sizeof(fileName));
	strcpy(filePath, "Data\\");
	strcat(fileName, realTime);
	strcat(fileName, ".lix");
	strcat(filePath, fileName);
	dumpFile = pcap_dump_open(catchHandle, filePath);
	if (dumpFile == NULL){
		MessageBox("文件创建错误！");
		return -1;
	}


	//步骤⑩：创建数据包接收线程
	LPDWORD threadCap = NULL;
	m_ThreadHandle = CreateThread(NULL, 0, Sniffer_capThread, this, 0, threadCap);
	if (m_ThreadHandle == NULL)	{
		CString str;
		str.Format("创建线程错误，代码为：%d.", GetLastError());
		MessageBox(str);
		return -1;
	}
	return 1;
}


/*********************************数据包接收线程*********************************/
// 1).更新数据包
int CSnifferDlg::Sniffer_updatePacket() {
	CString str;
	str.Format("%d", this->packetCount.num_arp);
	this->m_editARP.SetWindowText(str);

	str.Format("%d", this->packetCount.num_ip4);
	this->m_editIPv4.SetWindowText(str);

	str.Format("%d", this->packetCount.num_ip6);
	this->m_editIPv6.SetWindowText(str);

	str.Format("%d", this->packetCount.num_icmp4);
	this->m_editICMPv4.SetWindowText(str);

	str.Format("%d", this->packetCount.num_icmp6);
	this->m_editICMPv6.SetWindowText(str);

	str.Format("%d", this->packetCount.num_udp);
	this->m_editUDP.SetWindowText(str);

	str.Format("%d", this->packetCount.num_tcp);
	this->m_editTCP.SetWindowText(str);

	str.Format("%d", this->packetCount.num_http);
	this->m_editHTTP.SetWindowText(str);

	str.Format("%d", this->packetCount.num_other);
	this->m_editOther.SetWindowText(str);

	str.Format("%d", this->packetCount.num_sum);
	this->m_editSum.SetWindowText(str);

	return 1;
}

// 2).更新列表
int CSnifferDlg::Sniffer_updateList(struct pcap_pkthdr *data_header, struct data_packet *data, const u_char *pkt_data) {
	/********************初始化准备*********************/
	//建立数据包链表，保存本地化后的数据
	u_char *data_packet_list;
	data_packet_list = (u_char*)malloc(data_header->len);
	memcpy(data_packet_list, pkt_data, data_header->len);

	this->m_localDataList.AddTail(data);
	this->m_netDataList.AddTail(data_packet_list);

	//获取长度
	data->len = data_header->len;
	//获取时间
	time_t local_tv_sec = data_header->ts.tv_sec;
	struct tm *ltime = localtime(&local_tv_sec);
	data->time[0] = ltime->tm_year + 1900;
	data->time[1] = ltime->tm_mon + 1;
	data->time[2] = ltime->tm_mday;
	data->time[3] = ltime->tm_hour;
	data->time[4] = ltime->tm_min;
	data->time[5] = ltime->tm_sec;

	/********************更新控件*********************/
	//为新接收到的数据包在列表控件中新建项
	CString buffer;
	buffer.Format("%d", this->packetNum);
	int nextItem = this->m_listCtrl.InsertItem(this->packetNum, buffer);

	//时间戳
	CString timestr;
	timestr.Format("%d/%d/%d  %d:%d:%d", data->time[0],
		data->time[1], data->time[2], data->time[3], data->time[4], data->time[5]);
	this->m_listCtrl.SetItemText(nextItem, 1, timestr);

	//长度
	buffer.Empty();
	buffer.Format("%d", data->len);
	this->m_listCtrl.SetItemText(nextItem, 2, buffer);

	//源MAC
	buffer.Empty();
	buffer.Format("%02X-%02X-%02X-%02X-%02X-%02X", data->ethh->src[0], data->ethh->src[1],
		data->ethh->src[2], data->ethh->src[3], data->ethh->src[4], data->ethh->src[5]);
	this->m_listCtrl.SetItemText(nextItem, 3, buffer);

	//目的MAC
	buffer.Empty();
	buffer.Format("%02X-%02X-%02X-%02X-%02X-%02X", data->ethh->dest[0], data->ethh->dest[1],
		data->ethh->dest[2], data->ethh->dest[3], data->ethh->dest[4], data->ethh->dest[5]);
	this->m_listCtrl.SetItemText(nextItem, 4, buffer);

	//协议
	this->m_listCtrl.SetItemText(nextItem, 5, CString(data->type));

	//源IP
	buffer.Empty();
	if (data->ethh->type == PROTO_ARP) {
		buffer.Format("%d.%d.%d.%d", data->arph->src_ip[0],
			data->arph->src_ip[1], data->arph->src_ip[2], data->arph->src_ip[3]);
	}
	else if (data->ethh->type == PROTO_IP_V4) {
		struct  in_addr in;
		in.S_un.S_addr = data->ip4h->src_addr;
		buffer = CString(inet_ntoa(in));
	}
	else if (data->ethh->type == PROTO_IP_V6) {
		for (int i = 0; i < 8; i++) {
			if (i <= 6)
				buffer.AppendFormat("%02x:", data->ip6h->src_addr[i]);
			else
				buffer.AppendFormat("%02x", data->ip6h->src_addr[i]);
		}
	}
	this->m_listCtrl.SetItemText(nextItem, 6, buffer);

	//目的IP
	buffer.Empty();
	if (data->ethh->type == PROTO_ARP) {
		buffer.Format("%d.%d.%d.%d", data->arph->dest_ip[0],
			data->arph->dest_ip[1], data->arph->dest_ip[2], data->arph->dest_ip[3]);
	}
	else if (data->ethh->type == PROTO_IP_V4) {
		struct in_addr in;
		in.S_un.S_addr = data->ip4h->dest_addr;
		buffer = CString(inet_ntoa(in));
	}
	else if (data->ethh->type == PROTO_IP_V6) {
		for (int i = 0; i < 8; i++) {
			if (i <= 6)
				buffer.AppendFormat("%02x:", data->ip6h->dest_addr[i]);
			else
				buffer.AppendFormat("%02x", data->ip6h->dest_addr[i]);
		}
	}
	this->m_listCtrl.SetItemText(nextItem, 7, buffer);

	this->packetNum++;//包计数
	return 1;
}

// 3).接收线程函数
DWORD WINAPI Sniffer_capThread(LPVOID lpParameter) {
	CSnifferDlg *pthis = (CSnifferDlg*)lpParameter;
	if (pthis->m_ThreadHandle == NULL) {
		MessageBox(NULL, "线程句柄错误", "提示", MB_OK);
		return -1;
	}

	int flag;
	struct pcap_pkthdr *data_header;//数据包头
	const u_char *pkt_data = NULL;//收到的字节流数据
	while ((flag = pcap_next_ex(pthis->catchHandle, &data_header, &pkt_data)) >= 0) {
		/********************预处理判断*********************/
		if (flag == 0)//超时
			continue;

		struct data_packet *data = (struct data_packet*)malloc(sizeof(struct data_packet));
		memset(data, 0, sizeof(struct data_packet));

		if (data == NULL) {
			MessageBox(NULL, "空间已满，无法接收新的数据包", "Error", MB_OK);
			return -1;
		}

		//分析出错或所接收数据包不在处理范围内
		if (analyse_data_frame(pkt_data, data, &(pthis->packetCount)) < 0)
			continue;

		//将数据包保存到打开的文件中
		if (pthis->dumpFile != NULL)
			pcap_dump((unsigned char*)pthis->dumpFile, data_header, pkt_data);

		/********************更新控件*********************/
		pthis->Sniffer_updatePacket();
		pthis->Sniffer_updateList(data_header, data, pkt_data);
	}
	return 1;
}

/*********************************GUI数据更新函数*********************************/

// 1).保存文件
int CSnifferDlg::Sniffer_saveFile() {
	CFileFind find;
	if (find.FindFile(CString(filePath)) == NULL){
		MessageBox("保存文件遇到未知意外");
		return -1;
	}

	//保存文件对话框
	char szFilter[] = "lix文件(*.lix)|*.lix||";
	CFileDialog openDlg(FALSE, ".lix", 0, 0, szFilter);
	openDlg.m_ofn.lpstrInitialDir = "D:\\";
	if (openDlg.DoModal() == IDOK)
		CopyFile(CString(filePath), openDlg.GetPathName(), TRUE);

	return 1;
}

// 2).读取文件
int CSnifferDlg::Sniffer_readFile(CString path) {
	//处理路径
	int len = path.GetLength() + 1;
	char* charPath = (char *)malloc(len);
	memset(charPath, 0, len);
	if (charPath == NULL)
		return -1;
	for (int i = 0; i < len; i++)
		charPath[i] = (char)path.GetAt(i);

	//打开文件
	pcap_t *fp;
	if ((fp = pcap_open_offline(charPath, errorBufffer)) == NULL) {
		MessageBox("打开文件错误" + CString(errorBufffer));
		return -1;
	}

	struct pcap_pkthdr *data_header;//数据包头
	const u_char *pkt_data = NULL;//收到的字节流数据
	while (pcap_next_ex(fp, &data_header, &pkt_data) >= 0) {
		struct data_packet *data = (struct data_packet*)malloc(sizeof(struct data_packet));
		memset(data, 0, sizeof(struct data_packet));

		if (data == NULL) {
			MessageBox("空间已满，无法接收新的数据包");
			return  -1;
		}

		//分析出错或所接收数据包不在处理范围内
		if (analyse_data_frame(pkt_data, data, &(this->packetCount)) < 0)
			continue;

		//更新各类数据包计数
		this->Sniffer_updatePacket();
		this->Sniffer_updateList(data_header, data, pkt_data);
	}

	pcap_close(fp);
	return 1;
}

// 3).更新编辑框
int CSnifferDlg::Sniffer_updateEdit(int index) {
	POSITION localPos = this->m_localDataList.FindIndex(index);
	POSITION netPos = this->m_netDataList.FindIndex(index);

	struct data_packet* localData = (struct data_packet*)(this->m_localDataList.GetAt(localPos));
	u_char * netData = (u_char*)(this->m_netDataList.GetAt(netPos));

	CString buffer;
	this->print_packet_hex(netData, localData->len, &buffer);
	this->m_edit.SetWindowText(buffer);
	return 1;
}

// 4).数据格式化显示
void CSnifferDlg::print_packet_hex(const u_char* packet, int packet_size, CString *buffer) {
	for (int i = 0; i < packet_size; i += 16) {
		//将数据以16进制形式显示
		buffer->AppendFormat("%04x:  ", (u_int)i);
		int row = (packet_size - i) > 16 ? 16 : (packet_size - i);
		for (int j = 0; j < row; j++)
			buffer->AppendFormat("%02x  ", (u_int)packet[i + j]);

		if (row < 16)//不足16时，用空格补足
			for (int j = row; j < 16; j++)
				buffer->AppendFormat("            ");

		//将数据以字符形式显示
		for (int j = 0; j < row; j++) {
			u_char ch = packet[i + j];
			ch = isprint(ch) ? ch : '.';
			buffer->AppendFormat("%c", ch);
		}
		buffer->Append("\r\n");
		if (row < 16)
			return;
	}
}

// 5).更新树形框
int CSnifferDlg::Sniffer_updateTree(int index) {
	this->m_treeCtrl.DeleteAllItems();
	POSITION localPos = this->m_localDataList.FindIndex(index);
	struct data_packet* localData = (struct data_packet*)(this->m_localDataList.GetAt(localPos));

	CString str;
	str.Format("第%d个数据包", index + 1);
	HTREEITEM root = this->m_treeCtrl.GetRootItem();
	HTREEITEM data = this->m_treeCtrl.InsertItem(str, root);

	/****************链路层****************/
	HTREEITEM frame = this->m_treeCtrl.InsertItem("链路层", data);

	str.Format("源MAC：");
	for (int i = 0; i < 6; i++) {
		if (i <= 4)
			str.AppendFormat("%02x-", localData->ethh->src[i]);
		else
			str.AppendFormat("%02x", localData->ethh->src[i]);
	}
	this->m_treeCtrl.InsertItem(str, frame);

	str.Format("目的MAC：");
	for (int i = 0; i < 6; i++) {
		if (i <= 4)
			str.AppendFormat("%02x-", localData->ethh->dest[i]);
		else
			str.AppendFormat("%02x", localData->ethh->dest[i]);
	}
	this->m_treeCtrl.InsertItem(str, frame);

	str.Format("类型：0x%02x", localData->ethh->type);
	this->m_treeCtrl.InsertItem(str, frame);

	/****************网络层****************/
	//ARP头
	if (localData->ethh->type == PROTO_ARP) {
		HTREEITEM arp = this->m_treeCtrl.InsertItem("ARP头", data);
		str.Format("硬件类型：%d", localData->arph->hard_type);
		this->m_treeCtrl.InsertItem(str, arp);
		str.Format("协议类型：0x%02x", localData->arph->pro_type);
		this->m_treeCtrl.InsertItem(str, arp);
		str.Format("硬件地址长度：%d", localData->arph->hard_len);
		this->m_treeCtrl.InsertItem(str, arp);
		str.Format("协议地址长度：%d", localData->arph->pro_len);
		this->m_treeCtrl.InsertItem(str, arp);
		str.Format("操作码：%d", localData->arph->oper);
		this->m_treeCtrl.InsertItem(str, arp);

		str.Format("发送方MAC：");
		for (int i = 0; i < 6; i++) {
			if (i <= 4)
				str.AppendFormat("%02x-", localData->arph->src_mac[i]);
			else
				str.AppendFormat("%02x", localData->arph->src_mac[i]);
		}
		this->m_treeCtrl.InsertItem(str, arp);

		str.Format("发送方IP：");
		for (int i = 0; i < 4; i++) {
			if (i <= 2)
				str.AppendFormat("%d.", localData->arph->src_ip[i]);
			else
				str.AppendFormat("%d", localData->arph->src_ip[i]);
		}
		this->m_treeCtrl.InsertItem(str, arp);

		str.Format("接收方MAC：");
		for (int i = 0; i < 6; i++) {
			if (i <= 4)
				str.AppendFormat("%02x-", localData->arph->dest_mac[i]);
			else
				str.AppendFormat("%02x", localData->arph->dest_mac[i]);
		}
		this->m_treeCtrl.InsertItem(str, arp);

		str.Format("接收方IP：");
		for (int i = 0; i < 4; i++) {
			if (i <= 2)
				str.AppendFormat("%d.", localData->arph->dest_ip[i]);
			else
				str.AppendFormat("%d", localData->arph->dest_ip[i]);
		}
		this->m_treeCtrl.InsertItem(str, arp);
	}
	
	//IPv4头
	if (localData->ethh->type == PROTO_IP_V4) { 
		HTREEITEM ip = this->m_treeCtrl.InsertItem("IPv4头", data);

		str.Format("版本：%d", localData->ip4h->version);
		this->m_treeCtrl.InsertItem(str, ip);
		str.Format("IP头长：%d", localData->ip4h->ihl);
		this->m_treeCtrl.InsertItem(str, ip);
		str.Format("服务类型：%d", localData->ip4h->tos);
		this->m_treeCtrl.InsertItem(str, ip);
		str.Format("总长度：%d", localData->ip4h->total_len);
		this->m_treeCtrl.InsertItem(str, ip);
		str.Format("标识：0x%02x", localData->ip4h->id);
		this->m_treeCtrl.InsertItem(str, ip);
		str.Format("段偏移：%d", localData->ip4h->frag_off);
		this->m_treeCtrl.InsertItem(str, ip);
		str.Format("生存期：%d", localData->ip4h->ttl);
		this->m_treeCtrl.InsertItem(str, ip);
		str.Format("协议：%d", localData->ip4h->proto);
		this->m_treeCtrl.InsertItem(str, ip);
		str.Format("头部校验和：0x%02x", localData->ip4h->check);
		this->m_treeCtrl.InsertItem(str, ip);

		str.Format("源IP：");
		struct in_addr in;
		in.S_un.S_addr = localData->ip4h->src_addr;
		str.AppendFormat(CString(inet_ntoa(in)));
		this->m_treeCtrl.InsertItem(str, ip);

		str.Format("目的IP：");
		in.S_un.S_addr = localData->ip4h->dest_addr;
		str.AppendFormat(CString(inet_ntoa(in)));
		this->m_treeCtrl.InsertItem(str, ip);

		/****************传输层****************/
		//ICMPv4头
		if (localData->ip4h->proto == V4_PROTO_ICMP_V4) {
			HTREEITEM icmp = this->m_treeCtrl.InsertItem("ICMPv4头", data);

			str.Format("类型:%d", localData->icmp4h->type);
			this->m_treeCtrl.InsertItem(str, icmp);
			str.Format("代码:%d", localData->icmp4h->code);
			this->m_treeCtrl.InsertItem(str, icmp);
			str.Format("序号:%d", localData->icmp4h->seq);
			this->m_treeCtrl.InsertItem(str, icmp);
			str.Format("校验和:%d", localData->icmp4h->check);
			this->m_treeCtrl.InsertItem(str, icmp);
		}
		
		//TCP头
		if (localData->ip4h->proto == V4_PROTO_TCP) {
			HTREEITEM tcp = this->m_treeCtrl.InsertItem("TCP协议头", data);

			str.Format("  源端口:%d", localData->tcph->src_port);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format("  目的端口:%d", localData->tcph->dest_port);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format("  序列号:0x%02x", localData->tcph->seq);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format("  确认号:%d", localData->tcph->ack_seq);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format("  头部长度:%d", localData->tcph->doff);

			HTREEITEM flag = this->m_treeCtrl.InsertItem(" +标志位", tcp);
			str.Format("cwr %d", localData->tcph->cwr);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format("ece %d", localData->tcph->ece);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format("urg %d", localData->tcph->urg);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format("ack %d", localData->tcph->ack);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format("psh %d", localData->tcph->psh);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format("rst %d", localData->tcph->rst);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format("syn %d", localData->tcph->syn);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format("fin %d", localData->tcph->fin);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format("  紧急指针:%d", localData->tcph->urg_ptr);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format("  校验和:0x%02x", localData->tcph->check);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format("  选项:%d", localData->tcph->opt);
			this->m_treeCtrl.InsertItem(str, tcp);
		}
		 
		//UDP头
		if (localData->ip4h->proto == V4_PROTO_UDP) {
			HTREEITEM udp = this->m_treeCtrl.InsertItem("UDP协议头", data);

			str.Format("源端口:%d", localData->udph->sport);
			this->m_treeCtrl.InsertItem(str, udp);
			str.Format("目的端口:%d", localData->udph->dport);
			this->m_treeCtrl.InsertItem(str, udp);
			str.Format("总长度:%d", localData->udph->len);
			this->m_treeCtrl.InsertItem(str, udp);
			str.Format("校验和:0x%02x", localData->udph->check);
			this->m_treeCtrl.InsertItem(str, udp);
		}
	}
	
	//IPv6头
	if (localData->ethh->type == PROTO_IP_V6) {
		HTREEITEM ip6 = this->m_treeCtrl.InsertItem("IPv6头", data);

		str.Format("版本:%d", localData->ip6h->flowtype);
		this->m_treeCtrl.InsertItem(str, ip6);
		str.Format("流类型:%d", localData->ip6h->version);
		this->m_treeCtrl.InsertItem(str, ip6);
		str.Format("流标签:%d", localData->ip6h->flowid);
		this->m_treeCtrl.InsertItem(str, ip6);
		str.Format("有效载荷长度:%d", localData->ip6h->plen);
		this->m_treeCtrl.InsertItem(str, ip6);
		str.Format("下一个首部:0x%02x", localData->ip6h->next_head);
		this->m_treeCtrl.InsertItem(str, ip6);
		str.Format("跳限制:%d", localData->ip6h->hop_limit);
		this->m_treeCtrl.InsertItem(str, ip6);

		str.Format("源地址:");
		for (int i = 0; i < 8; i++) {
			if (i <= 6)
				str.AppendFormat("%02x:", localData->ip6h->src_addr[i]);
			else
				str.AppendFormat("%02x", localData->ip6h->src_addr[i]);
		}
		this->m_treeCtrl.InsertItem(str, ip6);

		str.Format("目的地址:");
		for (int i = 0; i < 8; i++) {
			if (i <= 6)
				str.AppendFormat("%02x:", localData->ip6h->src_addr[i]);
			else
				str.AppendFormat("%02x", localData->ip6h->src_addr[i]);
		}
		this->m_treeCtrl.InsertItem(str, ip6);

		/****************传输层****************/
		//IPv6头
		if (localData->ip6h->next_head == V6_PROTO_ICMP_V6) {
			HTREEITEM icmp6 = this->m_treeCtrl.InsertItem("ICMPv6协议头", data);

			str.Format("类型:%d", localData->icmp6h->type);
			this->m_treeCtrl.InsertItem(str, icmp6);
			str.Format("代码:%d", localData->icmp6h->code);
			this->m_treeCtrl.InsertItem(str, icmp6);
			str.Format("序号:%d", localData->icmp6h->seq);
			this->m_treeCtrl.InsertItem(str, icmp6);
			str.Format("校验和:%d", localData->icmp6h->check);
			this->m_treeCtrl.InsertItem(str, icmp6);
			str.Format("选项-类型:%d", localData->icmp6h->op_type);
			this->m_treeCtrl.InsertItem(str, icmp6);
			str.Format("选项-长度%d", localData->icmp6h->op_len);
			this->m_treeCtrl.InsertItem(str, icmp6);
			str.Format("选项-链路层地址:");

			for (int i = 0; i < 6; i++) {
				if (i <= 4)
					str.AppendFormat("%02x-", localData->icmp6h->op_eth_addr[i]);
				else
					str.AppendFormat("%02x", localData->icmp6h->op_eth_addr[i]);
			}
			this->m_treeCtrl.InsertItem(str, icmp6);
		}
		
		//TCP头
		if (localData->ip6h->next_head == V6_PROTO_TCP) {
			HTREEITEM tcp = this->m_treeCtrl.InsertItem("TCP协议头", data);

			str.Format("  源端口:%d", localData->tcph->src_port);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format("  目的端口:%d", localData->tcph->dest_port);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format("  序列号:0x%02x", localData->tcph->seq);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format("  确认号:%d", localData->tcph->ack_seq);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format("  头部长度:%d", localData->tcph->doff);

			HTREEITEM flag = this->m_treeCtrl.InsertItem("标志位", tcp);

			str.Format("cwr %d", localData->tcph->cwr);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format("ece %d", localData->tcph->ece);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format("urg %d", localData->tcph->urg);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format("ack %d", localData->tcph->ack);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format("psh %d", localData->tcph->psh);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format("rst %d", localData->tcph->rst);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format("syn %d", localData->tcph->syn);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format("fin %d", localData->tcph->fin);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format("  紧急指针:%d", localData->tcph->urg_ptr);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format("  校验和:0x%02x", localData->tcph->check);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format("  选项:%d", localData->tcph->opt);
			this->m_treeCtrl.InsertItem(str, tcp);
		}
		
		//UDP头
		if (localData->ip6h->next_head == V6_PROTO_UDP) {
			HTREEITEM udp = this->m_treeCtrl.InsertItem("UDP协议头", data);

			str.Format("源端口:%d", localData->udph->sport);
			this->m_treeCtrl.InsertItem(str, udp);
			str.Format("目的端口:%d", localData->udph->dport);
			this->m_treeCtrl.InsertItem(str, udp);
			str.Format("总长度:%d", localData->udph->len);
			this->m_treeCtrl.InsertItem(str, udp);
			str.Format("校验和:0x%02x", localData->udph->check);
			this->m_treeCtrl.InsertItem(str, udp);
		}
	}

	return 1;
}

/*********************************消息处理函数*********************************/

// 1).开始按钮
void CSnifferDlg::OnBnClickedButton1() {
	// TODO: 在此添加控件通知处理程序代码

	//若已有数据，提示保存数据
	if (this->m_localDataList.IsEmpty() == FALSE)
		if (MessageBox("确认不保存数据？", "警告", MB_YESNO) == IDNO)
			this->Sniffer_saveFile();

	//清空数据
	this->packetNum = 1; //重新计数
	this->m_localDataList.RemoveAll(); 
	this->m_netDataList.RemoveAll();
	memset(&(this->packetCount), 0, sizeof(struct packet_count));
	this->Sniffer_updatePacket();

	if (this->Sniffer_startCap() < 0)
		return;

	this->m_listCtrl.DeleteAllItems();
	this->m_treeCtrl.DeleteAllItems();
	this->m_edit.SetWindowText("");
	this->m_buttonStart.EnableWindow(FALSE);
	this->m_buttonStop.EnableWindow(TRUE);
	this->m_buttonSave.EnableWindow(FALSE);
}

// 2).结束按钮
void CSnifferDlg::OnBnClickedButton2() {
	// TODO: 在此添加控件通知处理程序代码
	if (this->m_ThreadHandle == NULL)
		return;
	if (TerminateThread(this->m_ThreadHandle, -1) == 0) {
		MessageBox("线程关闭错误，请稍后重试");
		return;
	}
	this->m_ThreadHandle = NULL;
	this->m_buttonStart.EnableWindow(TRUE);
	this->m_buttonStop.EnableWindow(FALSE);
	this->m_buttonSave.EnableWindow(TRUE);
}

// 3).保存按钮
void CSnifferDlg::OnBnClickedButton3() {
	// TODO: 在此添加控件通知处理程序代码
	if (this->Sniffer_saveFile() < 0)
		return;
}

// 4).读取按钮
void CSnifferDlg::OnBnClickedButton4() {
	// TODO: 在此添加控件通知处理程序代码

	//清空数据
	this->m_listCtrl.DeleteAllItems();
	this->packetNum = 1;
	this->m_localDataList.RemoveAll();
	this->m_netDataList.RemoveAll();
	memset(&(this->packetCount), 0, sizeof(struct packet_count));

	//打开文件对话框
	char szFilter[] = "lix文件(*.lix)|*.lix||";
	CFileDialog FileDlg(TRUE, ".lix", 0, 0, szFilter);
	FileDlg.m_ofn.lpstrInitialDir = "D:\\";
	if (FileDlg.DoModal() == IDOK) {
		int ret = this->Sniffer_readFile(FileDlg.GetPathName());
		if (ret < 0)
			return;
	}
}

// 5).列表更新
void CSnifferDlg::OnLvnItemchangedList1(NMHDR *pNMHDR, LRESULT *pResult) {
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	POSITION pos = m_listCtrl.GetFirstSelectedItemPosition();
	int index = m_listCtrl.GetNextSelectedItem(pos); //获取列表控件当前选择的行号
	if (index != -1) {
		this->Sniffer_updateEdit(index);//更新对应行的编辑框
		this->Sniffer_updateTree(index);//更新对应行的树形框
	}
	*pResult = 0;
}

// 6).列表项颜色变换
void CSnifferDlg::OnNMCustomdrawList1(NMHDR *pNMHDR, LRESULT *pResult) {
	LPNMLVCUSTOMDRAW pNMCD = (LPNMLVCUSTOMDRAW)pNMHDR;
	*pResult = 0;

	if (CDDS_PREPAINT == pNMCD->nmcd.dwDrawStage)
		*pResult = CDRF_NOTIFYITEMDRAW;
	else if(CDDS_ITEMPREPAINT == pNMCD->nmcd.dwDrawStage) {
		POSITION pos = this->m_localDataList.FindIndex(pNMCD->nmcd.dwItemSpec);
		struct data_packet * localData = (struct data_packet *)this->m_localDataList.GetAt(pos);
		
		char buffer[10];
		memset(buffer, 0, sizeof(buffer));
		strcpy(buffer, localData->type);
		
		COLORREF crText;
		if (!strcmp(buffer, "ARP"))
			crText = RGB(226, 238, 227);
		if (!strcmp(buffer, "IPv4"))
			crText = RGB(255, 182, 193);
		if (!strcmp(buffer, "IPv6"))
			crText = RGB(111, 224, 254);
		if(!strcmp(buffer, "UDP"))
			crText = RGB(194, 195, 252);
		if(!strcmp(buffer, "TCP"))
			crText = RGB(230, 230, 230);
		if(!strcmp(buffer, "ICMPv4"))
			crText = RGB(49, 164, 238);
		if(!strcmp(buffer, "ICMPv6"))
			crText = RGB(189, 254, 76);
		if (!strcmp(buffer, "HTTP"))
			crText = RGB(238, 232, 180);

		pNMCD->clrTextBk = crText;
		*pResult = CDRF_DODEFAULT;
	}
}
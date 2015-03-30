/*
 * G5 - TCP Transfer && LB Dispenser
 * Author      : calvin
 * Email       : calvinwillliams.c@gmail.com
 *
 * Licensed under the LGPL v2.1, see the file LICENSE in base directory.
 */

#ifndef _H_G5_
#define _H_G5_

#define VERSION		"1.2.4"

#define SERVICE_NAME	"G5"
#define SERVICE_DESC	"TCP Transfer && Load-Balance Dispenser"

/*
config file format :
rule_id	mode	( rule-properties ) client_addr ( client-properties ) -> forward_addr ( forward-properties ) -> server_addr ( server-properties ) ;
	mode		G  : manage port
			MS : master/slave mode
			RR : round & robin mode
			LC : least connection mode
			RT : response Time mode
			RD : random mode
			HS : hash mode
	rule-properties timeout n , ...
	client_addr	format : ip1.ip2.ip3.ip4:port
			ip1~4,port allow use '*' or '?' for match
			one or more address seprating by blank
	client-properties client_connection_count n , ...
	forward_addr	format : ip1.ip2.ip3.ip4:port
			one or more address seprating by blank
	server_addr	format : ip1.ip2.ip3.ip4:port
			one or more address seprating by blank
	( all seprated by blank charset )
demo :
admin G ( timeout 300 ) 192.168.1.79:* - 192.168.1.54:8060 ;
webdog MS ( timeout 120 ) 192.168.1.54:* 192.168.1.79:* 192.168.1.79:* - 192.168.1.54:8079 > 192.168.1.79:8089 192.168.1.79:8090 ;
hsbl LB 192.168.1.*:* ( client_connection_count 2 ) - 192.168.1.54:8080 > 192.168.1.79:8089 192.168.1.79:8090 192.168.1.79:8091 ;

manage port command :
	ver
	list rules
	add rule ...
	modify rule ...
	remove rule ...
	dump rule
	list forwards
	quit
demo :
	add rule webdog2 MS 1.2.3.4:1234 - 192.168.1.54:1234 > 4.3.2.1:4321 ;
	modify rule webdog2 MS 4.3.2.1:4321 - 192.168.1.54:1234 > 1.2.3.4:1234 ;
	remove rule webdog2 ;
*/

#if ( defined __linux )
#define USE_EPOLL
#elif ( defined _WIN32 )
#define USE_SELECT
#elif ( defined __unix )
#define USE_SELECT
#endif

#if ( defined __linux ) || ( defined __unix )
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <stdarg.h>
#include <limits.h>
#define _VSNPRINTF		vsnprintf
#define _SNPRINTF		snprintf
#define _CLOSESOCKET		close
#define _ERRNO			errno
#define _EWOULDBLOCK		EWOULDBLOCK
#define _ECONNABORTED		ECONNABORTED
#define _EINPROGRESS		EINPROGRESS
#define _ECONNRESET		ECONNRESET
#define _SOCKLEN_T		socklen_t
#define _GETTIMEOFDAY(_tv_)	gettimeofday(&(_tv_),NULL)
#define _LOCALTIME(_tt_,_stime_) \
	localtime_r(&(_tt_),&(_stime_));
#elif ( defined _WIN32 )
#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <io.h>
#include <windows.h>
#define _VSNPRINTF		_vsnprintf
#define _SNPRINTF		_snprintf
#define _CLOSESOCKET		closesocket
#define _ERRNO			GetLastError()
#define _EWOULDBLOCK		WSAEWOULDBLOCK
#define _ECONNABORTED		WSAECONNABORTED
#define _EINPROGRESS		WSAEINPROGRESS
#define _ECONNRESET		WSAECONNRESET
#define _SOCKLEN_T		int
#define _GETTIMEOFDAY(_tv_) \
	{ \
		SYSTEMTIME stNow ; \
		GetLocalTime( & stNow ); \
		(_tv_).tv_usec = stNow.wMilliseconds * 1000 ; \
		time( & ((_tv_).tv_sec) ); \
	}
#define _SYSTEMTIME2TIMEVAL_USEC(_syst_,_tv_) \
		(_tv_).tv_usec = (_syst_).wMilliseconds * 1000 ;
#define _SYSTEMTIME2TM(_syst_,_stime_) \
		(_stime_).tm_year = (_syst_).wYear - 1900 ; \
		(_stime_).tm_mon = (_syst_).wMonth - 1 ; \
		(_stime_).tm_mday = (_syst_).wDay ; \
		(_stime_).tm_hour = (_syst_).wHour ; \
		(_stime_).tm_min = (_syst_).wMinute ; \
		(_stime_).tm_sec = (_syst_).wSecond ;
#define _LOCALTIME(_tt_,_stime_) \
	{ \
		SYSTEMTIME	stNow ; \
		GetLocalTime( & stNow ); \
		_SYSTEMTIME2TM( stNow , (_stime_) ); \
	}
#endif

#ifndef ULONG_MAX
#define ULONG_MAX 0xffffffffUL
#endif

#define FOUND				9	/* 找到 */ /* found */
#define NOT_FOUND			4	/* 找不到 */ /* not found */

#define MATCH				1	/* 匹配 */ /* match */
#define NOT_MATCH			-1	/* 不匹配 */ /* not match */

#define RULE_ID_MAXLEN			64	/* 最长转发规则名长度 */ /* The longest length of forwarding rules */
#define RULE_MODE_MAXLEN		2	/* 最长转发规则模式长度 */ /* The longest length of forwarding rules mode */

#define FORWARD_RULE_MODE_G		"G"	/* 管理端口 */ /* manager port */
#define FORWARD_RULE_MODE_MS		"MS"	/* 主备模式 */ /* master-standby mode */
#define FORWARD_RULE_MODE_RR		"RR"	/* 轮询模式 */ /* polling mode */
#define FORWARD_RULE_MODE_LC		"LC"	/* 最少连接模式 */ /* minimum number of connections mode */
#define FORWARD_RULE_MODE_RT		"RT"	/* 最小响应时间模式 */ /* minimum response time mode */
#define FORWARD_RULE_MODE_RD		"RD"	/* 随机模式 */ /* random mode */
#define FORWARD_RULE_MODE_HS		"HS"	/* HASH模式 */ /* HASH mode */

#define RULE_CLIENT_MAXCOUNT		10	/* 单条规则中最大客户端配置数量 */ /* maximum clients in rule */
#define RULE_FORWARD_MAXCOUNT		3	/* 单条规则中最大转发端配置数量 */ /* maximum forwards in rule */
#define RULE_SERVER_MAXCOUNT		100	/* 单条规则中最大服务端配置数量 */ /* maximum servers in rule */

#define DEFAULT_FORWARD_RULE_MAXCOUNT	100	/* 缺省最大转发规则数量 */ /* maximum forward rules for default */
#define DEFAULT_CONNECTION_MAXCOUNT	1024	/* 缺省最大连接数量 */ /* 最大转发会话数量 = 最大连接数量 * 3 */ /* maximum connections for default */
#define DEFAULT_TRANSFER_BUFSIZE	4096	/* 缺省通讯转发缓冲区大小 */ /* communication I/O buffer for default */

/* 网络地址信息结构 */ /* network address information structure */
struct NetAddress
{
	char			ip[ 64 + 1 ] ; /* ip地址 */ /* ip address */
	char			port[ 10 + 1 ] ; /* 端口 */ /* port */
	struct sockaddr_in	sockaddr ; /* sock地址结构 */ /* sock structure */
} ;

/* 客户端信息结构 */ /* client information structure */
struct ClientNetAddress
{
	struct NetAddress	netaddr ; /* 网络地址结构 */ /* network address structure */
	int			sock ; /* sock描述字 */ /* sock fd */
	
	unsigned long		client_connection_count ; /* 客户端连接数量 */ /* client number of connections */
	unsigned long		maxclients ; /* 最大客户端数量 */ /* amount of clients */
} ;

/* 转发端信息结构 */ /* forward information structure */
struct ForwardNetAddress
{
	struct NetAddress	netaddr ; /* 网络地址结构 */ /* network address structure */
	int			sock ; /* sock描述字 */ /* sock fd */
} ;

/* 服务端信息结构 */ /* server information structure */
struct ServerNetAddress
{
	struct NetAddress	netaddr ; /* 网络地址结构 */ /* network address structure */
	int			sock ; /* sock描述字 */ /* sock fd */
	
	unsigned long		server_connection_count ; /* 服务端连接数量 */ /* server connection number */
} ;

#define SERVER_UNABLE_IGNORE_COUNT	100 /* 服务端不可用时最大暂禁次数 */

/* 统计端信息结构 */ /* stat information structure */
struct StatNetAddress
{
	struct NetAddress	netaddr ; /* 网络地址结构 */ /* network address structure */
	
	unsigned long		connection_count ; /* 连接数量 */ /* number of connections */
} ;

/* 转发规则结构 */ /* forwarding rules structure */
struct ForwardRule
{
	char				rule_id[ RULE_ID_MAXLEN + 1 ] ; /* 规则ID（字符串） */ /* rule id */
	char				rule_mode[ RULE_MODE_MAXLEN + 1 ] ; /* 规则类型 */ /* rule mode */
	
	long				timeout ; /* 超时时间（秒） */
	
	struct ClientNetAddress		client_addr[ RULE_CLIENT_MAXCOUNT ] ; /* 客户端地址结构 */ /* client address structure */
	unsigned long			client_count ; /* 客户端规则配置数量 */
	
	struct ForwardNetAddress	forward_addr[ RULE_FORWARD_MAXCOUNT ] ; /* 转发端地址结构 */ /* forward information structure */
	unsigned long			forward_count ; /* 转发端规则配置数量 */
	
	struct ServerNetAddress		server_addr[ RULE_SERVER_MAXCOUNT ] ; /* 服务端地址结构 */ /* server information structure */
	unsigned long			server_count ; /* 服务端规则配置数量 */
	unsigned long			select_index ; /* 当前服务端索引 */ /* current server index */
	
	union
	{
		struct
		{
			unsigned long	server_unable ; /* 服务不可用暂禁次数 */
		} RR[ RULE_SERVER_MAXCOUNT ] ;
		struct
		{
			unsigned long	server_unable ; /* 服务不可用暂禁次数 */
		} LC[ RULE_SERVER_MAXCOUNT ] ;
		struct
		{
			unsigned long	server_unable ; /* 服务不可用暂禁次数 */
			struct timeval	tv1 ; /* 最近读时间戳 */
			struct timeval	tv2 ; /* 最近写时间戳 */
			struct timeval	dtv ; /* 最近读写时间戳差 */
		} RT[ RULE_SERVER_MAXCOUNT ] ;
	} status ;
} ;

#define FORWARD_SESSION_TYPE_UNUSED	0	/* 转发会话未用单元 */
#define FORWARD_SESSION_TYPE_MANAGE	1	/* 管理连接会话 */
#define FORWARD_SESSION_TYPE_LISTEN	2	/* 侦听服务会话 */
#define FORWARD_SESSION_TYPE_CLIENT	3	/* 客户端会话 */
#define FORWARD_SESSION_TYPE_SERVER	4	/* 服务端会话 */

#define CONNECT_STATUS_CONNECTING	0	/* 异步连接服务端中 */
#define CONNECT_STATUS_RECEIVING	1	/* 等待接收中 */
#define CONNECT_STATUS_SENDING		2	/* 等待发送中 */
#define CONNECT_STATUS_SUSPENDING	3	/* 暂禁中 */

#define IO_BUFSIZE			4096	/* 通讯输入输出缓冲区 */

#define TRY_CONNECT_MAXCOUNT		5	/* 异步尝试连接服务端最大次数 */

/* 侦听会话结构 */ /* listen to the session structure  */
struct ListenNetAddress
{
	struct NetAddress	netaddr ; /* 网络地址结构 */ /* network address structure */
	int			sock ; /* sock描述字 */ /* sock fd */
	
	char			rule_mode[ 2 + 1 ] ; /* 规则类型 */ /* rule mode */
} ;

/* 转发会话结构 */ /* forwarding session structure */
struct ForwardSession
{
	char				forward_session_type ; /* 转发会话类型 */
	
	struct ClientNetAddress		client_addr ; /* 客户端地址结构 */
	struct ListenNetAddress		listen_addr ; /* 侦听端地址结构 */
	struct ServerNetAddress		server_addr ; /* 服务端地址结构 */
	unsigned long			client_session_index ; /* 客户端会话索引 */
	unsigned long			server_session_index ; /* 服务端会话索引 */
	
	struct ForwardRule		*p_forward_rule ; /* 转发规则指针 */
	struct ForwardRule		old_forward_rule ; /* 在线变更后的老转发规则 */
	unsigned long			client_index ; /* 客户端索引 */
	unsigned long			server_index ; /* 服务端索引 */
	
	unsigned char			status ; /* 会话状态 */
	unsigned long			try_connect_count ; /* 尝试连接服务端次数 */
	
	long				active_timestamp ; /* 最近活动时间戳 */
	
	char				io_buffer[ IO_BUFSIZE + 1 ] ; /* 输入输出缓冲区 */
	long				io_buflen ; /* 输入输出缓冲区中数据长度 */
} ;

/* 命令行参数结构 */ /* command line argument structure */
struct CommandParam
{
	char				*config_pathfilename ; /* -f ... */
	
	unsigned long			forward_rule_maxcount ; /* -r ... */
	unsigned long			forward_connection_maxcount ; /* -c ... */
	unsigned long			transfer_bufsize ; /* -b ... */
	
	char				debug_flag ; /* -d */
	
	char				install_service_flag ; /* --install-service */
	char				uninstall_service_flag ; /* --uninstall-service */
	char				service_flag ; /* --service */
} ;

/* 内部缓存结构 */ /* internal cache structure */
struct ServerCache
{
	struct timeval			tv ;
	struct tm			stime ;
	char				datetime[ 10 + 1 + 8 + 1 ] ;
} ;

/* 服务器环境大结构 */ /* server environment structure */

#define WAIT_EVENTS_COUNT		1024	/* 等待事件集合数量 */

struct ServerEnv
{
	struct CommandParam		cmd_para ; /* 命令行参数结构 */
	
	struct ForwardRule		*forward_rule ; /* 转发规则结构集合基地址 */
	unsigned long			forward_rule_count ; /* 转发规则结构数量 */
	
#ifdef USE_EPOLL
	int				epoll_fds ; /* epoll描述字 */
	struct epoll_event		*p_event ; /* 当前epoll事件结构指针 */
	struct epoll_event		events[ WAIT_EVENTS_COUNT ] ; /* epoll事件结构集合 */
	int				sock_count ; /* epoll sock集合 */
	int				sock_index ; /* 当前epoll sock索引 */
#endif
	struct ForwardSession		*forward_session ; /* 当前转发会话 */
	unsigned long			forward_session_maxcount ; /* 转发会话最大数量 */
	unsigned long			forward_session_count ; /* 转发会话数量 */
	unsigned long			forward_session_use_offsetpos ; /* 转发会话池当前偏移量（用于获取空闲单元用） */
	
	struct ServerCache		server_cache ; /* 服务器缓存 */
	
	unsigned long			maxsessions_per_ip ; /* 每个客户端ip最大会话数量 */
	struct StatNetAddress		*stat_addr ; /* 统计地址结构集合基地址，用于控制每个客户端ip最大会话数量 */
	unsigned long			stat_addr_maxcount ; /* 统计地址结构数量 */
} ;

int G5( struct ServerEnv *pse );

#endif

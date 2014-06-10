/*
 * TCP Transfer && LB Dispenser - G5
 * Author      : calvin
 * Email       : calvinwillliams.c@gmail.com
 * LastVersion : v1.2.3
 *
 * Licensed under the LGPL v2.1, see the file LICENSE in base directory.
 */

#include "G5.h"

#if ( defined _WIN32 )
static	WSADATA		wsd ;
SERVICE_STATUS		g_stServiceStatus;
SERVICE_STATUS_HANDLE	g_hServiceStatusHandle;

#endif

struct ServerEnv	*g_pse = NULL ;

char	*_g_forward_status[] = { "CONNECTING" , "CONNECTED" , "SUSPENDED" } ;

/* 日志输出 */ /* output log */
static void DebugOutput( struct ServerEnv *pse , char *format , ... )
{
	static char	log_buffer[ 1024 + 1 ] ;
	va_list		valist ;
	
	if( pse->cmd_para.debug_flag == 0 )
		return;
	
	memset( log_buffer , 0x00 , sizeof(log_buffer) );
	
	sprintf( log_buffer , "%s | " , pse->server_cache.datetime );
	
	va_start( valist , format );
	_VSNPRINTF( log_buffer+(19+3) , sizeof(log_buffer)-(19+3)-1 , format , valist );
	va_end( valist );
	
	fprintf( stdout , "%s" , log_buffer );
	
	return;
}

static void InfoOutput( struct ServerEnv *pse , char *format , ... )
{
	static char	log_buffer[ 1024 + 1 ] ;
	va_list		valist ;
	
	memset( log_buffer , 0x00 , sizeof(log_buffer) );
	
	sprintf( log_buffer , "%s | " , pse->server_cache.datetime );
	
	va_start( valist , format );
	_VSNPRINTF( log_buffer+(19+3) , sizeof(log_buffer)-(19+3)-1 , format , valist );
	va_end( valist );
	
	fprintf( stdout , "%s" , log_buffer );
	
	return;
}

static void InfoOutputNoPrefix( struct ServerEnv *pse , char *format , ... )
{
	va_list		valist ;
	
	va_start( valist , format );
	vfprintf( stdout , format , valist );
	va_end( valist );
	
	return;
}

static void ErrorOutput( struct ServerEnv *pse , char *format , ... )
{
	static char	log_buffer[ 1024 + 1 ] ;
	va_list		valist ;
	
	memset( log_buffer , 0x00 , sizeof(log_buffer) );
	
	sprintf( log_buffer , "%s | " , pse->server_cache.datetime );
	
	va_start( valist , format );
	_VSNPRINTF( log_buffer+(19+3) , sizeof(log_buffer)-(19+3)-1 , format , valist );
	va_end( valist );
	
	fprintf( stderr , "%s" , log_buffer );
	
	return;
}

/* 取随机数工具函数 */ /* random tool */
static int FetchRand( int min, int max )
{
	return ( rand() % ( max - min + 1 ) ) + min ;
}

/* 计算字符串HASH工具函数 */ /* hash tool */
static unsigned long CalcHash( char *str )
{
	unsigned long	hashval ;
	unsigned char	*puc = NULL ;
	
	hashval = 19791007 ;
	for( puc = (unsigned char *)str ; *puc ; puc++ )
	{
		hashval = hashval * 19830923 + (*puc) ;
	}
	
	return hashval;
}

/* 设置sock重用选项 */ /* set the sock reuse options  */
static int SetReuseAddr( int sock )
{
	int	on ;
	
	on = 1 ;
	setsockopt( sock , SOL_SOCKET , SO_REUSEADDR , (void *) & on, sizeof(on) );
	
	return 0;
}

/* 设置sock非堵塞选项 */ /* set the sock not blocking options  */
static int SetNonBlocking( int sock )
{
#if ( defined __linux ) || ( defined __unix )
	int	opts;
	
	opts = fcntl( sock , F_GETFL ) ;
	if( opts < 0 )
	{
		return -1;
	}
	
	opts = opts | O_NONBLOCK;
	if( fcntl( sock , F_SETFL , opts ) < 0 )
	{
		return -2;
	}
#elif ( defined _WIN32 )
	u_long	mode = 1 ;
	ioctlsocket( sock , FIONBIO , & mode );
#endif
	
	return 0;
}

/* 注册全局统计地址 */ /* registered global statistics address */
static int RegisterStatAddress( struct ServerEnv *pse , char *ip )
{
	unsigned long		index ;
	unsigned long		count ;
	struct StatNetAddress	*p_stat_addr = NULL ;
	
	if( pse->maxsessions_per_ip == 0 )
		return 0;
	
	for( count = 0 , index = CalcHash(ip) % pse->stat_addr_maxcount , p_stat_addr = & (pse->stat_addr[index]) ; count < pse->stat_addr_maxcount ; count++ , index++ , p_stat_addr++ )
	{
		if( index >= pse->stat_addr_maxcount )
		{
			index = 0 ;
			p_stat_addr = & (pse->stat_addr[0]) ;
		}
		
		if( p_stat_addr->netaddr.ip[0] == '\0' )
		{
			strcpy( p_stat_addr->netaddr.ip , ip );
			p_stat_addr->connection_count = 1 ;
			return 0;
		}
		else if( strcmp( p_stat_addr->netaddr.ip , ip ) == 0 )
		{
			if( p_stat_addr->connection_count >= pse->maxsessions_per_ip )
			{
				ErrorOutput( pse , "too much connections on ip[%s]\r\n" , ip );
				return -1;
			}
			p_stat_addr->connection_count++;
			return 0;
		}
	}
	
	ErrorOutput( pse , "too much connections on all ip\r\n" );
	return 1;
}

/* 注销全局统计地址 */ /* unregistered global statistics address */
static int UnregisterStatAddress( struct ServerEnv *pse , char *ip )
{
	unsigned long		index ;
	unsigned long		count ;
	struct StatNetAddress	*p_stat_addr = NULL ;
	
	if( pse->maxsessions_per_ip == 0 )
		return 0;
	
	for( count = 0 , index = CalcHash(ip) % pse->stat_addr_maxcount , p_stat_addr = & (pse->stat_addr[index]) ; count < pse->stat_addr_maxcount ; count++ , index++ , p_stat_addr++ )
	{
		if( index >= pse->stat_addr_maxcount )
		{
			index = 0 ;
			p_stat_addr = & (pse->stat_addr[0]) ;
		}
		
		if( strcmp( p_stat_addr->netaddr.ip , ip ) == 0 )
		{
			p_stat_addr->connection_count--;
			if( p_stat_addr->connection_count == 0 )
			{
				memset( p_stat_addr , 0x00 , sizeof(struct StatNetAddress) );
			}
			return 0;
		}
	}
	
	return 1;
}

/* 从epoll连接池取一个未用单元 */ /* fetch an unused unit from the epoll connection pool */
static int GetForwardSessionUnusedUnit( struct ServerEnv *pse , struct ForwardSession **pp_forward_session )
{
	unsigned long		index ;
	unsigned long		count ;
	struct ForwardSession	*p_forward_session = NULL ;
	
	for( count = 0 , index = pse->forward_session_use_offsetpos , p_forward_session = & (pse->forward_session[pse->forward_session_use_offsetpos])
		; count < pse->forward_session_maxcount
		; count++ , index++ , p_forward_session++ )
	{
		if( index >= pse->forward_session_maxcount )
		{
			index = 0 ;
			p_forward_session = & (pse->forward_session[0]) ;
		}
		
		if( p_forward_session->forward_session_type == FORWARD_SESSION_TYPE_UNUSED )
		{
			memset( p_forward_session , 0x00 , sizeof(struct ForwardSession) );
			(*pp_forward_session) = p_forward_session ;
			pse->forward_session_use_offsetpos = ( ( pse->forward_session_use_offsetpos + 1 ) % pse->forward_session_maxcount ) ;
			return FOUND;
		}
	}
	
	return NOT_FOUND;
}

/* 把一个epoll连接池单元设置为未用状态 */ /* set an unit to unused */
static int SetForwardSessionUnitUnused( struct ServerEnv *pse , struct ForwardSession *p_forward_session )
{
	UnregisterStatAddress( pse , p_forward_session->client_addr.netaddr.ip );
	memset( p_forward_session , 0x00 , sizeof(struct ForwardSession) );
	return 0;
}

static int SetForwardSessionUnitUnused2( struct ServerEnv *pse , struct ForwardSession *p_forward_client_session , struct ForwardSession *p_forward_server_session )
{
	UnregisterStatAddress( pse , p_forward_client_session->client_addr.netaddr.ip );
	memset( p_forward_client_session , 0x00 , sizeof(struct ForwardSession) );
	memset( p_forward_server_session , 0x00 , sizeof(struct ForwardSession) );
	return 0;
}

/* 查询转发规则 */ /* query forward rule */
static int QueryForwardRule( struct ServerEnv *pse , char *rule_id , struct ForwardRule **pp_forward_rule , unsigned long *p_index )
{
	unsigned long		index ;
	struct ForwardRule	*p_forward_rule = NULL ;
	
	for( index = 0 , p_forward_rule = & (pse->forward_rule[0]) ; index < pse->forward_rule_count ; index++ , p_forward_rule++ )
	{
		if( strcmp( p_forward_rule->rule_id , rule_id ) == 0 )
		{
			if( pp_forward_rule )
				(*pp_forward_rule) = p_forward_rule ;
			if( p_index )
				(*p_index) = index ;
			return FOUND;
		}
	}
	
	return NOT_FOUND;
}

/* 按转发规则强制保持所有相关网络连接 */ /* keep all related network connection */
static int KeepSessionWithRuleForcely( struct ServerEnv *pse , struct ForwardRule *p_forward_rule )
{
	unsigned long		index ;
	struct ForwardSession	*p_forward_session = NULL ;
	
	for( index = 0 , p_forward_session = & (pse->forward_session[0])
		; index < pse->forward_session_maxcount
		; index++ , p_forward_session++ )
	{
		if( p_forward_session->p_forward_rule == p_forward_rule )
		{
			memcpy( & (p_forward_session->old_forward_rule) , p_forward_rule , sizeof(struct ForwardRule) );
			p_forward_session->p_forward_rule = & (p_forward_session->old_forward_rule) ;
		}
	}
	
	return 0;
}

/* 按转发规则强制断开所有相关网络连接 */ /* disconnect all relevant network connection */
static int CloseSocketWithRuleForcely( struct ServerEnv *pse )
{
	unsigned long		index ;
	struct ForwardSession	*p_forward_session = NULL ;
	
	for( index = 0 , p_forward_session = & (pse->forward_session[0])
		; index < pse->forward_session_maxcount
		; index++ , p_forward_session++ )
	{
		if( p_forward_session->p_forward_rule == & (p_forward_session->old_forward_rule) )
		{
			if( p_forward_session->forward_session_type == FORWARD_SESSION_TYPE_CLIENT )
			{
				InfoOutput( pse , "close #%d# , forcely\r\n" , p_forward_session->client_addr.sock );
#ifdef USE_EPOLL
				epoll_ctl( pse->epoll_fds , EPOLL_CTL_DEL , p_forward_session->client_addr.sock , NULL );
#endif
				_CLOSESOCKET( p_forward_session->client_addr.sock );
				SetForwardSessionUnitUnused( pse , p_forward_session );
			}
			else if( p_forward_session->forward_session_type == FORWARD_SESSION_TYPE_SERVER )
			{
				InfoOutput( pse , "close #%d# , forcely\r\n" , p_forward_session->server_addr.sock );
#ifdef USE_EPOLL
				epoll_ctl( pse->epoll_fds , EPOLL_CTL_DEL , p_forward_session->server_addr.sock , NULL );
#endif
				_CLOSESOCKET( p_forward_session->server_addr.sock );
				SetForwardSessionUnitUnused( pse , p_forward_session );
			}
		}
	}
	
	return 0;
}

/* 如果没有绑定侦听端口，绑定之，并登记到epoll池 */ /* If there is no binding listener port, bindings, and register to the epoll pool */
static int BinListenSocket( struct ServerEnv *pse , struct ForwardRule *p_forward_rule , struct ForwardNetAddress *p_forward_addr )
{
	unsigned long		forward_session_index ;
	struct ForwardSession	*p_forward_session = NULL ;
#ifdef USE_EPOLL
	struct epoll_event	event ;
#endif
	
	int			nret = 0 ;
	
	/* 判断是否太多转发规则 */ /* determine whether too many rules */
	if( pse->forward_session_count >= pse->forward_session_maxcount )
	{
		ErrorOutput( pse , "too many listen addr\r\n" );
		return -91;
	}
	
	/* 判断是否有重复转发规则 */ /* determine whether there is a repeat rules */
	for( forward_session_index = 0 , p_forward_session = & ( pse->forward_session[0] )
		; forward_session_index < pse->forward_session_maxcount
		; forward_session_index++ , p_forward_session++ )
	{
		if( p_forward_session->forward_session_type == FORWARD_SESSION_TYPE_LISTEN )
		{
			if(	strcmp( p_forward_session->listen_addr.netaddr.ip , p_forward_addr->netaddr.ip ) == 0
				&&
				p_forward_session->listen_addr.netaddr.port == p_forward_addr->netaddr.port )
			{
				return 1;
			}
		}
	}
	
	/* 创建侦听端口，登记转发会话，登记epoll池 */ /* create a listener port, registration forwarding sessions, epoll pool */
	nret = GetForwardSessionUnusedUnit( pse , & p_forward_session ) ;
	if( nret != FOUND )
	{
		ErrorOutput( pse , "too many listen addr\r\n" );
		return -92;
	}
	
	strcpy( p_forward_session->listen_addr.rule_mode , p_forward_rule->rule_mode );
	strcpy( p_forward_session->listen_addr.netaddr.ip , p_forward_addr->netaddr.ip );
	strcpy( p_forward_session->listen_addr.netaddr.port , p_forward_addr->netaddr.port );
	
	p_forward_session->listen_addr.sock = socket( AF_INET , SOCK_STREAM , IPPROTO_TCP );
	if( p_forward_session->listen_addr.sock < 0 )
	{
		ErrorOutput( pse , "socket failed[%d]errno[%d]\r\n" , p_forward_session->listen_addr.sock , _ERRNO );
		return -93;
	}
	
	SetReuseAddr( p_forward_session->listen_addr.sock );
	SetNonBlocking( p_forward_session->listen_addr.sock );
	
	memset( & (p_forward_session->listen_addr.netaddr.sockaddr) , 0x00 , sizeof(p_forward_session->listen_addr.netaddr.sockaddr) );
	p_forward_session->listen_addr.netaddr.sockaddr.sin_family = AF_INET ;
	p_forward_session->listen_addr.netaddr.sockaddr.sin_addr.s_addr = inet_addr( p_forward_session->listen_addr.netaddr.ip ) ;
	p_forward_session->listen_addr.netaddr.sockaddr.sin_port = htons( (unsigned short)atoi(p_forward_session->listen_addr.netaddr.port) );
	
	nret = bind( p_forward_session->listen_addr.sock , (struct sockaddr *) & (p_forward_session->listen_addr.netaddr.sockaddr) , sizeof(struct sockaddr) ) ;
	if( nret )
	{
		ErrorOutput( pse , "bind[%s:%s] failed[%d]errno[%d]\r\n" , p_forward_session->listen_addr.netaddr.ip , p_forward_session->listen_addr.netaddr.port , nret , _ERRNO );
		return -94;
	}
	
	nret = listen( p_forward_session->listen_addr.sock , 1024 ) ;
	if( nret )
	{
		ErrorOutput( pse , "listen[%s:%s] failed[%d]errno[%d]\r\n" , p_forward_session->listen_addr.netaddr.ip , p_forward_session->listen_addr.netaddr.port , nret , _ERRNO );
		return -95;
	}
	
	p_forward_session->forward_session_type = FORWARD_SESSION_TYPE_LISTEN ;
	
#ifdef USE_EPOLL
	memset( & event , 0x00 , sizeof(event) );
	event.data.ptr = p_forward_session ;
	event.events = EPOLLIN | EPOLLET ;
	epoll_ctl( pse->epoll_fds , EPOLL_CTL_ADD , p_forward_session->listen_addr.sock , & event );
#endif
	
	pse->forward_session_count++;
	
	p_forward_addr->sock = p_forward_session->listen_addr.sock ;
	
	return 0;
}

/* 新增一条转发规则 */ /* new a forwarding rule */
static int AddForwardRule( struct ServerEnv *pse , struct ForwardRule *p_forward_rule )
{
	int		nret = 0 ;
	
	if( pse->forward_rule_count >= pse->cmd_para.forward_rule_maxcount )
	{
		ErrorOutput( pse , "too many forward rule\r\n" );
		return -1;
	}
	
	nret = QueryForwardRule( pse , p_forward_rule->rule_id , NULL , NULL ) ;
	if( nret == FOUND )
	{
		ErrorOutput( pse , "forward rule rule_id[%s] found\r\n" , p_forward_rule->rule_id );
		return -2;
	}
	
	/*
	if( strcmp( p_forward_rule->rule_mode , FORWARD_RULE_MODE_G ) == 0 )
	{
	*/
		nret = BinListenSocket( pse , p_forward_rule , p_forward_rule->forward_addr ) ;
		if( nret < 0 )
		{
			ErrorOutput( pse , "BinListenSocket failed[%d]\r\n" , nret );
			return -3;
		}
	/*
	}
	*/
	
	memcpy( & (pse->forward_rule[pse->forward_rule_count]) , p_forward_rule , sizeof(struct ForwardRule) );
	pse->forward_rule_count++;
	
	return 0;
}

/* 修改一条转发规则 */ /* modify a forwarding rule */
static int ModifyForwardRule( struct ServerEnv *pse , struct ForwardRule *p_forward_rule )
{
	struct ForwardRule	*p = NULL ;
	
	int			nret = 0 ;
	
	nret = QueryForwardRule( pse , p_forward_rule->rule_id , & p , NULL ) ;
	if( nret == NOT_FOUND )
	{
		ErrorOutput( pse , "forward rule rule_id[%s] not found\r\n" , p_forward_rule->rule_id );
		return -1;
	}
	
	if( strcmp( p_forward_rule->rule_mode , FORWARD_RULE_MODE_G ) == 0 )
	{
		nret = BinListenSocket( pse , p_forward_rule , p_forward_rule->forward_addr ) ;
		if( nret < 0 )
		{
			ErrorOutput( pse , "BinListenSocket failed[%d]\r\n" , nret );
			return -2;
		}
		else if( nret == 0 )
		{
			InfoOutput( pse , "LISTEN #%d#\r\n" , p_forward_rule->forward_addr->sock );
		}
	}
	
	KeepSessionWithRuleForcely( pse , p );
	
	memcpy( p , p_forward_rule , sizeof(struct ForwardRule) );
	
	return 0;
}

/* 删除一条转发规则 */ /* remove a forwarding rule */
static int RemoveForwardRule( struct ServerEnv *pse , char *rule_id )
{
	struct ForwardRule	*p_forward_rule = NULL ;
	unsigned long		index ;
	
	int			nret = 0 ;
	
	if( pse->forward_rule_count == 0 )
	{
		ErrorOutput( pse , "no forward rule exist\r\n" );
		return -1;
	}
	
	nret = QueryForwardRule( pse , rule_id , & p_forward_rule , & index ) ;
	if( nret == NOT_FOUND )
	{
		ErrorOutput( pse , "forward rule rule_id[%s] not found\r\n" , rule_id );
		return -2;
	}
	
	KeepSessionWithRuleForcely( pse , p_forward_rule );
	
	memmove( & (pse->forward_rule[index]) , & (pse->forward_rule[index+1]) , sizeof(struct ForwardRule) * (pse->forward_rule_count-index-1) );
	memset( & (pse->forward_rule[pse->forward_rule_count-1]) , 0x00 , sizeof(struct ForwardRule) );
	pse->forward_rule_count--;
	
	return 0;
}

/* 从配置段中解析网络地址 */ /* analytical network address from a configuration section */
static int ParseIpAndPort( char *ip_and_port , struct NetAddress *paddr )
{
	char		*p_colon = NULL ;
	
	p_colon = strchr( ip_and_port , ':' ) ;
	if( p_colon == NULL )
		return -1;
	
	strncpy( paddr->ip , ip_and_port , p_colon - ip_and_port );
	strcpy( paddr->port , p_colon + 1 );
	
	return 0;
}

/* 装载单条转发配置 */ /* load a single rule configuration */
static int GetRuleProperty( char **pp_property_key , char **pp_property_value )
{
	(*pp_property_key) = strtok( NULL , " \t\r\r\n" ) ;
	if( (*pp_property_key) == NULL )
		return -30;
	
	if( strcmp( (*pp_property_key) , ")" ) == 0 )
		return 1;
	
	(*pp_property_value) = strtok( NULL , " \t\r\r\n" ) ;
	if( (*pp_property_value) == NULL )
		return -30;
	
	return 0;
}

static int LoadGlobalProperty( struct ServerEnv *pse )
{
	char		*property_key = NULL ;
	char		*property_value = NULL ;
	
	int		nret = 0 ;
	
	while( ( nret = GetRuleProperty( & property_key , & property_value ) ) == 0 )
	{
		if( strcmp( property_key , "maxsessions_per_ip" ) == 0 )
		{
			pse->maxsessions_per_ip = atol(property_value) ;
			InfoOutput( pse , " ( maxsessions_per_ip %ld )\r\n" , pse->maxsessions_per_ip );
		}
		else
		{
			ErrorOutput( pse , "global property key[%s] invalid\r\n" , property_key );
			return -30;
		}
	}
	if( nret < 0 )
	{
		ErrorOutput( pse , "property invalid\r\n" );
		return nret;
	}
	
	return 0;
}

static int LoadForwardConfig( struct ServerEnv *pse , char *buffer , char *rule_id , struct ForwardRule *p_forward_rule )
{
	char				*p_begin = NULL ;
	char				*property_key = NULL ;
	char				*property_value = NULL ;
	
	unsigned long			client_session_index ;
	struct ClientNetAddress		*p_client_addr = NULL ;
	unsigned long			forward_index ;
	struct ForwardNetAddress	*p_forward_addr = NULL ;
	unsigned long			server_session_index ;
	struct ServerNetAddress		*p_server_addr = NULL ;
	
	int				nret = 0 ;
	
	memset( p_forward_rule , 0x00 , sizeof(struct ForwardRule) );
	
	strcpy( p_forward_rule->rule_id , rule_id );
	
	p_begin = strtok( buffer , " \t\r\r\n" ) ;
	if( p_begin == NULL )
	{
		ErrorOutput( pse , "expect rule rule_mode\r\n" );
		return -21;
	}
	if( strlen(p_begin) > RULE_MODE_MAXLEN )
	{
		ErrorOutput( pse , "rule rule_mode too long\r\n" );
		return -22;
	}
	strcpy( p_forward_rule->rule_mode , p_begin );
	
	if( strcmp( p_forward_rule->rule_mode , FORWARD_RULE_MODE_G )
		&& strcmp( p_forward_rule->rule_mode , FORWARD_RULE_MODE_MS )
		&& strcmp( p_forward_rule->rule_mode , FORWARD_RULE_MODE_RR )
		&& strcmp( p_forward_rule->rule_mode , FORWARD_RULE_MODE_LC )
		&& strcmp( p_forward_rule->rule_mode , FORWARD_RULE_MODE_RT )
		&& strcmp( p_forward_rule->rule_mode , FORWARD_RULE_MODE_RD )
		&& strcmp( p_forward_rule->rule_mode , FORWARD_RULE_MODE_HS ) )
	{
		ErrorOutput( pse , "rule rule_mode [%s] invalid\r\n" , p_forward_rule->rule_mode );
		return -23;
	}
	
	InfoOutput( pse , "%s %s" , p_forward_rule->rule_id , p_forward_rule->rule_mode );
	
	for( client_session_index = 0 , p_client_addr = & (p_forward_rule->client_addr[0]) ; client_session_index < RULE_CLIENT_MAXCOUNT ; )
	{
		p_begin = strtok( NULL , " \t\r\r\n" ) ;
		if( p_begin == NULL )
		{
			ErrorOutput( pse , "expect client addr\r\n" );
			return -31;
		}
		
		if( client_session_index == 0 && strcmp( p_begin , "(" ) == 0 )
		{
			while( ( nret = GetRuleProperty( & property_key , & property_value ) ) == 0 )
			{
				if( strcmp( property_key , "timeout" ) == 0 )
				{
					p_forward_rule->timeout = atol(property_value) ;
					InfoOutputNoPrefix( pse , " ( timeout %ld )" , p_forward_rule->timeout );
				}
				else
				{
					ErrorOutput( pse , "rule property key[%s] invalid\r\n" , property_key );
					return -30;
				}
			}
			if( nret < 0 )
			{
				ErrorOutput( pse , "rule invalid\r\n" );
				return nret;
			}
			
			continue;
		}
		else if( strcmp( p_begin , "(" ) == 0 )
		{
			if( client_session_index > 0 )
			{
				while( ( nret = GetRuleProperty( & property_key , & property_value ) ) == 0 )
				{
					if( strcmp( property_key , "maxclients" ) == 0 )
					{
						p_forward_rule->client_addr[client_session_index-1].maxclients = atol(property_value) ;
						InfoOutputNoPrefix( pse , " ( maxclients %ld )" , p_forward_rule->client_addr[client_session_index-1].maxclients );
					}
					else
					{
						ErrorOutput( pse , "client property key[%s] invalid\r\n" , property_key );
						return -30;
					}
				}
				if( nret < 0 )
				{
					ErrorOutput( pse , "rule invalid\r\n" );
					return nret;
				}
			}
			
			continue;
		}
		
		if( strcmp( p_begin , "-" ) == 0 || strcmp( p_begin , ";" ) == 0 )
			break;
		
		nret = ParseIpAndPort( p_begin , & (p_client_addr->netaddr) ) ;
		if( nret )
		{
			ErrorOutput( pse , "client addr[%s] invalid[%d]\r\n" , p_begin , nret );
			return -32;
		}
		
		InfoOutputNoPrefix( pse , " %s:%s" , p_client_addr->netaddr.ip , p_client_addr->netaddr.port );
		
		client_session_index++ , p_client_addr++ , p_forward_rule->client_count++ ;
	}
	
	if( strcmp( p_begin , ";" ) != 0 )
	{
		InfoOutputNoPrefix( pse , " -" );
		
		for( forward_index = 0 , p_forward_addr = & (p_forward_rule->forward_addr[0]) ; forward_index < RULE_CLIENT_MAXCOUNT ; )
		{
			p_begin = strtok( NULL , " \t\r\r\n" ) ;
			if( p_begin == NULL )
			{
				ErrorOutput( pse , "expect forward addr\r\n" );
				return -41;
			}
			
			if( strcmp( p_begin , ">" ) == 0 || strcmp( p_begin , ";" ) == 0 )
				break;
			
			nret = ParseIpAndPort( p_begin , & (p_forward_addr->netaddr) ) ;
			if( nret )
			{
				ErrorOutput( pse , "forward addr[%s] invalid[%d]\r\n" , p_begin , nret );
				return -42;
			}
			
			InfoOutputNoPrefix( pse , " %s:%s" , p_forward_addr->netaddr.ip , p_forward_addr->netaddr.port );
			
			/*
			nret = BinListenSocket( pse , p_forward_rule , p_forward_addr ) ;
			if( nret < 0 )
			{
				return nret;
			}
			else if( nret == 0 )
			{
				InfoOutputNoPrefix( pse , "LISTEN #%d#" , p_forward_addr->sock );
			}
			*/
			
			forward_index++ , p_forward_addr++ , p_forward_rule->forward_count++ ;
		}
		
		if( strcmp( p_begin , ";" ) != 0 )
		{
			InfoOutputNoPrefix( pse , " >" );
			
			for( server_session_index = 0 , p_server_addr = & (p_forward_rule->server_addr[0]) ; server_session_index < RULE_CLIENT_MAXCOUNT ; )
			{
				p_begin = strtok( NULL , " \t\r\r\n" ) ;
				if( p_begin == NULL )
				{
					fprintf( stderr , "expect server addr\r\n" );
					return -51;
				}
				
				if( strcmp( p_begin , ";" ) == 0 )
					break;
				
				nret = ParseIpAndPort( p_begin , & (p_server_addr->netaddr) ) ;
				if( nret )
				{
					fprintf( stderr , "server addr[%s] invalid[%d]\r\n" , p_begin , nret );
					return -52;
				}
				
				InfoOutputNoPrefix( pse , " %s:%s" , p_server_addr->netaddr.ip , p_server_addr->netaddr.port );
				
				server_session_index++ , p_server_addr++ , p_forward_rule->server_count++ ;
			}
		}
	}
	
	InfoOutputNoPrefix( pse , " ;\r\n" );
	
	if( strcmp( p_forward_rule->rule_mode , FORWARD_RULE_MODE_G ) == 0 )
	{
		if( p_forward_rule->server_count > 0 )
		{
			fprintf( stderr , "rule rule_mode [%s] unexpect server_addr\r\n" , p_forward_rule->rule_mode );
			return -61;
		}
	}
	else
	{
		if( p_forward_rule->forward_count == 0 )
		{
			ErrorOutput( pse , "rule rule_mode [%s] expect forward_addr\r\n" , p_forward_rule->rule_mode );
			return -62;
		}
		if( p_forward_rule->server_count == 0 )
		{
			ErrorOutput( pse , "rule rule_mode [%s] expect server_addr\r\n" , p_forward_rule->rule_mode );
			return -63;
		}
	}
	
	return 0;
}

/* 装载所有配置 */ /* load all configuration */
static int LoadConfig( struct ServerEnv *pse )
{
	FILE				*fp = NULL ;
	char				buffer[ 1024 + 1 ] ;
	char				*pbuffer = NULL ;
	
	char				*p_remark = NULL ;
	char				*p_begin = NULL ;
	struct ForwardRule		forward_rule ;
	
	int				nret = 0 ;
	
	fp = fopen( pse->cmd_para.config_pathfilename , "r" ) ;
	if( fp == NULL )
	{
		ErrorOutput( pse , "can't open config file [%s]\r\n" , pse->cmd_para.config_pathfilename );
		return -1;
	}
	
	while( fgets( buffer , sizeof(buffer)-1 , fp ) )
	{
		p_remark = strchr( buffer , '#' ) ;
		if( p_remark )
		{
			(*p_remark) = '\0' ;
		}
		
		p_begin = strtok( buffer , " \t\r\r\n" ) ;
		if( p_begin == NULL )
		{
			continue;
		}
		
		if( strcmp( p_begin , "(" ) == 0 )
		{
			nret = LoadGlobalProperty( pse ) ;
			if( nret > 0 )
			{
				continue;
			}
			else if( nret < 0 )
			{
				ErrorOutput( pse , "LoadGlobalProperty failed[%d]\r\n" , nret );
				fclose(fp);
				return nret;
			}
		}
		else
		{
			if( strlen(p_begin) > RULE_ID_MAXLEN )
			{
				ErrorOutput( pse , "rule rule_id too long\r\n" );
				return -12;
			}
			
			pbuffer = strtok( NULL , "" ) ;
			
			nret = LoadForwardConfig( pse , pbuffer , p_begin , & forward_rule ) ;
			if( nret > 0 )
			{
				continue;
			}
			else if( nret < 0 )
			{
				ErrorOutput( pse , "LoadForwardConfig failed[%d]\r\n" , nret );
				fclose(fp);
				return nret;
			}
			else
			{
				nret = AddForwardRule( pse , & forward_rule ) ;
				if( nret )
				{
					fclose(fp);
					return nret;
				}
			}
		}
	}
	
	fclose(fp);
	
	return 0;
}

/* 判断字符串匹配性 */ /* judgment of string matching */
static int IsMatchString(char *pcMatchString, char *pcObjectString, char cMatchMuchCharacters, char cMatchOneCharacters)
{
	int el=strlen(pcMatchString);
	int sl=strlen(pcObjectString);
	char cs,ce;

	int is,ie;
	int last_xing_pos=-1;

	for(is=0,ie=0;is<sl && ie<el;){
		cs=pcObjectString[is];
		ce=pcMatchString[ie];

		if(cs!=ce){
			if(ce==cMatchMuchCharacters){
				last_xing_pos=ie;
				ie++;
			}else if(ce==cMatchOneCharacters){
				is++;
				ie++;
			}else if(last_xing_pos>=0){
				while(ie>last_xing_pos){
					ce=pcMatchString[ie];
					if(ce==cs)
						break;
					ie--;
				}

				if(ie==last_xing_pos)
					is++;
			}else
				return -1;
		}else{
			is++;
			ie++;
		}
	}

	if(pcObjectString[is]==0 && pcMatchString[ie]==0)
		return 0;

	if(pcMatchString[ie]==0)
		ie--;

	if(ie>=0){
		while(pcMatchString[ie])
			if(pcMatchString[ie++]!=cMatchMuchCharacters)
				return -2;
	} 

	return 0;
}

/* 判断客户端网络地址是否匹配 */ /* whether the client network address matching */
static int MatchClientAddr( struct ClientNetAddress *p_client_addr , struct ForwardRule *p_forward_rule , unsigned long *p_client_index )
{
	unsigned long			match_addr_index ;
	struct ClientNetAddress		*p_match_addr = NULL ;
	
	for( match_addr_index = 0 , p_match_addr = & (p_forward_rule->client_addr[0])
		; match_addr_index < p_forward_rule->client_count
		; match_addr_index++ , p_match_addr++ )
	{
		if(	IsMatchString( p_match_addr->netaddr.ip , p_client_addr->netaddr.ip , '*' , '?' ) == 0
			&&
			IsMatchString( p_match_addr->netaddr.port , p_client_addr->netaddr.port , '*' , '?' ) == 0
		)
		{
			(*p_client_index) = match_addr_index ;
			return MATCH;
		}
	}
	
	return NOT_MATCH;
}

/* 判断本地侦听端网络地址是否匹配 */ /* determine local listener port network address is matched */
static int MatchForwardAddr( struct ListenNetAddress *p_listen_addr , struct ForwardRule *p_forward_rule )
{
	unsigned long			match_addr_index ;
	struct ForwardNetAddress	*p_match_addr = NULL ;
	
	for( match_addr_index = 0 , p_match_addr = & (p_forward_rule->forward_addr[0])
		; match_addr_index < p_forward_rule->forward_count
		; match_addr_index++ , p_match_addr++ )
	{
		if(	IsMatchString( p_match_addr->netaddr.ip , p_listen_addr->netaddr.ip , '*' , '?' ) == 0
			&&
			IsMatchString( p_match_addr->netaddr.port , p_listen_addr->netaddr.port , '*' , '?' ) == 0
		)
		{
			return MATCH;
		}
	}
	
	return NOT_MATCH;
}

/* 判断转发规则是否匹配 */ /* to determine whether a forwarding rule matching */
static int MatchForwardRule( struct ServerEnv *pse , struct ClientNetAddress *p_client_addr , struct ListenNetAddress *p_listen_addr , struct ForwardRule **pp_forward_rule , unsigned long *p_client_index )
{
	unsigned long		forward_no ;
	struct ForwardRule	*p_forward_rule = NULL ;
	
	for( forward_no = 0 , p_forward_rule = & (pse->forward_rule[0]) ; forward_no < pse->forward_rule_count ; forward_no++ , p_forward_rule++ )
	{
		if( MatchForwardAddr( p_listen_addr , p_forward_rule ) == MATCH && MatchClientAddr( p_client_addr , p_forward_rule , p_client_index ) == MATCH )
		{
			(*pp_forward_rule) = p_forward_rule ;
			return FOUND;
		}
	}
	
	return NOT_FOUND;
}

/* 从目标网络地址中根据不同算法选择一个目标网络地址 */ /* according to the different algorithms to choose a target network address from the target network addresses */
static int SelectServerAddress( struct ServerEnv *pse , struct ClientNetAddress *p_client_addr , struct ForwardRule *p_forward_rule , char *ip , char *port )
{
	if( strcmp( p_forward_rule->rule_mode , FORWARD_RULE_MODE_MS ) == 0 )
	{
		strcpy( ip , p_forward_rule->server_addr[p_forward_rule->select_index].netaddr.ip );
		strcpy( port , p_forward_rule->server_addr[p_forward_rule->select_index].netaddr.port );
	}
	else if( strcmp( p_forward_rule->rule_mode , FORWARD_RULE_MODE_RR ) == 0 )
	{
		while(1)
		{
			if( p_forward_rule->status.RR[p_forward_rule->select_index].server_unable <= 0 )
			{
				strcpy( ip , p_forward_rule->server_addr[p_forward_rule->select_index].netaddr.ip );
				strcpy( port , p_forward_rule->server_addr[p_forward_rule->select_index].netaddr.port );
				
				p_forward_rule->select_index = ( (p_forward_rule->select_index+1) % p_forward_rule->server_count ) ;
				
				return 0;
			}
			else
			{
				p_forward_rule->status.RR[p_forward_rule->select_index].server_unable--;
			}
			
			p_forward_rule->select_index++;
			if( p_forward_rule->select_index >= p_forward_rule->server_count )
				p_forward_rule->select_index = 0 ;
		}
	}
	else if( strcmp( p_forward_rule->rule_mode , FORWARD_RULE_MODE_LC ) == 0 )
	{
		unsigned long		index , count ;
		unsigned long		server_connection_count ;
		
		index = p_forward_rule->select_index + 1 ;
		p_forward_rule->select_index = -1 ;
		server_connection_count = ULONG_MAX ;
		while( p_forward_rule->select_index == -1 )
		{
			for( count = 0 ; count < p_forward_rule->server_count ; index++ , count++ )
			{
				if( index >= p_forward_rule->server_count )
				{
					index = 0 ;
				}
				
				if( p_forward_rule->status.LC[index].server_unable <= 0 )
				{
					if( p_forward_rule->server_addr[index].server_connection_count < server_connection_count )
					{
						p_forward_rule->select_index = index ;
						server_connection_count = p_forward_rule->server_addr[index].server_connection_count ;
					}
				}
				else 
				{
					p_forward_rule->status.LC[index].server_unable--;
				}
			}
		}
		
		strcpy( ip , p_forward_rule->server_addr[p_forward_rule->select_index].netaddr.ip );
		strcpy( port , p_forward_rule->server_addr[p_forward_rule->select_index].netaddr.port );
	}
	else if( strcmp( p_forward_rule->rule_mode , FORWARD_RULE_MODE_RT ) == 0 )
	{
		unsigned long		index , count ;
		unsigned long		dtt ;
		/*
		unsigned long		dt ;
		*/
		
		index = p_forward_rule->select_index + 1 ;
		p_forward_rule->select_index = -1 ;
		dtt = ULONG_MAX ;
		while( p_forward_rule->select_index == -1 )
		{
			for( count = 0 ; count < p_forward_rule->server_count ; index++ , count++ )
			{
				if( index >= p_forward_rule->server_count )
				{
					index = 0 ;
				}
				
				if( p_forward_rule->status.RT[index].server_unable <= 0 )
				{
					if( p_forward_rule->status.RT[index].tv1.tv_sec == 0 || p_forward_rule->status.RT[index].tv2.tv_sec == 0 )
					{
						p_forward_rule->select_index = index ;
						break;
					}
					
					p_forward_rule->status.RT[index].dtv.tv_sec = abs( p_forward_rule->status.RT[index].tv1.tv_sec - p_forward_rule->status.RT[index].tv2.tv_sec ) ;
					/*
					p_forward_rule->status.RT[index].dtv.tv_usec = abs( p_forward_rule->status.RT[index].tv1.tv_usec - p_forward_rule->status.RT[index].tv2.tv_usec ) ;
					dt = p_forward_rule->status.RT[index].dtv.tv_sec * 1000000 + p_forward_rule->status.RT[index].dtv.tv_usec ;
					*/
					if( (unsigned long)(p_forward_rule->status.RT[index].dtv.tv_sec) < dtt )
					{
						p_forward_rule->select_index = index ;
						dtt = p_forward_rule->status.RT[index].dtv.tv_sec ;
					}
				}
				else
				{
					p_forward_rule->status.RT[index].server_unable--;
				}
			}
		}
		
		strcpy( ip , p_forward_rule->server_addr[p_forward_rule->select_index].netaddr.ip );
		strcpy( port , p_forward_rule->server_addr[p_forward_rule->select_index].netaddr.port );
	}
	else if( strcmp( p_forward_rule->rule_mode , FORWARD_RULE_MODE_RD ) == 0 )
	{
		p_forward_rule->select_index = FetchRand( 0 , p_forward_rule->server_count - 1 ) ;
		
		strcpy( ip , p_forward_rule->server_addr[p_forward_rule->select_index].netaddr.ip );
		strcpy( port , p_forward_rule->server_addr[p_forward_rule->select_index].netaddr.port );
	}
	else if( strcmp( p_forward_rule->rule_mode , FORWARD_RULE_MODE_HS ) == 0 )
	{
		p_forward_rule->select_index = CalcHash( p_client_addr->netaddr.ip ) % p_forward_rule->server_count ;
		
		strcpy( ip , p_forward_rule->server_addr[p_forward_rule->select_index].netaddr.ip );
		strcpy( port , p_forward_rule->server_addr[p_forward_rule->select_index].netaddr.port );
	}
	else
	{
		ErrorOutput( pse , "'rule_mode'[%s] invalid\r\n" , p_forward_rule->rule_mode );
		return -1;
	}
	
	return 0;
}

/* 当目标网络地址不可用时，根据不同算法做相应处理 */ /* when the target network address is unavailable, according to the different algorithms accordingly  */
static int OnServerUnable( struct ServerEnv *pse , struct ForwardRule *p_forward_rule )
{
	if( strcmp( p_forward_rule->rule_mode , FORWARD_RULE_MODE_MS ) == 0 )
	{
		p_forward_rule->select_index = ( (p_forward_rule->select_index+1) % p_forward_rule->server_count ) ;
	}
	else if( strcmp( p_forward_rule->rule_mode , FORWARD_RULE_MODE_RR ) == 0 )
	{
		p_forward_rule->status.RR[p_forward_rule->select_index].server_unable = SERVER_UNABLE_IGNORE_COUNT ;
	}
	else if( strcmp( p_forward_rule->rule_mode , FORWARD_RULE_MODE_LC ) == 0 )
	{
		p_forward_rule->status.LC[p_forward_rule->select_index].server_unable = SERVER_UNABLE_IGNORE_COUNT ;
	}
	else if( strcmp( p_forward_rule->rule_mode , FORWARD_RULE_MODE_RT ) == 0 )
	{
		p_forward_rule->status.RT[p_forward_rule->select_index].server_unable = SERVER_UNABLE_IGNORE_COUNT ;
	}
	else if( strcmp( p_forward_rule->rule_mode , FORWARD_RULE_MODE_RD ) == 0 )
	{
	}
	else if( strcmp( p_forward_rule->rule_mode , FORWARD_RULE_MODE_HS ) == 0 )
	{
	}
	else
	{
		ErrorOutput( pse , "'rule_mode'[%s] invalid\r\n" , p_forward_rule->rule_mode );
		return -1;
	}
	
	return 0;
}

/* 接受管理端口连接 */ /* accept the management port connection */
static int AcceptManageSocket( struct ServerEnv *pse , struct ForwardSession *p_forward_session )
{
	_SOCKLEN_T		addr_len = sizeof(struct sockaddr_in) ;
	
	struct ClientNetAddress	client_addr ;
#ifdef USE_EPOLL
	struct epoll_event	client_event ;
#endif
	
	struct ForwardRule	*p_forward_rule = NULL ;
	unsigned long		client_index ;
	
	struct ForwardSession	*p_forward_session_client = NULL ;
	
	int			nret = 0 ;
	
	/* 循环接受管理端口连接 */
	while(1)
	{
		/* 接受管理端口连接 */ /* accept the management port connection */
		client_addr.sock = accept( p_forward_session->listen_addr.sock , (struct sockaddr *) & (client_addr.netaddr.sockaddr) , & addr_len ) ;
		if( client_addr.sock < 0 )
		{
			if( _ERRNO == _EWOULDBLOCK || _ERRNO == _ECONNABORTED )
				break;
			
			ErrorOutput( pse , "accept[%d] failed[%d]errno[%d]\r\n" , p_forward_session->listen_addr.sock , client_addr.sock  , _ERRNO );
			return 1;
		}
		
		SetNonBlocking( client_addr.sock );
		SetReuseAddr( client_addr.sock );
		
		strcpy( client_addr.netaddr.ip , inet_ntoa( client_addr.netaddr.sockaddr.sin_addr ) );
		sprintf( client_addr.netaddr.port , "%ld" , (unsigned long)ntohs( client_addr.netaddr.sockaddr.sin_port ) );
		
		/* 匹配转发规则 */ /* matching forward rules */
		nret = MatchForwardRule( pse , & client_addr , & (p_forward_session->listen_addr) , & p_forward_rule , & client_index ) ;
		if( nret != FOUND )
		{
			ErrorOutput( pse , "match forward rule [%s:%s] - [%s:%s] failed[%d]\r\n" , client_addr.netaddr.ip , client_addr.netaddr.port , p_forward_session->listen_addr.netaddr.ip , p_forward_session->listen_addr.netaddr.port , nret );
			_CLOSESOCKET( client_addr.sock );
			return 1;
		}
		
		/* 检查最大连接数量 */ /* check the maximum number of connections */
		if(	p_forward_rule->client_addr[client_index].maxclients > 0
			&& p_forward_rule->client_addr[client_index].client_connection_count + 1 > p_forward_rule->client_addr[client_index].maxclients )
		{
			ErrorOutput( pse , "too many manage connection\r\n" );
			_CLOSESOCKET( client_addr.sock );
			return 1;
		}
		
		/* 登记转发会话、登记epoll池 */ /* registration forwarding sessions in epoll pool  */
		nret = GetForwardSessionUnusedUnit( pse , & p_forward_session_client ) ;
		if( nret != FOUND )
		{
			ErrorOutput( pse , "GetForwardSessionUnusedUnit failed[%d]\r\n" , nret );
			_CLOSESOCKET( client_addr.sock );
			return 1;
		}
		
		p_forward_session_client->forward_session_type = FORWARD_SESSION_TYPE_MANAGE ;
		
		strcpy( p_forward_session_client->client_addr.netaddr.ip , client_addr.netaddr.ip );
		strcpy( p_forward_session_client->client_addr.netaddr.port , client_addr.netaddr.port );
		p_forward_session_client->client_addr.sock = client_addr.sock ;
		memcpy( & (p_forward_session_client->client_addr.netaddr) , & (client_addr.netaddr) , sizeof(struct sockaddr_in) );
		p_forward_session_client->client_session_index = p_forward_session_client - & (pse->forward_session[0]) ;
		
		strcpy( p_forward_session_client->listen_addr.netaddr.ip , p_forward_session->listen_addr.netaddr.ip );
		strcpy( p_forward_session_client->listen_addr.netaddr.port , p_forward_session->listen_addr.netaddr.port );
		p_forward_session_client->listen_addr.sock = p_forward_session->listen_addr.sock ;
		memcpy( & (p_forward_session_client->listen_addr.netaddr) , & (p_forward_session->listen_addr.netaddr) , sizeof(struct sockaddr_in) );
		strcpy( p_forward_session_client->listen_addr.rule_mode , p_forward_session->listen_addr.rule_mode );
		
		p_forward_session_client->p_forward_rule = p_forward_rule ;
		p_forward_session_client->client_index = client_index ;
		
		p_forward_session_client->status = CONNECT_STATUS_RECEIVING ;
		p_forward_session_client->active_timestamp = pse->server_cache.tv.tv_sec ;
		
#ifdef USE_EPOLL
		memset( & (client_event) , 0x00 , sizeof(client_event) );
		client_event.data.ptr = p_forward_session_client ;
		client_event.events = EPOLLIN | EPOLLERR | EPOLLET ;
		epoll_ctl( pse->epoll_fds , EPOLL_CTL_ADD , p_forward_session_client->client_addr.sock , & client_event );
#endif
		
		DebugOutput( pse , "accept [%s:%s]#%d# - [%s:%s]#%d# manage\r\n"
			, p_forward_session_client->client_addr.netaddr.ip , p_forward_session_client->client_addr.netaddr.port , p_forward_session_client->client_addr.sock
			, p_forward_session->listen_addr.netaddr.ip , p_forward_session->listen_addr.netaddr.port , p_forward_session->listen_addr.sock );
		
		p_forward_session_client->p_forward_rule->client_addr[p_forward_session_client->client_index].client_connection_count++;
		
		send( p_forward_session_client->client_addr.sock , "> " , 2 , 0 );
	}
	
	return 0;
}

/* 连接到目标网络地址 */ /* connect to the target network address  */
static int ConnectToRemote( struct ServerEnv *pse , struct ForwardSession *p_forward_session , struct ForwardRule *p_forward_rule , unsigned long client_index , struct ClientNetAddress *p_client_addr , unsigned long try_connect_count )
{
	_SOCKLEN_T		addr_len = sizeof(struct sockaddr_in) ;
	
	struct ServerNetAddress	server_addr ;
#ifdef USE_EPOLL
	struct epoll_event	client_event ;
	struct epoll_event	server_event ;
#endif
	
	struct ForwardSession	*p_forward_session_client = NULL ;
	struct ForwardSession	*p_forward_session_server = NULL ;
	
	int			nret = 0 ;
	
	/* 创建转连的本地客户端sock */ /* create the local client sock */
	server_addr.sock = socket( AF_INET , SOCK_STREAM , IPPROTO_TCP );
	if( server_addr.sock < 0 )
	{
		ErrorOutput( pse , "socket failed[%d]errno[%d]\r\n" , server_addr.sock , _ERRNO );
		return 1;
	}
	
	SetNonBlocking( server_addr.sock );
	
	/* 根据转发规则，选择目标网络地址 */ /* according to the rules of forwarding, select the target network address */
	nret = SelectServerAddress( pse , p_client_addr , p_forward_rule , server_addr.netaddr.ip , server_addr.netaddr.port ) ;
	if( nret )
	{
		return nret;
	}
	
	memset( & (server_addr.netaddr.sockaddr) , 0x00 , sizeof(server_addr.netaddr.sockaddr) );
	server_addr.netaddr.sockaddr.sin_family = AF_INET ;
	/* inet_aton( server_addr.netaddr.ip , & (server_addr.netaddr.sockaddr.sin_addr) ); */
	server_addr.netaddr.sockaddr.sin_addr.s_addr = inet_addr( server_addr.netaddr.ip ) ;
	server_addr.netaddr.sockaddr.sin_port = htons( (unsigned short)atoi(server_addr.netaddr.port) );
	
	/* 连接目标网络地址 */ /* connect target network address */
	nret = connect( server_addr.sock , ( struct sockaddr *) & (server_addr.netaddr.sockaddr) , addr_len );
	if( nret < 0 )
	{
		if( _ERRNO != _EINPROGRESS && _ERRNO != _EWOULDBLOCK )
		{
			ErrorOutput( pse , "connect to [%s:%s] failed[%d]errno[%d]\r\n" , server_addr.netaddr.ip , server_addr.netaddr.port , nret , _ERRNO );
			_CLOSESOCKET( server_addr.sock );
			return 1;
		}
		
		/* 登记服务端转发会话，登记epoll池 */ /* register server forwarding sessions in epoll pool  */
		nret = GetForwardSessionUnusedUnit( pse , & p_forward_session_server ) ;
		if( nret != FOUND )
		{
			ErrorOutput( pse , "GetForwardSessionUnusedUnit failed[%d]\r\n" , nret );
			_CLOSESOCKET( server_addr.sock );
			return 1;
		}
		
		p_forward_session_server->forward_session_type = FORWARD_SESSION_TYPE_SERVER ;
		
		strcpy( p_forward_session_server->client_addr.netaddr.ip , p_client_addr->netaddr.ip );
		strcpy( p_forward_session_server->client_addr.netaddr.port , p_client_addr->netaddr.port );
		p_forward_session_server->client_addr.sock = p_client_addr->sock ;
		memcpy( & (p_forward_session_server->client_addr.netaddr) , & (p_client_addr->netaddr) , sizeof(struct sockaddr_in) );
		p_forward_session_server->client_session_index = 0 ;
		
		strcpy( p_forward_session_server->listen_addr.netaddr.ip , p_forward_session->listen_addr.netaddr.ip );
		strcpy( p_forward_session_server->listen_addr.netaddr.port , p_forward_session->listen_addr.netaddr.port );
		p_forward_session_server->listen_addr.sock = p_forward_session->listen_addr.sock ;
		memcpy( & (p_forward_session_server->listen_addr.netaddr) , & (p_forward_session->listen_addr.netaddr) , sizeof(struct sockaddr_in) );
		strcpy( p_forward_session_server->listen_addr.rule_mode , p_forward_rule->rule_mode );
		
		strcpy( p_forward_session_server->server_addr.netaddr.ip , server_addr.netaddr.ip );
		strcpy( p_forward_session_server->server_addr.netaddr.port , server_addr.netaddr.port );
		p_forward_session_server->server_addr.sock = server_addr.sock ;
		memcpy( & (p_forward_session_server->server_addr.netaddr) , & (server_addr.netaddr) , sizeof(struct sockaddr_in) );
		p_forward_session_server->server_session_index = p_forward_session_server - & (pse->forward_session[0]) ;
		
		p_forward_session_server->p_forward_rule = p_forward_rule ;
		p_forward_session_server->client_index = client_index ;
		p_forward_session_server->server_index = p_forward_rule->select_index ;
		
		p_forward_session_server->status = CONNECT_STATUS_CONNECTING ;
		p_forward_session_server->try_connect_count = try_connect_count ;
		p_forward_session_server->active_timestamp = pse->server_cache.tv.tv_sec ;
		
#ifdef USE_EPOLL
		memset( & (server_event) , 0x00 , sizeof(server_event) );
		server_event.data.ptr = p_forward_session_server ;
		server_event.events = EPOLLOUT | EPOLLERR | EPOLLET ;
		epoll_ctl( pse->epoll_fds , EPOLL_CTL_ADD , p_forward_session_server->server_addr.sock , & server_event );
#endif
		
		p_forward_session_server->p_forward_rule->client_addr[p_forward_session_server->client_index].client_connection_count++;
		p_forward_session_server->p_forward_rule->server_addr[p_forward_session_server->p_forward_rule->select_index].server_connection_count++;
	}
	else
	{
		/* 登记客户端转发会话，登记epoll池 */ /* register client forwarding sessions in epoll pool  */
		nret = GetForwardSessionUnusedUnit( pse , & p_forward_session_client ) ;
		if( nret != FOUND )
		{
			ErrorOutput( pse , "GetForwardSessionUnusedUnit failed[%d]\r\n" , nret );
			_CLOSESOCKET( server_addr.sock );
			return 1;
		}
		
		p_forward_session_client->forward_session_type = FORWARD_SESSION_TYPE_CLIENT ;
		
		strcpy( p_forward_session_client->client_addr.netaddr.ip , p_client_addr->netaddr.ip );
		strcpy( p_forward_session_client->client_addr.netaddr.port , p_client_addr->netaddr.port );
		p_forward_session_client->client_addr.sock = p_client_addr->sock ;
		memcpy( & (p_forward_session_client->client_addr.netaddr) , & (p_client_addr->netaddr) , sizeof(struct sockaddr_in) );
		p_forward_session_client->client_session_index = p_forward_session_client - & (pse->forward_session[0]) ;
		
		strcpy( p_forward_session_client->listen_addr.netaddr.ip , p_forward_session->listen_addr.netaddr.ip );
		strcpy( p_forward_session_client->listen_addr.netaddr.port , p_forward_session->listen_addr.netaddr.port );
		p_forward_session_client->listen_addr.sock = p_forward_session->listen_addr.sock ;
		memcpy( & (p_forward_session_client->listen_addr.netaddr) , & (p_forward_session->listen_addr.netaddr) , sizeof(struct sockaddr_in) );
		strcpy( p_forward_session_client->listen_addr.rule_mode , p_forward_rule->rule_mode );
		
		strcpy( p_forward_session_client->server_addr.netaddr.ip , server_addr.netaddr.ip );
		strcpy( p_forward_session_client->server_addr.netaddr.port , server_addr.netaddr.port );
		p_forward_session_client->server_addr.sock = server_addr.sock ;
		memcpy( & (p_forward_session_client->server_addr.netaddr) , & (server_addr.netaddr) , sizeof(struct sockaddr_in) );
		p_forward_session_client->server_session_index = p_forward_session_server - & (pse->forward_session[0]) ;
		
		p_forward_session_client->p_forward_rule = p_forward_rule ;
		p_forward_session_client->status = CONNECT_STATUS_RECEIVING ;
		p_forward_session_client->client_index = client_index ;
		p_forward_session_client->server_index = p_forward_rule->select_index ;
		
		p_forward_session_client->active_timestamp = pse->server_cache.tv.tv_sec ;
		
#ifdef USE_EPOLL
		memset( & (client_event) , 0x00 , sizeof(client_event) );
		client_event.data.ptr = p_forward_session_client ;
		client_event.events = EPOLLIN | EPOLLERR | EPOLLET ;
		epoll_ctl( pse->epoll_fds , EPOLL_CTL_ADD , p_forward_session_client->client_addr.sock , & client_event );
#endif
		
		/* 登记服务端转发会话，登记epoll池 */ /* register server forwarding sessions in epoll pool  */
		nret = GetForwardSessionUnusedUnit( pse , & p_forward_session_server ) ;
		if( nret != FOUND )
		{
			ErrorOutput( pse , "GetForwardSessionUnusedUnit failed[%d]\r\n" , nret );
			_CLOSESOCKET( server_addr.sock );
			return 1;
		}
		
		p_forward_session_server->forward_session_type = FORWARD_SESSION_TYPE_SERVER ;
		
		strcpy( p_forward_session_server->client_addr.netaddr.ip , p_client_addr->netaddr.ip );
		strcpy( p_forward_session_server->client_addr.netaddr.port , p_client_addr->netaddr.port );
		p_forward_session_server->client_addr.sock = p_client_addr->sock ;
		memcpy( & (p_forward_session_server->client_addr.netaddr) , & (p_client_addr->netaddr) , sizeof(struct sockaddr_in) );
		p_forward_session_server->client_session_index = p_forward_session_server - & (pse->forward_session[0]) ;
		
		strcpy( p_forward_session_server->server_addr.netaddr.ip , server_addr.netaddr.ip );
		strcpy( p_forward_session_server->server_addr.netaddr.port , server_addr.netaddr.port );
		p_forward_session_server->server_addr.sock = server_addr.sock ;
		memcpy( & (p_forward_session_server->server_addr.netaddr) , & (server_addr.netaddr) , sizeof(struct sockaddr_in) );
		p_forward_session_server->server_session_index = p_forward_session_server - & (pse->forward_session[0]) ;
		
		p_forward_session_server->p_forward_rule = p_forward_rule ;
		p_forward_session_server->client_index = client_index ;
		p_forward_session_server->server_index = p_forward_rule->select_index ;
		
		p_forward_session_server->status = CONNECT_STATUS_RECEIVING ;
		p_forward_session_server->active_timestamp = pse->server_cache.tv.tv_sec ;
		
#ifdef USE_EPOLL
		memset( & (server_event) , 0x00 , sizeof(server_event) );
		server_event.data.ptr = p_forward_session_server ;
		server_event.events = EPOLLIN | EPOLLERR | EPOLLET ;
		epoll_ctl( pse->epoll_fds , EPOLL_CTL_ADD , p_forward_session_server->server_addr.sock , & server_event );
#endif
		
		p_forward_session_server->p_forward_rule->client_addr[p_forward_session_server->client_index].client_connection_count++;
		p_forward_session_server->p_forward_rule->server_addr[p_forward_session_server->p_forward_rule->select_index].server_connection_count++;
		
		DebugOutput( pse , "accept [%s:%s]#%d# - [%s:%s]#%d# > [%s:%s]#%d#\r\n"
			, p_forward_session_client->client_addr.netaddr.ip , p_forward_session_client->client_addr.netaddr.port , p_forward_session_client->client_addr.sock
			, p_forward_session->listen_addr.netaddr.ip , p_forward_session->listen_addr.netaddr.port , p_forward_session->listen_addr.sock
			, p_forward_session_client->server_addr.netaddr.ip , p_forward_session_client->server_addr.netaddr.port , p_forward_session_client->server_addr.sock );
	}
	
	return 0;
}

/* 接受转发端口连接 */ /* accept the forwarding port connection */
static int AcceptForwardSocket( struct ServerEnv *pse , struct ForwardSession *p_forward_session )
{
	_SOCKLEN_T		addr_len = sizeof(struct sockaddr_in) ;
	
	struct ClientNetAddress	client_addr ;
	
	struct ForwardRule	*p_forward_rule = NULL ;
	unsigned long		client_index ;
	
	int			nret = 0 ;
	
	/* 循环接受转发端口连接 */
	while(1)
	{
		/* 接受转发端口连接 */ /* accept the forwarding port connection */
		client_addr.sock = accept( p_forward_session->listen_addr.sock , (struct sockaddr *) & (client_addr.netaddr.sockaddr) , & addr_len ) ;
		if( client_addr.sock < 0 )
		{
			if( _ERRNO == _EWOULDBLOCK || _ERRNO == _ECONNABORTED )
				break;
			
			ErrorOutput( pse , "accept[%d] failed[%d]errno[%d]\r\n" , p_forward_session->listen_addr.sock , client_addr.sock  , _ERRNO );
			return 1;
		}
		
		SetNonBlocking( client_addr.sock );
		SetReuseAddr( client_addr.sock );
		
		strcpy( client_addr.netaddr.ip , inet_ntoa( client_addr.netaddr.sockaddr.sin_addr ) );
		sprintf( client_addr.netaddr.port , "%ld" , (unsigned long)ntohs( client_addr.netaddr.sockaddr.sin_port ) );
		
		/* 匹配转发规则 */ /* matching forward rules */
		nret = MatchForwardRule( pse , & client_addr , & (p_forward_session->listen_addr) , & p_forward_rule , & client_index ) ;
		if( nret != FOUND )
		{
			ErrorOutput( pse , "match forward rule [%s:%s] - [%s:%s] failed[%d]\r\n" , client_addr.netaddr.ip , client_addr.netaddr.port , p_forward_session->listen_addr.netaddr.ip , p_forward_session->listen_addr.netaddr.port , nret );
			_CLOSESOCKET( client_addr.sock );
			return 1;
		}
		
		/* 注册全局统计地址 */ /* registered global statistics address */
		nret = RegisterStatAddress( pse , client_addr.netaddr.ip ) ;
		if( nret )
		{
			_CLOSESOCKET( client_addr.sock );
			return 1;
		}
		
		/* 检查最大连接数量 */ /* check the maximum number of connections */
		if(	p_forward_rule->client_addr[client_index].maxclients > 0
			&& p_forward_rule->client_addr[client_index].client_connection_count + 1 > p_forward_rule->client_addr[client_index].maxclients )
		{
			ErrorOutput( pse , "too many forward connections\r\n" );
			_CLOSESOCKET( client_addr.sock );
			return 1;
		}
		
		/* 连接目标网络地址 */ /* connect target network address */
		nret = ConnectToRemote( pse , p_forward_session , p_forward_rule , client_index , & client_addr , TRY_CONNECT_MAXCOUNT ) ;
		if( nret )
		{
			_CLOSESOCKET( client_addr.sock );
			return nret;
		}
	}
	
	return 0;
}

/* 转发通讯数据 */ /* forward the communications data */
static int TransferSocketData( struct ServerEnv *pse , struct ForwardSession *p_forward_session )
{
	int			in_sock ;
	int			out_sock ;
	struct ForwardSession	*p_in_forward_session = NULL ;
	struct ForwardSession	*p_out_forward_session = NULL ;
	
	ssize_t			len ;
	
	if( p_forward_session->forward_session_type == FORWARD_SESSION_TYPE_CLIENT )
	{
		in_sock = p_forward_session->client_addr.sock ;
		out_sock = p_forward_session->server_addr.sock ;
		p_in_forward_session = & (pse->forward_session[p_forward_session->client_session_index]) ;
		p_out_forward_session = & (pse->forward_session[p_forward_session->server_session_index]) ;
	}
	else
	{
		in_sock = p_forward_session->server_addr.sock ;
		out_sock = p_forward_session->client_addr.sock ;
		p_in_forward_session = & (pse->forward_session[p_forward_session->server_session_index]) ;
		p_out_forward_session = & (pse->forward_session[p_forward_session->client_session_index]) ;
	}
	
	while(1)
	{
		/* 接收通讯数据 */ /* receiving communications data */
		p_out_forward_session->io_buflen = recv( in_sock , p_out_forward_session->io_buffer , IO_BUFSIZE , 0 ) ;
		pse->forward_session[p_forward_session->server_session_index].active_timestamp = pse->server_cache.tv.tv_sec ;
		pse->forward_session[p_forward_session->client_session_index].active_timestamp = pse->server_cache.tv.tv_sec ;
		if( p_out_forward_session->io_buflen < 0 )
		{
			if( _ERRNO == _EWOULDBLOCK )
			{
				break;
			}
			
			if( _ERRNO == _ECONNRESET )
			{
				ErrorOutput( pse , "close #%d# reset , close #%d# passivity\r\n" , in_sock , out_sock );
			}
			else
			{
				ErrorOutput( pse , "close #%d# recv error errno[%d] , close #%d# passivity\r\n" , in_sock , _ERRNO , out_sock );
			}
			
			pse->forward_session[p_forward_session->client_session_index].p_forward_rule->client_addr[p_forward_session->client_index].client_connection_count--;
			pse->forward_session[p_forward_session->server_session_index].p_forward_rule->server_addr[p_forward_session->server_index].server_connection_count--;
#ifdef USE_EPOLL
			epoll_ctl( pse->epoll_fds , EPOLL_CTL_DEL , p_forward_session->client_addr.sock , NULL );
			epoll_ctl( pse->epoll_fds , EPOLL_CTL_DEL , p_forward_session->server_addr.sock , NULL );
#endif
			_CLOSESOCKET( p_forward_session->client_addr.sock );
			_CLOSESOCKET( p_forward_session->server_addr.sock );
			SetForwardSessionUnitUnused2( pse , & (pse->forward_session[p_forward_session->client_session_index]) , & (pse->forward_session[p_forward_session->server_session_index]) );
			return 0;
		}
		else if( p_out_forward_session->io_buflen == 0 )
		{
			/* 通讯连接断开处理 */ /* communication connection is broken */
			DebugOutput( pse , "close #%d# recv 0 , close #%d# passivity\r\n" , in_sock , out_sock );
			
			pse->forward_session[p_forward_session->client_session_index].p_forward_rule->client_addr[p_forward_session->client_index].client_connection_count--;
			pse->forward_session[p_forward_session->server_session_index].p_forward_rule->server_addr[p_forward_session->server_index].server_connection_count--;
#ifdef USE_EPOLL
			epoll_ctl( pse->epoll_fds , EPOLL_CTL_DEL , p_forward_session->client_addr.sock , NULL );
			epoll_ctl( pse->epoll_fds , EPOLL_CTL_DEL , p_forward_session->server_addr.sock , NULL );
#endif
			_CLOSESOCKET( p_forward_session->client_addr.sock );
			_CLOSESOCKET( p_forward_session->server_addr.sock );
			SetForwardSessionUnitUnused2( pse , & (pse->forward_session[p_forward_session->client_session_index]) , & (pse->forward_session[p_forward_session->server_session_index]) );

			return 0;
		}
		
		/* RT模式额外处理 */ /* RT model additional processing */
		if( strcmp( pse->forward_session[p_forward_session->server_session_index].p_forward_rule->rule_mode , FORWARD_RULE_MODE_RT ) == 0 )
		{
			if( p_forward_session->forward_session_type == FORWARD_SESSION_TYPE_CLIENT )
			{
				pse->forward_session[p_forward_session->server_session_index].p_forward_rule->status.RT[pse->forward_session[p_forward_session->server_session_index].p_forward_rule->select_index].tv1 = pse->server_cache.tv ;
			}
			else
			{
				pse->forward_session[p_forward_session->server_session_index].p_forward_rule->status.RT[pse->forward_session[p_forward_session->server_session_index].p_forward_rule->select_index].tv2 = pse->server_cache.tv ;
			}
		}
		
		/* 发送通讯数据 */ /* Sending communications data */
		while( p_out_forward_session->io_buflen > 0 )
		{
			len = send( out_sock , p_out_forward_session->io_buffer , p_out_forward_session->io_buflen , 0 ) ;
			if( len < 0 )
			{
				if( _ERRNO == _EWOULDBLOCK )
				{
#ifdef USE_EPOLL
					struct epoll_event	in_event ;
					struct epoll_event	out_event ;
					
					struct epoll_event	*p_event = NULL ;
					int			sock_index ;
					struct ForwardSession	*p_session = NULL ;
#endif
					
					/* 输出缓冲区满了 */ /* output buffer is full */
					DebugOutput( pse , "transfer3 #%d# to #%d# overflow\r\n" , in_sock , out_sock );
					
					p_in_forward_session->status = CONNECT_STATUS_SUSPENDING ;
					p_out_forward_session->status = CONNECT_STATUS_SENDING ;
					
#ifdef USE_EPOLL
					memset( & (in_event) , 0x00 , sizeof(in_event) );
					in_event.data.ptr = p_in_forward_session ;
					in_event.events = EPOLLERR | EPOLLET ;
					epoll_ctl( pse->epoll_fds , EPOLL_CTL_MOD , in_sock , & in_event );
					
					memset( & (out_event) , 0x00 , sizeof(out_event) );
					out_event.data.ptr = p_out_forward_session ;
					out_event.events = EPOLLOUT | EPOLLERR | EPOLLET ;
					epoll_ctl( pse->epoll_fds , EPOLL_CTL_MOD , out_sock , & out_event );
					
					/* 把另一方向的事件暂时屏蔽掉 */ /* put another direction event blocking */
					if( pse->sock_index + 1 < pse->sock_count )
					{
						for( sock_index = pse->sock_index + 1 , p_event = & (pse->events[sock_index]) ; sock_index < pse->sock_count ; sock_index++ , p_event++ )
						{
							p_session = p_event->data.ptr ;
							if( p_session->forward_session_type == FORWARD_SESSION_TYPE_CLIENT && p_session->client_addr.sock == out_sock )
								p_event->events = 0 ;
							else if( p_session->forward_session_type == FORWARD_SESSION_TYPE_SERVER && p_session->server_addr.sock == out_sock )
								p_event->events = 0 ;
						}
					}
#endif
					return 0;
				}
				else
				{
					ErrorOutput( pse , "close #%d# send error , close #%d# passivity\r\n" , in_sock , out_sock );
					
					pse->forward_session[p_forward_session->client_session_index].p_forward_rule->client_addr[p_forward_session->client_index].client_connection_count--;
					pse->forward_session[p_forward_session->server_session_index].p_forward_rule->server_addr[p_forward_session->server_index].server_connection_count--;
#ifdef USE_EPOLL
					epoll_ctl( pse->epoll_fds , EPOLL_CTL_DEL , p_forward_session->client_addr.sock , NULL );
					epoll_ctl( pse->epoll_fds , EPOLL_CTL_DEL , p_forward_session->server_addr.sock , NULL );
#endif
					_CLOSESOCKET( p_forward_session->client_addr.sock );
					_CLOSESOCKET( p_forward_session->server_addr.sock );
					SetForwardSessionUnitUnused2( pse , & (pse->forward_session[p_forward_session->client_session_index]) , & (pse->forward_session[p_forward_session->server_session_index]) );
					return 0;
				}
			}
			else if( len == p_out_forward_session->io_buflen )
			{
				DebugOutput( pse , "transfer #%d# [%d]bytes to #%d#\r\n" , in_sock , len , out_sock );
				p_out_forward_session->io_buflen = 0 ;
				break;
			}
			else
			{
				DebugOutput( pse , "transfer2 #%d# [%d]bytes to #%d#\r\n" , in_sock , len , out_sock );
				p_out_forward_session->io_buflen -= len ;
				memmove( p_out_forward_session->io_buffer , p_out_forward_session->io_buffer + len , p_out_forward_session->io_buflen );
			}
		}
	}
	
	return 0;
}

/* 继续写通讯数据 */ /* continue to write data communications */
static int ContinueToWriteSocketData( struct ServerEnv *pse , struct ForwardSession *p_forward_session )
{
	int			in_sock ;
	int			out_sock ;
	unsigned long		client_session_index ;
	unsigned long		server_session_index ;
	struct ForwardSession	*p_in_forward_session = NULL ;
	struct ForwardSession	*p_out_forward_session = NULL ;
	
	ssize_t			len ;
	
	if( p_forward_session->forward_session_type == FORWARD_SESSION_TYPE_SERVER )
	{
		in_sock = p_forward_session->client_addr.sock ;
		out_sock = p_forward_session->server_addr.sock ;
		client_session_index = p_forward_session->client_session_index ;
		server_session_index = p_forward_session->server_session_index ;
		p_in_forward_session = & (pse->forward_session[p_forward_session->client_session_index]) ;
		p_out_forward_session = & (pse->forward_session[p_forward_session->server_session_index]) ;
	}
	else
	{
		in_sock = p_forward_session->server_addr.sock ;
		out_sock = p_forward_session->client_addr.sock ;
		server_session_index = p_forward_session->server_session_index ;
		client_session_index = p_forward_session->client_session_index ;
		p_in_forward_session = & (pse->forward_session[p_forward_session->server_session_index]) ;
		p_out_forward_session = & (pse->forward_session[p_forward_session->client_session_index]) ;
	}
	
	while( p_out_forward_session->io_buflen > 0 )
	{
		/* 发送通讯数据 */ /* sending communications data */
		len = send( out_sock , p_out_forward_session->io_buffer , p_out_forward_session->io_buflen , 0 ) ;
		pse->forward_session[p_forward_session->server_session_index].active_timestamp = pse->server_cache.tv.tv_sec ;
		pse->forward_session[p_forward_session->client_session_index].active_timestamp = pse->server_cache.tv.tv_sec ;
		if( len < 0 )
		{
			if( _ERRNO == _EWOULDBLOCK )
			{
				DebugOutput( pse , "transfer42 #%d# [%d]bytes to #%d#\r\n" , in_sock , len , out_sock );
				
				p_out_forward_session->io_buflen -= len ;
				memmove( p_out_forward_session->io_buffer , p_out_forward_session->io_buffer + len , p_out_forward_session->io_buflen );
				break;
			}
			else
			{
				ErrorOutput( pse , "close #%d# send error , close #%d# passivity\r\n" , in_sock , out_sock );
				pse->forward_session[p_forward_session->client_session_index].p_forward_rule->client_addr[p_forward_session->client_index].client_connection_count--;
				pse->forward_session[p_forward_session->server_session_index].p_forward_rule->server_addr[p_forward_session->server_index].server_connection_count--;
#ifdef USE_EPOLL
				epoll_ctl( pse->epoll_fds , EPOLL_CTL_DEL , in_sock , NULL );
				epoll_ctl( pse->epoll_fds , EPOLL_CTL_DEL , out_sock , NULL );
#endif
				_CLOSESOCKET( p_forward_session->client_addr.sock );
				_CLOSESOCKET( p_forward_session->server_addr.sock );
				SetForwardSessionUnitUnused2( pse , & (pse->forward_session[p_forward_session->client_session_index]) , & (pse->forward_session[p_forward_session->server_session_index]) );
				return 0;
			}
		}
		else if( len == p_out_forward_session->io_buflen )
		{
#ifdef USE_EPOLL
			struct epoll_event	in_event ;
			struct epoll_event	out_event ;
#endif
			
			DebugOutput( pse , "transfer31 #%d# [%d]bytes to #%d#\r\n" , in_sock , len , out_sock );
			
			p_in_forward_session->status = CONNECT_STATUS_RECEIVING ;
			p_out_forward_session->status = CONNECT_STATUS_RECEIVING ;
			
			p_out_forward_session->io_buflen = 0 ;
			
			/* 输出缓冲区空了 */ /* output buffer is empty  */
#ifdef USE_EPOLL
			memset( & (in_event) , 0x00 , sizeof(in_event) );
			in_event.data.ptr = p_in_forward_session ;
			in_event.events = EPOLLIN | EPOLLERR | EPOLLET ;
			epoll_ctl( pse->epoll_fds , EPOLL_CTL_MOD , in_sock , & in_event );
			
			memset( & (out_event) , 0x00 , sizeof(out_event) );
			out_event.data.ptr = p_out_forward_session ;
			out_event.events = EPOLLIN | EPOLLERR | EPOLLET ;
			epoll_ctl( pse->epoll_fds , EPOLL_CTL_MOD , out_sock , & out_event );
#endif
			
			break;
		}
		else
		{
			DebugOutput( pse , "transfer41 #%d# [%d]bytes to #%d#\r\n" , in_sock , len , out_sock );
			p_out_forward_session->io_buflen -= len ;
			memmove( p_out_forward_session->io_buffer , p_out_forward_session->io_buffer + len , p_out_forward_session->io_buflen );
		}
	}
	
	return 0;
}

/* 处理管理命令 */ /* handle administrative commands  */
static int ProcessManageCommand( struct ServerEnv *pse , int out_sock , struct ForwardSession *p_forward_session )
{
	char		*p_remark = NULL ;
	
	char		cmd1[ 64 + 1 ] ;
	char		cmd2[ 64 + 1 ] ;
	char		cmd3[ 64 + 1 ] ;
	
	char		out_buf[ IO_BUFSIZE + 1 ] ;
	
	p_remark = strchr( p_forward_session->io_buffer , '#' ) ;
	if( p_remark )
	{
		(*p_remark) = '\0' ;
	}
	
	memset( cmd1 , 0x00 , sizeof(cmd1) );
	memset( cmd2 , 0x00 , sizeof(cmd2) );
	sscanf( p_forward_session->io_buffer , "%64s %64s %64s" , cmd1 , cmd2 , cmd3 );
	
	if( strcmp( cmd1 , "?" ) == 0 )
	{
		_SNPRINTF( out_buf , sizeof(out_buf)-1 , "ver\r\n"
						"list rules\r\n"
						"add rule ...\r\n"
						"modify rule ...\r\n"
						"remove rule ...\r\n"
						"dump rule\r\n"
						"list forwards\r\n"
						"quit\r\n" );
		send( out_sock , out_buf , strlen(out_buf) , 0 );
	}
	else if( strcmp( cmd1 , "ver" ) == 0 )
	{
		/* 显示版本 */ /* display version */
		memset( out_buf , 0x00 , sizeof(out_buf) );
		_SNPRINTF( out_buf , sizeof(out_buf)-1 , "version v%s build %s %s %d:%d:%d,%d:%d:%d,%d\r\n"
						, VERSION , __DATE__ , __TIME__
						, DEFAULT_FORWARD_RULE_MAXCOUNT , DEFAULT_CONNECTION_MAXCOUNT , DEFAULT_TRANSFER_BUFSIZE
						, RULE_CLIENT_MAXCOUNT , RULE_FORWARD_MAXCOUNT , RULE_SERVER_MAXCOUNT
						, RULE_ID_MAXLEN );
		send( out_sock , out_buf , strlen(out_buf) , 0 );
	}
	else if( strcmp( cmd1 , "list" ) == 0 && strcmp( cmd2 , "rules" ) == 0 )
	{
		unsigned long			forward_rule_index ;
		struct ForwardRule		*p_forward_rule = NULL ;
		
		unsigned long			client_session_index ;
		struct ClientNetAddress		*p_client_addr = NULL ;
		unsigned long			forward_index ;
		struct ForwardNetAddress	*p_forward_addr = NULL ;
		unsigned long			server_session_index ;
		struct ServerNetAddress		*p_server_addr = NULL ;
		
		/* 列表所有转发规则 */ /* list all forwarding rules */
		for( forward_rule_index = 0 , p_forward_rule = & (pse->forward_rule[0]) ; forward_rule_index < pse->forward_rule_count ; forward_rule_index++ , p_forward_rule++ )
		{
			_SNPRINTF( out_buf , sizeof(out_buf)-1 , "%6ld : %s %s" , forward_rule_index+1 , p_forward_rule->rule_id , p_forward_rule->rule_mode );
			send( out_sock , out_buf , strlen(out_buf) , 0 );
			
			if( p_forward_rule->timeout > 0 )
			{
				_SNPRINTF( out_buf , sizeof(out_buf)-1 , " ( timeout %ld )" , p_forward_rule->timeout );
				send( out_sock , out_buf , strlen(out_buf) , 0 );
			}
			
			for( client_session_index = 0 , p_client_addr = & (p_forward_rule->client_addr[0]) ; client_session_index < p_forward_rule->client_count ; client_session_index++ , p_client_addr++ )
			{
				_SNPRINTF( out_buf , sizeof(out_buf)-1 , " %s:%s" , p_client_addr->netaddr.ip , p_client_addr->netaddr.port );
				send( out_sock , out_buf , strlen(out_buf) , 0 );
				
				if( p_client_addr->maxclients > 0 )
				{
					_SNPRINTF( out_buf , sizeof(out_buf)-1 , " ( conntions[%ld/%ld] )" , p_client_addr->client_connection_count , p_client_addr->maxclients );
					send( out_sock , out_buf , strlen(out_buf) , 0 );
				}
			}
			
			_SNPRINTF( out_buf , sizeof(out_buf)-1 , " -" );
			send( out_sock , out_buf , strlen(out_buf) , 0 );
			
			for( forward_index = 0 , p_forward_addr = & (p_forward_rule->forward_addr[0]) ; forward_index < p_forward_rule->forward_count ; forward_index++ , p_forward_addr++ )
			{
				_SNPRINTF( out_buf , sizeof(out_buf)-1 , " %s:%s" , p_forward_addr->netaddr.ip , p_forward_addr->netaddr.port );
				send( out_sock , out_buf , strlen(out_buf) , 0 );
			}
			
			if( strcmp( p_forward_rule->rule_mode , FORWARD_RULE_MODE_G ) != 0 )
			{
				_SNPRINTF( out_buf , sizeof(out_buf)-1 , " >" );
				send( out_sock , out_buf , strlen(out_buf) , 0 );
				
				for( server_session_index = 0 , p_server_addr = & (p_forward_rule->server_addr[0]) ; server_session_index < p_forward_rule->server_count ; server_session_index++ , p_server_addr++ )
				{
					_SNPRINTF( out_buf , sizeof(out_buf)-1 , " %s:%s" , p_server_addr->netaddr.ip , p_server_addr->netaddr.port );
					send( out_sock , out_buf , strlen(out_buf) , 0 );
				}
			}
			
			_SNPRINTF( out_buf , sizeof(out_buf)-1 , " ;\r\n" );
			send( out_sock , out_buf , strlen(out_buf) , 0 );
		}
	}
	else if( strcmp( cmd1 , "add" ) == 0 && strcmp( cmd2 , "rule" ) == 0 )
	{
		char				*p_buffer = NULL ;
		char				*p_rule_id = NULL ;
		struct ForwardRule		forward_rule ;
		
		int				nret = 0 ;
		
		/* 新增转发规则 */ /* new a forwarding rule */
		p_buffer = strtok( p_forward_session->io_buffer , " \t" ) ;
		p_buffer = strtok( NULL , " \t" ) ;
		p_rule_id = strtok( NULL , " \t" ) ;
		p_buffer = strtok( NULL , "" ) ;
		nret = LoadForwardConfig( pse , p_buffer , p_rule_id , & forward_rule ) ;
		if( nret > 0 )
		{
		}
		else if( nret < 0 )
		{
			_SNPRINTF( out_buf , sizeof(out_buf)-1 , "parse forward rule failed[%d]\r\n" , nret );
			send( out_sock , out_buf , strlen(out_buf) , 0 );
		}
		else
		{
			nret = AddForwardRule( pse , & forward_rule ) ;
			if( nret )
			{
				_SNPRINTF( out_buf , sizeof(out_buf)-1 , "add forward rule failed[%d]\r\n" , nret );
				send( out_sock , out_buf , strlen(out_buf) , 0 );
			}
			else
			{
				_SNPRINTF( out_buf , sizeof(out_buf)-1 , "add forward rule ok\r\n" );
				send( out_sock , out_buf , strlen(out_buf) , 0 );
			}
		}
	}
	else if( strcmp( cmd1 , "modify" ) == 0 && strcmp( cmd2 , "rule" ) == 0 )
	{
		char				*p_buffer = NULL ;
		char				*p_rule_id = NULL ;
		struct ForwardRule		forward_rule ;
		
		int				nret = 0 ;
		
		/* 修改转发规则 */ /* modify a forwarding rule */
		p_buffer = strtok( p_forward_session->io_buffer , " \t" ) ;
		p_buffer = strtok( NULL , " \t" ) ;
		p_rule_id = strtok( NULL , " \t" ) ;
		p_buffer = strtok( NULL , "" ) ;
		nret = LoadForwardConfig( pse , p_buffer , p_rule_id , & forward_rule ) ;
		if( nret > 0 )
		{
		}
		else if( nret < 0 )
		{
			_SNPRINTF( out_buf , sizeof(out_buf)-1 , "parse forward rule failed[%d]\r\n" , nret );
			send( out_sock , out_buf , strlen(out_buf) , 0 );
		}
		else
		{
			nret = ModifyForwardRule( pse , & forward_rule ) ;
			if( nret )
			{
				_SNPRINTF( out_buf , sizeof(out_buf)-1 , "modify forward rule failed[%d]\r\n" , nret );
				send( out_sock , out_buf , strlen(out_buf) , 0 );
			}
			else
			{
				_SNPRINTF( out_buf , sizeof(out_buf)-1 , "modify forward rule ok\r\n" );
				send( out_sock , out_buf , strlen(out_buf) , 0 );
			}
		}
	}
	else if( strcmp( cmd1 , "remove" ) == 0 && strcmp( cmd2 , "rule" ) == 0 )
	{
		int				nret = 0 ;
		
		/* 删除转发规则 */ /* remove a forwarding rule */
		nret = RemoveForwardRule( pse , cmd3 ) ;
		if( nret )
		{
			_SNPRINTF( out_buf , sizeof(out_buf)-1 , "remove forward rule failed[%d]\r\n" , nret );
			send( out_sock , out_buf , strlen(out_buf) , 0 );
		}
		else
		{
			_SNPRINTF( out_buf , sizeof(out_buf)-1 , "remove forward rule ok\r\n" );
			send( out_sock , out_buf , strlen(out_buf) , 0 );
		}
	}
	else if( strcmp( cmd1 , "dump" ) == 0 && strcmp( cmd2 , "rules" ) == 0 )
	{
		FILE				*fp = NULL ;
		
		unsigned long			forward_rule_index ;
		struct ForwardRule		*p_forward_rule = NULL ;
		
		unsigned long			client_session_index ;
		struct ClientNetAddress		*p_client_addr = NULL ;
		unsigned long			forward_index ;
		struct ForwardNetAddress	*p_forward_addr = NULL ;
		unsigned long			server_session_index ;
		struct ServerNetAddress		*p_server_addr = NULL ;
		
		/* 保存规则到配置文件 */ /* dump config to file */
		fp = fopen( pse->cmd_para.config_pathfilename , "w" ) ;
		if( fp == NULL )
		{
			_SNPRINTF( out_buf , sizeof(out_buf)-1 , "can't open config file for writing\r\n" );
			send( out_sock , out_buf , strlen(out_buf) , 0 );
			return 0;
		}
		
		if( pse->maxsessions_per_ip > 0 )
		{
			fprintf( fp , "( maxsessions_per_ip %ld )\r\n" , pse->maxsessions_per_ip );
		}
		
		for( forward_rule_index = 0 , p_forward_rule = & (pse->forward_rule[0]) ; forward_rule_index < pse->forward_rule_count ; forward_rule_index++ , p_forward_rule++ )
		{
			fprintf( fp , "%s %s" , p_forward_rule->rule_id , p_forward_rule->rule_mode );
			
			if( p_forward_rule->timeout > 0 )
			{
				fprintf( fp , " ( timeout %ld )" , p_forward_rule->timeout );
			}
			
			for( client_session_index = 0 , p_client_addr = & (p_forward_rule->client_addr[0]) ; client_session_index < p_forward_rule->client_count ; client_session_index++ , p_client_addr++ )
			{
				fprintf( fp , " %s:%s" , p_client_addr->netaddr.ip , p_client_addr->netaddr.port );
				
				if( p_client_addr->maxclients > 0 )
				{
					fprintf( fp , " ( maxclients %ld )" , p_client_addr->maxclients );
				}
			}
			
			fprintf( fp , " -" );
			
			for( forward_index = 0 , p_forward_addr = & (p_forward_rule->forward_addr[0]) ; forward_index < p_forward_rule->forward_count ; forward_index++ , p_forward_addr++ )
			{
				fprintf( fp , " %s:%s" , p_forward_addr->netaddr.ip , p_forward_addr->netaddr.port );
			}
			
			if( strcmp( p_forward_rule->rule_mode , FORWARD_RULE_MODE_G ) != 0 )
			{
				fprintf( fp , " >" );
				
				for( server_session_index = 0 , p_server_addr = & (p_forward_rule->server_addr[0]) ; server_session_index < p_forward_rule->server_count ; server_session_index++ , p_server_addr++ )
				{
					fprintf( fp , " %s:%s" , p_server_addr->netaddr.ip , p_server_addr->netaddr.port );
				}
			}
			
			fprintf( fp , " ;\r\n" );
		}
		
		fclose(fp);
		
		_SNPRINTF( out_buf , sizeof(out_buf)-1 , "dump all forward rules ok\r\n" );
		send( out_sock , out_buf , strlen(out_buf) , 0 );
	}
	else if( strcmp( cmd1 , "list" ) == 0 && strcmp( cmd2 , "forwards" ) == 0 )
	{
		unsigned long		index ;
		struct ForwardSession	*p_forward_session = NULL ;
		
		/* 列表转发会话 */ /* list all forward sessions */
		for( index = 0 , p_forward_session = & (pse->forward_session[0]) ; index < pse->forward_session_maxcount ; index++ , p_forward_session++ )
		{
			memset( out_buf , 0x00 , sizeof(out_buf) );
			
			if( p_forward_session->forward_session_type == FORWARD_SESSION_TYPE_MANAGE )
			{
				_SNPRINTF( out_buf , sizeof(out_buf)-1 , "%6ld : CLIENT [%s:%s]#%d# - MANAGE [%s:%s]#%d#\r\n"
					, index+1
					, p_forward_session->client_addr.netaddr.ip , p_forward_session->client_addr.netaddr.port , p_forward_session->client_addr.sock
					, p_forward_session->listen_addr.netaddr.ip , p_forward_session->listen_addr.netaddr.port , p_forward_session->listen_addr.sock );
			}
			else if( p_forward_session->forward_session_type == FORWARD_SESSION_TYPE_LISTEN )
			{
				_SNPRINTF( out_buf , sizeof(out_buf)-1 , "%6ld : LISTEN [%s:%s]#%d#\r\n"
					, index+1
					, p_forward_session->listen_addr.netaddr.ip , p_forward_session->listen_addr.netaddr.port , p_forward_session->listen_addr.sock );
			}
			else if( p_forward_session->forward_session_type == FORWARD_SESSION_TYPE_CLIENT )
			{
				_SNPRINTF( out_buf , sizeof(out_buf)-1 , "%6ld : CLIENT [%s:%s]#%d# - LISTEN [%s:%s]#%d# > SERVER [%s:%s]#%d# %s\r\n"
					, index+1
					, p_forward_session->client_addr.netaddr.ip , p_forward_session->client_addr.netaddr.port , p_forward_session->client_addr.sock
					, p_forward_session->listen_addr.netaddr.ip , p_forward_session->listen_addr.netaddr.port , p_forward_session->listen_addr.sock
					, p_forward_session->server_addr.netaddr.ip , p_forward_session->server_addr.netaddr.port , p_forward_session->server_addr.sock
					, _g_forward_status[p_forward_session->status] );
			}
			else if( p_forward_session->forward_session_type == FORWARD_SESSION_TYPE_SERVER )
			{
				_SNPRINTF( out_buf , sizeof(out_buf)-1 , "%6ld : CLIENT [%s:%s]#%d# < LISTEN [%s:%s]#%d# - SERVER [%s:%s]#%d# %s\r\n"
					, index+1
					, p_forward_session->client_addr.netaddr.ip , p_forward_session->client_addr.netaddr.port , p_forward_session->client_addr.sock
					, p_forward_session->listen_addr.netaddr.ip , p_forward_session->listen_addr.netaddr.port , p_forward_session->listen_addr.sock
					, p_forward_session->server_addr.netaddr.ip , p_forward_session->server_addr.netaddr.port , p_forward_session->server_addr.sock
					, _g_forward_status[p_forward_session->status] );
			}
			
			send( out_sock , out_buf , strlen(out_buf) , 0 );
		}
	}
	else if( strcmp( cmd1 , "clean" ) == 0 && strcmp( cmd2 , "forwards" ) == 0 )
	{
		int				nret = 0 ;
		
		/* 强制断开老会话 */ /* forcibly disconnected session */
		nret = CloseSocketWithRuleForcely( pse ) ;
		if( nret )
		{
			_SNPRINTF( out_buf , sizeof(out_buf)-1 , "clean forwards failed[%d]\r\n" , nret );
			send( out_sock , out_buf , strlen(out_buf) , 0 );
		}
		else
		{
			_SNPRINTF( out_buf , sizeof(out_buf)-1 , "clean forwards ok\r\n" );
			send( out_sock , out_buf , strlen(out_buf) , 0 );
		}
	}
	else if( strcmp( cmd1 , "quit" ) == 0 )
	{
		/* 断开管理端口 */ /* disconnect the management port */
		p_forward_session->p_forward_rule->client_addr[p_forward_session->client_index].client_connection_count--;
		ErrorOutput( pse , "close #%d# initiative\r\n" , out_sock );
#ifdef USE_EPOLL
		epoll_ctl( pse->epoll_fds , EPOLL_CTL_DEL , out_sock , NULL );
#endif
		_CLOSESOCKET( out_sock );
		SetForwardSessionUnitUnused( pse , p_forward_session );
		return 1;
	}
	else
	{
		memset( out_buf , 0x00 , sizeof(out_buf) );
		_SNPRINTF( out_buf , sizeof(out_buf)-1 , "command invalid [%s]\r\n" , p_forward_session->io_buffer );
		send( out_sock , out_buf , strlen(out_buf) , 0 );
	}
	
	return 0;
}

/* 接收管理命令，或并处理之 */ /* receive administrative commands, or and deal with it  */
static int ReceiveOrProcessManageData( struct ServerEnv *pse , struct ForwardSession *p_forward_session )
{
	int		in_sock ;
	int		out_sock ;
	
	char		*p_manage_buffer_offset = NULL ;
	ssize_t		manage_input_remain_bufsize ;
	ssize_t		recv_len ;
	char		*p = NULL ;
	
	int		nret = 0 ;
	
	in_sock = p_forward_session->client_addr.sock ;
	out_sock = in_sock ;
	
	while(1)
	{
		/* 接收管理端口数据 */ /* receive data management port */
		p_manage_buffer_offset = p_forward_session->io_buffer + p_forward_session->io_buflen ;
		manage_input_remain_bufsize = IO_BUFSIZE-1 - p_forward_session->io_buflen ;
		if( manage_input_remain_bufsize == 0 )
		{
			ErrorOutput( pse , "close #%d# too many data\r\n" , in_sock );
#ifdef USE_EPOLL
			epoll_ctl( pse->epoll_fds , EPOLL_CTL_DEL , in_sock , NULL );
#endif
			_CLOSESOCKET( in_sock );
			SetForwardSessionUnitUnused( pse , p_forward_session );
			return 0;
		}
		recv_len = recv( in_sock , p_manage_buffer_offset , manage_input_remain_bufsize , 0 ) ;
		p_forward_session->active_timestamp = pse->server_cache.tv.tv_sec ;
		if( recv_len < 0 )
		{
			if( _ERRNO == _EWOULDBLOCK )
			{
				break;
			}
			else if( _ERRNO == _ECONNRESET )
			{
				p_forward_session->p_forward_rule->client_addr[p_forward_session->client_index].client_connection_count--;
				ErrorOutput( pse , "close #%d# , reset\r\n" , in_sock );
#ifdef USE_EPOLL
				epoll_ctl( pse->epoll_fds , EPOLL_CTL_DEL , in_sock , NULL );
#endif
				_CLOSESOCKET( in_sock );
				SetForwardSessionUnitUnused( pse , p_forward_session );
				return 0;
			}
			else
			{
				p_forward_session->p_forward_rule->client_addr[p_forward_session->client_index].client_connection_count--;
				ErrorOutput( pse , "close #%d# , recv error\r\n" , in_sock );
#ifdef USE_EPOLL
				epoll_ctl( pse->epoll_fds , EPOLL_CTL_DEL , in_sock , NULL );
#endif
				_CLOSESOCKET( in_sock );
				SetForwardSessionUnitUnused( pse , p_forward_session );
				return 0;
			}
		}
		else if( recv_len == 0 )
		{
			/* 接受到断开事件 */ /* disconnect events */
			p_forward_session->p_forward_rule->client_addr[p_forward_session->client_index].client_connection_count--;
			ErrorOutput( pse , "close #%d# recv 0\r\n" , in_sock );
#ifdef USE_EPOLL
			epoll_ctl( pse->epoll_fds , EPOLL_CTL_DEL , in_sock , NULL );
#endif
			_CLOSESOCKET( in_sock );
			SetForwardSessionUnitUnused( pse , p_forward_session );
			return 0;
		}
		
		/* 判断是否形成完整命令数据 */ /* determine if full command data */
		p = strchr( p_manage_buffer_offset , '\n' ) ;
		if( p )
		{
			/* 已经形成完整命令数据，处理之，并保留未成型命令 */
			(*p) = '\0' ;
			if( p - p_manage_buffer_offset > 0 && *(p-1) == '\r' )
				*(p-1) = '\0' ;
			
			if( p_forward_session->io_buffer[0] != '\0' )
			{
				nret = ProcessManageCommand( pse , out_sock , p_forward_session ) ;
				if( nret > 0 )
				{
					break;
				}
				else if( nret < 0 )
				{
					p_forward_session->p_forward_rule->client_addr[p_forward_session->client_index].client_connection_count--;
					ErrorOutput( pse , "close #%d# proc error\r\n" , in_sock );
#ifdef USE_EPOLL
					epoll_ctl( pse->epoll_fds , EPOLL_CTL_DEL , in_sock , NULL );
#endif
					_CLOSESOCKET( in_sock );
					SetForwardSessionUnitUnused( pse , p_forward_session );
					return -1;
				}
			}
			
			p_forward_session->io_buflen = strlen(p+1) ;
			memmove( p_forward_session->io_buffer , p+1 , strlen(p+1)+1 );
			memset( p_forward_session->io_buffer , 0x00 , IO_BUFSIZE - p_forward_session->io_buflen );
			
			send( out_sock , "> " , 2 , 0 );
		}
		else
		{
			/* 未形成完整命令，继续累加 */
			p_forward_session->io_buflen += recv_len ;
		}
	}
	
	return 0;
}

/* 异步连接目标网络地址后回调，连接成功后登记到epoll池 */ /* asynchronous callback after connecting target network address, registration to the epoll pool after a successful connection */
static int SetSocketConnected( struct ServerEnv *pse , struct ForwardSession *p_forward_session_server )
{
	struct ForwardSession	*p_forward_session_client = NULL ;
#ifdef USE_EPOLL
	struct epoll_event	client_event ;
	struct epoll_event	server_event ;
#endif
	
	int			nret = 0 ;
	
	/* 查询epoll池未用单元 */
	nret = GetForwardSessionUnusedUnit( pse , & p_forward_session_client ) ;
	if( nret != FOUND )
	{
		p_forward_session_server->p_forward_rule->client_addr[p_forward_session_server->client_index].client_connection_count--;
		p_forward_session_server->p_forward_rule->server_addr[p_forward_session_server->p_forward_rule->select_index].server_connection_count--;
		ErrorOutput( pse , "GetForwardSessionUnusedUnit failed[%d]\r\n" , nret );
		_CLOSESOCKET( p_forward_session_server->client_addr.sock );
		_CLOSESOCKET( p_forward_session_server->server_addr.sock );
		SetForwardSessionUnitUnused( pse , p_forward_session_server );
		return 1;
	}
	
	/* 登记客户端信息转发会话、epoll池，更新服务端信息 */
	p_forward_session_client->forward_session_type = FORWARD_SESSION_TYPE_CLIENT ;
	
	memcpy( & (p_forward_session_client->client_addr) , & (p_forward_session_server->client_addr) , sizeof(struct ClientNetAddress) );
	p_forward_session_client->client_session_index = p_forward_session_client - & (pse->forward_session[0]) ;
	memcpy( & (p_forward_session_client->listen_addr) , & (p_forward_session_server->listen_addr) , sizeof(struct ClientNetAddress) );
	memcpy( & (p_forward_session_client->server_addr) , & (p_forward_session_server->server_addr) , sizeof(struct ServerNetAddress) );
	p_forward_session_client->server_session_index = p_forward_session_server->server_session_index ;
	
	p_forward_session_client->p_forward_rule = p_forward_session_server->p_forward_rule ;
	p_forward_session_client->client_index = p_forward_session_server->client_index ;
	p_forward_session_client->server_index = p_forward_session_server->server_index ;
	
	p_forward_session_client->status = CONNECT_STATUS_RECEIVING ;
	p_forward_session_client->active_timestamp = pse->server_cache.tv.tv_sec ;
	
#ifdef USE_EPOLL
	memset( & (client_event) , 0x00 , sizeof(client_event) );
	client_event.data.ptr = p_forward_session_client ;
	client_event.events = EPOLLIN | EPOLLERR | EPOLLET ;
	epoll_ctl( pse->epoll_fds , EPOLL_CTL_ADD , p_forward_session_client->client_addr.sock , & client_event );
#endif
	
	p_forward_session_server->client_session_index = p_forward_session_client - & (pse->forward_session[0]) ;
	p_forward_session_server->status = CONNECT_STATUS_RECEIVING ;
	p_forward_session_server->active_timestamp = pse->server_cache.tv.tv_sec ;
	
#ifdef USE_EPOLL
	memset( & (server_event) , 0x00 , sizeof(server_event) );
	server_event.data.ptr = p_forward_session_server ;
	server_event.events = EPOLLIN | EPOLLERR | EPOLLET ;
	epoll_ctl( pse->epoll_fds , EPOLL_CTL_MOD , p_forward_session_server->server_addr.sock , & server_event );
#endif
	
	DebugOutput( pse , "forward2 [%s:%s]#%d# - [%s:%s]#%d# > [%s:%s]#%d#\r\n"
		, p_forward_session_client->client_addr.netaddr.ip , p_forward_session_client->client_addr.netaddr.port , p_forward_session_client->client_addr.sock
		, p_forward_session_server->listen_addr.netaddr.ip , p_forward_session_server->listen_addr.netaddr.port , p_forward_session_server->listen_addr.sock
		, p_forward_session_server->server_addr.netaddr.ip , p_forward_session_server->server_addr.netaddr.port , p_forward_session_server->server_addr.sock );
	
	return 0;
}

/* 解决sock错误处理 */ /* to solve the error sock handling */
static int ResolveSocketError( struct ServerEnv *pse , struct ForwardSession *p_forward_session )
{
	int		nret = 0 ;
	
	/* 如果是异步连接错误事件 */
	if( p_forward_session->forward_session_type == FORWARD_SESSION_TYPE_SERVER && p_forward_session->status == CONNECT_STATUS_CONNECTING )
	{
		ErrorOutput( pse , "connect2 to [%s:%s] failed\r\n" , p_forward_session->server_addr.netaddr.ip , p_forward_session->server_addr.netaddr.port );
		
		/* 处理目标网络地址不可用错误 */
		nret = OnServerUnable( pse , p_forward_session->p_forward_rule ) ;
		if( nret )
		{
			goto _CLOSE_PAIR;
		}
		if( p_forward_session->try_connect_count <= 0 )
		{
			goto _CLOSE_PAIR;
		}
		
		/* 连接其它目标网络地址 */
		nret = ConnectToRemote( pse , p_forward_session , p_forward_session->p_forward_rule , p_forward_session->client_index , & (p_forward_session->client_addr) , --p_forward_session->try_connect_count ) ;
		
		/* 从epoll池中删除客户端sock */
		p_forward_session->p_forward_rule->client_addr[p_forward_session->client_index].client_connection_count--;
		p_forward_session->p_forward_rule->server_addr[p_forward_session->p_forward_rule->select_index].server_connection_count--;
#ifdef USE_EPOLL
		epoll_ctl( pse->epoll_fds , EPOLL_CTL_DEL , p_forward_session->server_addr.sock , NULL );
#endif
		_CLOSESOCKET( p_forward_session->server_addr.sock );
		SetForwardSessionUnitUnused( pse , p_forward_session );
		
		if( nret )
		{
			goto _CLOSE_PAIR;
		}
	}
	/* 如果是转发错误事件 */
	else
	{
_CLOSE_PAIR :
		/* 从epoll池中删除转发两端信息、删除转发会话 */
		ErrorOutput( pse , "close #%d# - #%d# EPOLLERR\r\n" , p_forward_session->client_addr.sock , p_forward_session->server_addr.sock );
		pse->forward_session[p_forward_session->server_session_index].p_forward_rule->client_addr[p_forward_session->client_index].client_connection_count--;
		pse->forward_session[p_forward_session->server_session_index].p_forward_rule->server_addr[p_forward_session->server_session_index].server_connection_count--;
#ifdef USE_EPOLL
		epoll_ctl( pse->epoll_fds , EPOLL_CTL_DEL , p_forward_session->client_addr.sock , NULL );
		epoll_ctl( pse->epoll_fds , EPOLL_CTL_DEL , p_forward_session->server_addr.sock , NULL );
#endif
		_CLOSESOCKET( p_forward_session->client_addr.sock );
		_CLOSESOCKET( p_forward_session->server_addr.sock );
		SetForwardSessionUnitUnused2( pse , & (pse->forward_session[p_forward_session->client_session_index]) , & (pse->forward_session[p_forward_session->server_session_index]) );
	}
	
	return 0;
}

/* 断开超时会话 */ /* disconnect the timeout session */
static int ProcessForwardSessionTimeout( struct ServerEnv *pse )
{
	unsigned long		index ;
	struct ForwardSession	*p_forward_session = NULL ;
	
	for( index = 0 , p_forward_session = & (pse->forward_session[0]) ; index < pse->forward_session_maxcount ; index++ , p_forward_session++ )
	{
		if( p_forward_session->forward_session_type != FORWARD_SESSION_TYPE_UNUSED )
		{
			if(	p_forward_session->forward_session_type == FORWARD_SESSION_TYPE_MANAGE
				&& p_forward_session->p_forward_rule->timeout > 0
				&& pse->server_cache.tv.tv_sec >= p_forward_session->active_timestamp + p_forward_session->p_forward_rule->timeout )
			{
				/* 从epoll池中删除 */
				DebugOutput( pse , "close #%d# timeout\r\n" , p_forward_session->client_addr.sock );
				p_forward_session->p_forward_rule->client_addr[p_forward_session->client_index].client_connection_count--;
#ifdef USE_EPOLL
				epoll_ctl( pse->epoll_fds , EPOLL_CTL_DEL , p_forward_session->client_addr.sock , NULL );
#endif
				_CLOSESOCKET( p_forward_session->client_addr.sock );
				SetForwardSessionUnitUnused( pse , p_forward_session );
			}
			else if( ( p_forward_session->forward_session_type == FORWARD_SESSION_TYPE_CLIENT || p_forward_session->forward_session_type == FORWARD_SESSION_TYPE_SERVER )
				&& p_forward_session->p_forward_rule->timeout
				&& pse->server_cache.tv.tv_sec >= p_forward_session->active_timestamp + p_forward_session->p_forward_rule->timeout )
			{
				/* 从epoll池中删除 */
				DebugOutput( pse , "close #%d# #%d# timeout\r\n" , p_forward_session->client_addr.sock , p_forward_session->server_addr.sock );
				pse->forward_session[p_forward_session->client_session_index].p_forward_rule->client_addr[p_forward_session->client_index].client_connection_count--;
				pse->forward_session[p_forward_session->server_session_index].p_forward_rule->server_addr[p_forward_session->server_index].server_connection_count--;
#ifdef USE_EPOLL
				epoll_ctl( pse->epoll_fds , EPOLL_CTL_DEL , p_forward_session->client_addr.sock , NULL );
				epoll_ctl( pse->epoll_fds , EPOLL_CTL_DEL , p_forward_session->server_addr.sock , NULL );
#endif
				_CLOSESOCKET( p_forward_session->client_addr.sock );
				_CLOSESOCKET( p_forward_session->server_addr.sock );
				SetForwardSessionUnitUnused2( pse , & (pse->forward_session[p_forward_session->client_session_index]) , & (pse->forward_session[p_forward_session->server_session_index]) );
			}
		}
	}
	
	return 0;
}

#ifdef USE_EPOLL
/* epoll服务器主工作循环 */ /* epoll server main loop */
static int ServerLoop( struct ServerEnv *pse )
{
	static struct ServerCache	server_cache ;
	
	struct ForwardSession		*p_forward_session = NULL ;
	
	int				nret = 0 ;
	
	while(1)
	{
		/* 批量等待epoll事件 */ /* batch waiting epoll events */
		pse->sock_count = epoll_wait( pse->epoll_fds , pse->events , WAIT_EVENTS_COUNT , 1000 ) ;
		
		/* 处理缓存 */ /* handle the cache  */
		gettimeofday( & (server_cache.tv) , NULL );
		if( server_cache.tv.tv_sec == pse->server_cache.tv.tv_sec )
		{
			memcpy( & (pse->server_cache) , & server_cache , sizeof(struct ServerCache) );
		}
		else
		{
			localtime_r( & (server_cache.tv.tv_sec) , & (server_cache.stime) );
			sprintf( server_cache.datetime , "%04d-%02d-%02d %02d:%02d:%02d" , server_cache.stime.tm_year+1900 , server_cache.stime.tm_mon+1 , server_cache.stime.tm_mday , server_cache.stime.tm_hour , server_cache.stime.tm_min , server_cache.stime.tm_sec ) ;
			
			memcpy( & (pse->server_cache) , & server_cache , sizeof(struct ServerCache) );
		}
		
		/* 处理超时会话 */ /* processing timeout session */
		ProcessForwardSessionTimeout( pse );
		
		/* 如果没有epoll事件，迭代之 */ /* if there is no epoll events, iteration */
		if( pse->sock_count == 0 )
			continue;
		
		/* 如果有epoll事件，处理之 */ /* if there are epoll events, deal with it  */
		for( pse->sock_index = 0 , pse->p_event = & (pse->events[0]) ; pse->sock_index < pse->sock_count ; pse->sock_index++ , pse->p_event++ )
		{
			p_forward_session = pse->p_event->data.ptr ;
			
			/* 如果是输入事件 */ /* if the input events */
			if( pse->p_event->events & EPOLLIN )
			{
				/* 如果是侦听端口事件 */ /* if the event listener port  */
				if( p_forward_session->forward_session_type == FORWARD_SESSION_TYPE_LISTEN )
				{
					/* 如果是管理端口事件 */ /* if it is a management port  */
					if( strcmp( p_forward_session->listen_addr.rule_mode , FORWARD_RULE_MODE_G ) == 0 )
					{
						nret = AcceptManageSocket( pse , p_forward_session ) ;
						if( nret > 0 )
						{
							continue;
						}
						else if( nret < 0 )
						{
							ErrorOutput( pse , "AcceptManageSocket failed[%d]\r\n" , nret );
							return nret;
						}
					}
					/* 如果是转发端口事件 */ /* if it is a forwarding port event */
					else
					{
						nret = AcceptForwardSocket( pse , p_forward_session ) ;
						if( nret > 0 )
						{
							continue;
						}
						else if( nret < 0 )
						{
							ErrorOutput( pse , "AcceptForwardSocket failed[%d]\r\n" , nret );
							return nret;
						}
					}
				}
				/* 如果是管理端口输入事件 */ /* if it is a management port input event */
				else if( p_forward_session->forward_session_type == FORWARD_SESSION_TYPE_MANAGE )
				{
					nret = ReceiveOrProcessManageData( pse , p_forward_session ) ;
					if( nret > 0 )
					{
						continue;
					}
					else if( nret < 0 )
					{
						ErrorOutput( pse , "ReceiveOrProcessManageData failed[%d]\r\n" , nret );
						return nret;
					}
				}
				/* 如果是转发端口输入事件 */ /* If it is a forwarding port input event */
				else if( p_forward_session->forward_session_type == FORWARD_SESSION_TYPE_CLIENT || p_forward_session->forward_session_type == FORWARD_SESSION_TYPE_SERVER )
				{
					nret = TransferSocketData( pse , p_forward_session ) ;
					if( nret > 0 )
					{
						continue;
					}
					else if( nret < 0 )
					{
						ErrorOutput( pse , "TransferSocketData failed[%d]\r\n" , nret );
						return nret;
					}
				}
			}
			/* 如果是输出事件 */ /* if it is output  */
			else if( pse->p_event->events & EPOLLOUT )
			{
				if( p_forward_session->forward_session_type == FORWARD_SESSION_TYPE_SERVER && p_forward_session->status == CONNECT_STATUS_CONNECTING )
				{
					/* 如果是异步连接建立响应事件 */ /* if the connection is an asynchronous response to an event is established  */
					nret = SetSocketConnected( pse , p_forward_session ) ;
					if( nret > 0 )
					{
						continue;
					}
					else if( nret < 0 )
					{
						ErrorOutput( pse , "SetSocketConnected failed[%d]\r\n" , nret );
						return nret;
					}
				}
				else if( p_forward_session->status == CONNECT_STATUS_SENDING )
				{
					/* 如果是异步发送sock可写事件 */ /* if it is asynchronous send the sock to write event */
					nret = ContinueToWriteSocketData( pse , p_forward_session ) ;
					if( nret > 0 )
					{
						continue;
					}
					else if( nret < 0 )
					{
						ErrorOutput( pse , "ContinueToWriteSocketData failed[%d]\r\n" , nret );
						return nret;
					}
				}
			}
			/* 如果是错误事件 */ /* if it is wrong to event */
			else if( pse->p_event->events & EPOLLERR )
			{
				nret = ResolveSocketError( pse , p_forward_session ) ;
				if( nret > 0 )
				{
					continue;
				}
				else if( nret < 0 )
				{
					ErrorOutput( pse , "ResolveSocketError failed[%d]\r\n" , nret );
					return nret;
				}
			}
		}
	}
	
	return 0;
}
#endif

#ifdef USE_SELECT
/* select服务器主工作循环 */ /* select server main loop */
static int ServerLoop( struct ServerEnv *pse )
{
	static struct ServerCache	server_cache ;
	
	int				max_sock ;
	fd_set				read_socks ;
	fd_set				write_socks ;
	fd_set				except_socks ;
	struct timeval			select_tv ;
	
	struct ForwardSession		*p_forward_session = NULL ;
	
	int				nret = 0 ;
	
	while(1)
	{
		/* 批量等待select事件 */ /* Wait for the select events */
		unsigned long		index ;
		struct ForwardSession	*p_forward_session = NULL ;
		
		FD_ZERO( & read_socks );
		FD_ZERO( & write_socks );
		FD_ZERO( & except_socks );
		
		max_sock = 0 ;
		for( index = 0 , p_forward_session = & (pse->forward_session[0]) ; index < pse->forward_session_maxcount ; index++ , p_forward_session++ )
		{
			if( p_forward_session->forward_session_type == FORWARD_SESSION_TYPE_LISTEN )
			{
				FD_SET( p_forward_session->listen_addr.sock , & read_socks );
				if( p_forward_session->listen_addr.sock > max_sock ) max_sock = p_forward_session->listen_addr.sock ;
			}
			else if( p_forward_session->forward_session_type == FORWARD_SESSION_TYPE_MANAGE )
			{
				FD_SET( p_forward_session->client_addr.sock , & read_socks );
				if( p_forward_session->listen_addr.sock > max_sock ) max_sock = p_forward_session->listen_addr.sock ;
			}
			else if( p_forward_session->forward_session_type == FORWARD_SESSION_TYPE_CLIENT )
			{
				if( p_forward_session->status == CONNECT_STATUS_CONNECTING )
				{
					FD_SET( p_forward_session->server_addr.sock , & write_socks );
					if( p_forward_session->server_addr.sock > max_sock ) max_sock = p_forward_session->server_addr.sock ;
				}
				else if( p_forward_session->status == CONNECT_STATUS_RECEIVING )
				{
					FD_SET( p_forward_session->client_addr.sock , & read_socks );
					if( p_forward_session->client_addr.sock > max_sock ) max_sock = p_forward_session->client_addr.sock ;
				}
				else if( p_forward_session->status == CONNECT_STATUS_SENDING )
				{
					FD_SET( p_forward_session->client_addr.sock , & write_socks );
					if( p_forward_session->client_addr.sock > max_sock ) max_sock = p_forward_session->client_addr.sock ;
				}
			}
			else if( p_forward_session->forward_session_type == FORWARD_SESSION_TYPE_SERVER )
			{
				if( p_forward_session->status == CONNECT_STATUS_CONNECTING )
				{
					FD_SET( p_forward_session->client_addr.sock , & write_socks );
					if( p_forward_session->client_addr.sock > max_sock ) max_sock = p_forward_session->client_addr.sock ;
				}
				else if( p_forward_session->status == CONNECT_STATUS_RECEIVING )
				{
					FD_SET( p_forward_session->server_addr.sock , & read_socks );
					if( p_forward_session->server_addr.sock > max_sock ) max_sock = p_forward_session->server_addr.sock ;
				}
				else if( p_forward_session->status == CONNECT_STATUS_SENDING )
				{
					FD_SET( p_forward_session->server_addr.sock , & write_socks );
					if( p_forward_session->server_addr.sock > max_sock ) max_sock = p_forward_session->server_addr.sock ;
				}
			}
		}
		
		select_tv.tv_sec = 1 ;
		select_tv.tv_usec = 0 ;
		nret = select( max_sock + 1 , & read_socks , & write_socks , & except_socks , & select_tv ) ;
		if( nret < 0 )
		{
			ErrorOutput( pse , "select failed[%d]errno[%d]\r\n" , nret , _ERRNO );
			return nret;
		}
		
		/* 处理缓存 */ /* handle the cache */
		_GETTIMEOFDAY( server_cache.tv );
		if( server_cache.tv.tv_sec == pse->server_cache.tv.tv_sec )
		{
			memcpy( & (pse->server_cache) , & server_cache , sizeof(struct ServerCache) );
		}
		else
		{
			_LOCALTIME( server_cache.tv.tv_sec , server_cache.stime );
			sprintf( server_cache.datetime , "%04d-%02d-%02d %02d:%02d:%02d" , server_cache.stime.tm_year+1900 , server_cache.stime.tm_mon+1 , server_cache.stime.tm_mday , server_cache.stime.tm_hour , server_cache.stime.tm_min , server_cache.stime.tm_sec ) ;
			
			memcpy( & (pse->server_cache) , & server_cache , sizeof(struct ServerCache) );
		}
		
		/* 处理超时会话 */ /* processing timeout session */
		ProcessForwardSessionTimeout( pse );
		
		/* 如果没有select事件，迭代之 */ /* If there is not select events, iteration */
		if( nret == 0 )
			continue;
		
		for( index = 0 , p_forward_session = & (pse->forward_session[0]) ; index < pse->forward_session_maxcount ; index++ , p_forward_session++ )
		{
			if( p_forward_session->forward_session_type == FORWARD_SESSION_TYPE_LISTEN )
			{
				if( FD_ISSET( p_forward_session->listen_addr.sock , & read_socks ) )
				{
					if( strcmp( p_forward_session->listen_addr.rule_mode , FORWARD_RULE_MODE_G ) == 0 )
					{
						/* 如果是管理端口事件 */ /* if it is a management port  */
						nret = AcceptManageSocket( pse , p_forward_session ) ;
						if( nret > 0 )
						{
							continue;
						}
						else if( nret < 0 )
						{
							ErrorOutput( pse , "AcceptManageSocket failed[%d]\r\n" , nret );
							return nret;
						}
					}
					else
					{
						/* 如果是转发端口事件 */ /* if it is a forwarding port event  */
						nret = AcceptForwardSocket( pse , p_forward_session ) ;
						if( nret > 0 )
						{
							continue;
						}
						else if( nret < 0 )
						{
							ErrorOutput( pse , "AcceptForwardSocket failed[%d]\r\n" , nret );
							return nret;
						}
					}
				}
			}
			else if( p_forward_session->forward_session_type == FORWARD_SESSION_TYPE_MANAGE )
			{
				if( FD_ISSET( p_forward_session->client_addr.sock , & read_socks ) )
				{
					/* 如果是管理端口输入事件 */ /* If it is a management port input event */
					nret = ReceiveOrProcessManageData( pse , p_forward_session ) ;
					if( nret > 0 )
					{
						continue;
					}
					else if( nret < 0 )
					{
						ErrorOutput( pse , "ReceiveOrProcessManageData failed[%d]\r\n" , nret );
						return nret;
					}
				}
			}
			else if( p_forward_session->forward_session_type == FORWARD_SESSION_TYPE_CLIENT )
			{
				if( p_forward_session->status == CONNECT_STATUS_CONNECTING && FD_ISSET( p_forward_session->server_addr.sock , & write_socks ) )
				{
					/* 如果是异步连接建立响应事件 */ /* if the connection is an asynchronous response to an event is established */
					nret = SetSocketConnected( pse , p_forward_session ) ;
					if( nret > 0 )
					{
						continue;
					}
					else if( nret < 0 )
					{
						ErrorOutput( pse , "SetSocketConnected failed[%d]\r\n" , nret );
						return nret;
					}
				}
				else if( p_forward_session->status == CONNECT_STATUS_RECEIVING && FD_ISSET( p_forward_session->client_addr.sock , & read_socks ) )
				{
					/* 如果是转发端口输入事件 */ /* if it is a forwarding port input events */
					nret = TransferSocketData( pse , p_forward_session ) ;
					if( nret > 0 )
					{
						continue;
					}
					else if( nret < 0 )
					{
						ErrorOutput( pse , "TransferSocketData failed[%d]\r\n" , nret );
						return nret;
					}
				}
				else if( p_forward_session->status == CONNECT_STATUS_SENDING && FD_ISSET( p_forward_session->client_addr.sock , & write_socks ) )
				{
					/* 如果是异步发送sock可写事件 */ /* if it is asynchronous send the sock to write event */
					nret = ContinueToWriteSocketData( pse , p_forward_session ) ;
					if( nret > 0 )
					{
						continue;
					}
					else if( nret < 0 )
					{
						ErrorOutput( pse , "ContinueToWriteSocketData failed[%d]\r\n" , nret );
						return nret;
					}
				}
			}
			else if( p_forward_session->forward_session_type == FORWARD_SESSION_TYPE_SERVER )
			{
				if( p_forward_session->status == CONNECT_STATUS_CONNECTING && FD_ISSET( p_forward_session->client_addr.sock , & write_socks ) )
				{
					/* 如果是异步连接建立响应事件 */ /* if the connection is an asynchronous response to an event is established  */
					nret = SetSocketConnected( pse , p_forward_session ) ;
					if( nret > 0 )
					{
						continue;
					}
					else if( nret < 0 )
					{
						ErrorOutput( pse , "SetSocketConnected failed[%d]\r\n" , nret );
						return nret;
					}
				}
				else if( p_forward_session->status == CONNECT_STATUS_RECEIVING && FD_ISSET( p_forward_session->server_addr.sock , & read_socks ) )
				{
					/* 如果是转发端口输入事件 */ /* if it is a forwarding port input event */
					nret = TransferSocketData( pse , p_forward_session ) ;
					if( nret > 0 )
					{
						continue;
					}
					else if( nret < 0 )
					{
						ErrorOutput( pse , "TransferSocketData failed[%d]\r\n" , nret );
						return nret;
					}
				}
				else if( p_forward_session->status == CONNECT_STATUS_SENDING && FD_ISSET( p_forward_session->server_addr.sock , & write_socks ) )
				{
					/* 如果是异步发送sock可写事件 */ /* if it is asynchronous send the sock to write event */
					nret = ContinueToWriteSocketData( pse , p_forward_session ) ;
					if( nret > 0 )
					{
						continue;
					}
					else if( nret < 0 )
					{
						ErrorOutput( pse , "ContinueToWriteSocketData failed[%d]\r\n" , nret );
						return nret;
					}
				}
			}
			else if( FD_ISSET( p_forward_session->client_addr.sock , & except_socks ) )
			{
				/* 如果是错误事件 */ /* if it is wrong to event */
				nret = ResolveSocketError( pse , p_forward_session ) ;
				if( nret > 0 )
				{
					continue;
				}
				else if( nret < 0 )
				{
					ErrorOutput( pse , "ResolveSocketError failed[%d]\r\n" , nret );
					return nret;
				}
			}
		}
	}
	
	return 0;
}
#endif

/* G5入口函数 */ /* entry function */
int G5( struct ServerEnv *pse )
{
	int			nret ;
	
	printf( "--- startup ---\n" );
	
	_GETTIMEOFDAY( pse->server_cache.tv );
	_LOCALTIME( pse->server_cache.tv.tv_sec , pse->server_cache.stime );
	sprintf( pse->server_cache.datetime , "%04d-%02d-%02d %02d:%02d:%02d" , pse->server_cache.stime.tm_year+1900 , pse->server_cache.stime.tm_mon+1 , pse->server_cache.stime.tm_mday , pse->server_cache.stime.tm_hour , pse->server_cache.stime.tm_min , pse->server_cache.stime.tm_sec ) ;
	
#ifdef USE_EPOLL
	/* 创建epoll池 */ /* create the epoll pool */
	pse->epoll_fds = epoll_create( pse->forward_session_maxcount ) ;
	if( pse->epoll_fds < 0 )
	{
		ErrorOutput( pse , "epoll_create failed[%d]errno[%d]\r\n" , pse->epoll_fds , _ERRNO );
		return -1;
	}
	
	printf( "epoll_create ok #%d#\r\n" , pse->epoll_fds );
#endif
	
	/* 装载配置文件 */ /* Load configuration file */
	nret = LoadConfig( pse ) ;
	if( nret )
	{
		ErrorOutput( pse , "load config failed[%d]\r\n" , nret );
		return nret;
	}
	
	/* 服务器主工作循环 */ /* server main loop */
	nret = ServerLoop( pse ) ;
	if( nret )
	{
		ErrorOutput( pse , "server loop failed[%d]\r\n" , nret );
		return nret;
	}
	
#ifdef USE_EPOLL
	/* 销毁epoll池 */ /* destroy the epoll pool  */
	_CLOSESOCKET( pse->epoll_fds );
#endif
	
	return 0;
}

#if ( defined _WIN32 )

/* for testing
G5 -f ..\..\..\test\demo-win.conf -d -r 10 -s 1024 -b 100 --install-service
*/

/* 安装、卸载WINDOWS服务 */ /* Install and uninstall the WINDOWS service */
static int InstallService( struct ServerEnv *pse )
{
	SC_HANDLE		schSCManager;
	SC_HANDLE		schService;
	SERVICE_DESCRIPTION	stServiceDescription ;
	
	char		acPathFileName[ 256 + 1 ];
	char		acPathName[ 256 + 1 ];
	char		acStartCommand[ 256 + 1 ];
	
	memset( acPathFileName , 0x00 , sizeof( acPathFileName ) );
	GetModuleFileName( NULL, acPathFileName , 255 );
	strcpy( acPathName , acPathFileName );
	if( strrchr( acPathName , '\\' ) )
		strrchr( acPathName , '\\' )[0] = '\0' ;
	sprintf( acStartCommand , "\"%s\" -f \"%s\\%s\"" , acPathFileName , acPathName , pse->cmd_para.config_pathfilename );
	if( pse->cmd_para.forward_rule_maxcount != DEFAULT_FORWARD_RULE_MAXCOUNT )
		sprintf( acStartCommand + strlen(acStartCommand) , " -r %ld" , pse->cmd_para.forward_rule_maxcount );
	if( pse->cmd_para.forward_connection_maxcount != DEFAULT_CONNECTION_MAXCOUNT )
		sprintf( acStartCommand + strlen(acStartCommand) , " -s %ld" , pse->cmd_para.forward_connection_maxcount );
	if( pse->cmd_para.transfer_bufsize != DEFAULT_TRANSFER_BUFSIZE )
		sprintf( acStartCommand + strlen(acStartCommand) , " -b %ld" , pse->cmd_para.transfer_bufsize );
	if( pse->cmd_para.debug_flag == 1 )
		sprintf( acStartCommand + strlen(acStartCommand) , " -d" );
	sprintf( acStartCommand + strlen(acStartCommand) , " --service" );
	
	schSCManager = OpenSCManager( NULL , NULL , SC_MANAGER_CREATE_SERVICE ) ;
	if( schSCManager == NULL )
		return -1;
	
	schService = CreateService( schSCManager ,
				SERVICE_NAME ,
				SERVICE_NAME ,
				SERVICE_ALL_ACCESS ,
				SERVICE_WIN32_OWN_PROCESS|SERVICE_INTERACTIVE_PROCESS ,
				SERVICE_AUTO_START ,
				SERVICE_ERROR_NORMAL ,
				acStartCommand ,
				NULL ,
				NULL ,
				NULL ,
				NULL ,
				NULL );
	if( schService == NULL )
	{
		CloseServiceHandle( schSCManager );
		return -2;
	}
	
	stServiceDescription.lpDescription = SERVICE_DESC ;
	if( ! ChangeServiceConfig2( schService , SERVICE_CONFIG_DESCRIPTION , & stServiceDescription ) )
	{
		CloseServiceHandle( schService );
		CloseServiceHandle( schSCManager );
		return -3;
	}
	
	CloseServiceHandle( schService );
	CloseServiceHandle( schSCManager );
	
	return 0;
}

static int UninstallService( struct ServerEnv *pse )
{
	SC_HANDLE	schSCManager;
	SC_HANDLE	schService;
	
	BOOL		bReturnValue;
	
	schSCManager = OpenSCManager( NULL , NULL , SC_MANAGER_CREATE_SERVICE ) ;
	if( schSCManager == NULL )
		return -1;
	
	schService = OpenService( schSCManager , SERVICE_NAME , SERVICE_ALL_ACCESS ) ;
	if( schService == NULL )
	{
		CloseServiceHandle( schSCManager );
		return -2;
	}
	
	bReturnValue = DeleteService( schService ) ;
	if( bReturnValue == FALSE )
	{
		CloseServiceHandle( schSCManager );
		return -3;
	}
	
	CloseServiceHandle( schService );
	CloseServiceHandle( schSCManager );
	
	return 0;
}

static void WINAPI ServiceCtrlHandler( DWORD dwControl )
{
	switch ( dwControl )
	{
		case SERVICE_CONTROL_STOP:
		case SERVICE_CONTROL_SHUTDOWN:
			g_stServiceStatus.dwCurrentState = SERVICE_STOP_PENDING ;
			SetServiceStatus( g_hServiceStatusHandle , & g_stServiceStatus ) ;
			
			g_stServiceStatus.dwCurrentState = SERVICE_STOPPED ;
			SetServiceStatus( g_hServiceStatusHandle , & g_stServiceStatus) ;
			
			break;
			
		case SERVICE_CONTROL_PAUSE:
			g_stServiceStatus.dwCurrentState = SERVICE_PAUSE_PENDING ;
			SetServiceStatus( g_hServiceStatusHandle , & g_stServiceStatus ) ;
			
			g_stServiceStatus.dwCurrentState = SERVICE_PAUSED ;
			SetServiceStatus( g_hServiceStatusHandle , & g_stServiceStatus) ;
			
			break;
		
		case SERVICE_CONTROL_CONTINUE:
			g_stServiceStatus.dwCurrentState = SERVICE_CONTINUE_PENDING ;
			SetServiceStatus( g_hServiceStatusHandle , & g_stServiceStatus ) ;
			
			g_stServiceStatus.dwCurrentState = SERVICE_RUNNING ;
			SetServiceStatus( g_hServiceStatusHandle , & g_stServiceStatus) ;
			
			break;
			
		case SERVICE_CONTROL_INTERROGATE:
			g_stServiceStatus.dwCurrentState = SERVICE_RUNNING ;
			SetServiceStatus( g_hServiceStatusHandle , & g_stServiceStatus) ;
			
			break;
			
		default:
			break;
			
	}
	
	return;
}

static void WINAPI ServiceMainProc( DWORD argc , LPTSTR *argv )
{
	g_stServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS ;
	g_stServiceStatus.dwCurrentState = SERVICE_START_PENDING ;
	g_stServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP ;
	g_stServiceStatus.dwWin32ExitCode = 0 ;
	g_stServiceStatus.dwServiceSpecificExitCode = 0 ;
	g_stServiceStatus.dwCheckPoint = 0 ;
	g_stServiceStatus.dwWaitHint = 0 ;
	
	g_hServiceStatusHandle = RegisterServiceCtrlHandler( SERVICE_NAME , ServiceCtrlHandler ) ;
	if( g_hServiceStatusHandle == (SERVICE_STATUS_HANDLE)0 )
		return;
	
	g_stServiceStatus.dwCheckPoint = 0 ;
	g_stServiceStatus.dwWaitHint = 0 ;
	g_stServiceStatus.dwCurrentState = SERVICE_RUNNING ;
	
	SetServiceStatus( g_hServiceStatusHandle , & g_stServiceStatus );
	
	G5( g_pse );
	
	return;
}

#endif

/* 软件版本及命令行参数说明 */ /* version and the command line parameters  */
static void copyright()
{
	printf( "%s - %s\r\n" , SERVICE_NAME , SERVICE_DESC );
	printf( "Copyright by calvin (calvinwilliams.c@gmail.com)\r\n" );
	return;
}

static void version()
{
	printf( "v%s build %s %s %d:%d:%d,%d:%d:%d,%d\r\n" , VERSION , __DATE__ , __TIME__
		, DEFAULT_FORWARD_RULE_MAXCOUNT , DEFAULT_CONNECTION_MAXCOUNT , DEFAULT_TRANSFER_BUFSIZE
		, RULE_CLIENT_MAXCOUNT , RULE_FORWARD_MAXCOUNT , RULE_SERVER_MAXCOUNT
		, RULE_ID_MAXLEN );
	return;
}

static void usage()
{
	printf( "USAGE : G5 -f config_pathfilename [ -r forward_rule_maxcount ] [ -s forward_connection_maxcount ] [ -b transfer_bufsize ] [ -d ]\r\n" );
	printf( "           -v\r\n" );
#if ( defined _WIN32 )
	printf( "           [ --install-service | --uninstall-service ]\n" );
#endif
	return;
}

int main( int argc , char *argv[] )
{
	struct ServerEnv	se , *pse = & se ;
	
	long			n ;
	
	int			nret = 0 ;
	
#if ( defined _WIN32 )
	if( WSAStartup( MAKEWORD(2,2) , &wsd ) != 0 )
		return 9;
#endif

	/* 设置标准输出无缓冲 */
	setbuf( stdout , NULL );
	
	/* 设置随机数种子 */
	srand( (unsigned)time(NULL) );
	
	if( argc > 1 )
	{
		/* 初始化服务器环境 */ /* initialize the server environment  */
		memset( pse , 0x00 , sizeof(struct ServerEnv) );
		
		/* 初始化命令行参数 */ /* initialize the command line parameters */
		pse->cmd_para.forward_rule_maxcount = DEFAULT_FORWARD_RULE_MAXCOUNT ;
		pse->cmd_para.forward_connection_maxcount = DEFAULT_CONNECTION_MAXCOUNT ;
		pse->cmd_para.transfer_bufsize = DEFAULT_TRANSFER_BUFSIZE ;
		
		/* 分析命令行参数 */ /* analysis of command line parameters */
		for( n = 1 ; n < argc ; n++ )
		{
			if( strcmp( argv[n] , "-v" ) == 0 && 1 + 1 == argc )
			{
				version();
				exit(0);
			}
			else if( strcmp( argv[n] , "-f" ) == 0 && n + 1 < argc )
			{
				n++;
				pse->cmd_para.config_pathfilename = argv[n] ;
			}
			else if( strcmp( argv[n] , "-r" ) == 0 && n + 1 < argc )
			{
				n++;
				pse->cmd_para.forward_rule_maxcount = atol(argv[n]) ;
			}
			else if( strcmp( argv[n] , "-s" ) == 0 && n + 1 < argc )
			{
				n++;
				pse->cmd_para.forward_connection_maxcount = atol(argv[n]) ;
			}
			else if( strcmp( argv[n] , "-b" ) == 0 && n + 1 < argc )
			{
				n++;
				pse->cmd_para.transfer_bufsize = atol(argv[n]) ;
			}
			else if( strcmp( argv[n] , "-d" ) == 0 )
			{
				pse->cmd_para.debug_flag = 1 ;
			}
#if ( defined _WIN32 )
			else if( strcmp( argv[n] , "--install-service" ) == 0 )
			{
				pse->cmd_para.install_service_flag = 1 ;
			}
			else if( strcmp( argv[n] , "--uninstall-service" ) == 0 )
			{
				pse->cmd_para.uninstall_service_flag = 1 ;
			}
			else if( strcmp( argv[n] , "--service" ) == 0 )
			{
				pse->cmd_para.service_flag = 1 ;
			}
#endif
			else
			{
				fprintf( stderr , "invalid opt[%s]\r\n" , argv[n] );
				usage();
				exit(7);
			}
		}
		
#if ( defined _WIN32 )
		/* 卸载WINDOWS服务 */ /* Uninstall the WINDOWS service */
		if( pse->cmd_para.uninstall_service_flag == 1 )
		{
			nret = UninstallService( pse ) ;
			if( nret )
			{
				fprintf( stderr , "卸载WINDOWS服务失败[%d]errno[%d]\n" , nret , _ERRNO );
				exit(1);
			}
			else
			{
				fprintf( stderr , "卸载WINDOWS服务成功\n" );
				exit(0);
			}
		}
#endif
		
		if( pse->cmd_para.config_pathfilename == NULL )
		{
			copyright();
			usage();
			return 7;
		}
		
#if ( defined _WIN32 )
		/* 安装WINDOWS服务 */ /* Install a WINDOWS service  */
		if( pse->cmd_para.install_service_flag == 1 )
		{
			nret = InstallService( pse ) ;
			if( nret )
			{
				fprintf( stderr , "安装WINDOWS服务失败[%d]errno[%d]\n" , nret , _ERRNO );
				exit(1);
			}
			else
			{
				fprintf( stderr , "安装WINDOWS服务成功\n" );
				exit(0);
			}
		}
#endif
		
		/* 申请服务器环境内部内存 */ /* alloc server environment internal memory */
		pse->forward_rule = (struct ForwardRule *)malloc( sizeof(struct ForwardRule) * pse->cmd_para.forward_rule_maxcount ) ;
		if( pse->forward_rule == NULL )
		{
			fprintf( stderr , "alloc failed , errno[%d]\r\n" , _ERRNO );
			return 7;
		}
		memset( pse->forward_rule , 0x00 , sizeof(struct ForwardRule) * pse->cmd_para.forward_rule_maxcount );
		
		pse->forward_session_maxcount = pse->cmd_para.forward_connection_maxcount * 3 ;
		pse->forward_session = (struct ForwardSession *)malloc( sizeof(struct ForwardSession) * pse->forward_session_maxcount ) ;
		if( pse->forward_session == NULL )
		{
			fprintf( stderr , "alloc failed , errno[%d]\r\n" , _ERRNO );
			return 7;
		}
		memset( pse->forward_session , 0x00 , sizeof(struct ForwardSession) * pse->forward_session_maxcount );
		
		pse->stat_addr_maxcount = pse->forward_session_maxcount * 2 ;
		pse->stat_addr = (struct StatNetAddress *)malloc( sizeof(struct StatNetAddress) * pse->stat_addr_maxcount ) ;
		if( pse->stat_addr == NULL )
		{
			fprintf( stderr , "alloc failed , errno[%d]\r\n" , _ERRNO );
			return 7;
		}
		memset( pse->stat_addr , 0x00 , sizeof(struct StatNetAddress) * pse->stat_addr_maxcount );
		
		copyright();
		
		printf( "--- configure ---\n" );
		printf( "forward_rule_maxcount       [%ld]\r\n" , pse->cmd_para.forward_rule_maxcount );
		printf( "forward_connection_maxcount [%ld]\r\n" , pse->cmd_para.forward_connection_maxcount );
		printf( "transfer_bufsize            [%ld]bytes\r\n" , pse->cmd_para.transfer_bufsize );
		
		/* 调用G5入口函数 */ /* Call the entry function */
		if( pse->cmd_para.service_flag == 0 )
		{
			nret = G5( pse ) ;
			if( nret )
				return nret;
		}
		else
		{
#if ( defined _WIN32 )
			SERVICE_TABLE_ENTRY ste [] =
			{
				{ SERVICE_NAME , ServiceMainProc },
				{ NULL , NULL }
			} ;
			
			g_pse = pse ;
			
			if( ! StartServiceCtrlDispatcher( ste ) )
				return 3;
#endif
		}
	}
	else
	{
		copyright();
		usage();
		return 1;
	}
	
#if ( defined _WIN32 )
	WSACleanup();
#endif
	
	return 0;
}

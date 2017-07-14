
#ifndef __SVR_SESSION_MANAGER_HH_
#define __SVR_SESSION_MANAGER_HH_

#include <list>
#include <set>
#include <stdlib.h>
#include <boost/thread/mutex.hpp>
#include <boost/smart_ptr/detail/spinlock.hpp>
#include "tcp_client.hpp"
#include "conhash.h"
#include "conhash_inter.h"

typedef std::set<CTcpClient_ptr> TCPCLIENT_SET;
typedef std::map<int, unsigned int> SVRTYPE_CONNID_MAP;
typedef std::map<unsigned int, conhash_s * > SVRTYPE_CONHASH_MAP;
typedef std::set<unsigned int> SVR_CONNID_SET;

#define MAX_NODE_NUM 512

class CSvrSessionManager
{
public:
	CSvrSessionManager();

	virtual ~CSvrSessionManager();

	//add server connection.
	void add_svr_conn(int svr_type, CTcpClient_ptr connection);

	//add server hash node.
	void add_svr_node(unsigned int svr_type, unsigned int svr_conn);

	//delete server hash node.
	void del_svr_node(unsigned int svr_type, unsigned int svr_conn);

	void del_conn_inf(unsigned int idConn);

	void del_conn_inf_by_type(unsigned int idConn, unsigned int svr_type);

	CTcpClient_ptr add_conn_inf(int svr_type, unsigned int idConn, const std::string & distributed_value = "");

    CTcpClient_ptr get_conn_inf(int svr_type, unsigned int idConn, const std::string & distributed_value = "");
  
	void print_conn_inf();

	void get_usermgr_svr(std::set<CTcpClient_ptr> & ret);

private:
	boost::mutex svr_conn_mutex_;
  std::map<int, TCPCLIENT_SET > svr_sessions_;
  std::map<unsigned int, SVRTYPE_CONNID_MAP > session_map_;
	std::map<int, SVR_CONNID_SET > m_mapNode;
	std::map<int, node_s * > m_nodes;

	//key:svr_type,value:conhash_s
	SVRTYPE_CONHASH_MAP m_svr_conhash;
};

#endif  //__SVR_SESSION_MANAGER_HH_



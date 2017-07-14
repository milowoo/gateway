
#include "svrsession_manager.h"
#include <iostream>
#include "CLogThread.h"
#include "WebgateApplication.h"

CSvrSessionManager::CSvrSessionManager()
{
    session_map_.clear();
	svr_sessions_.clear();
	m_mapNode.clear();
	m_svr_conhash.clear();
	m_nodes.clear();
}

CSvrSessionManager::~CSvrSessionManager()
{
	boost::mutex::scoped_lock lock(svr_conn_mutex_);
	
	SVRTYPE_CONHASH_MAP::iterator iter = m_svr_conhash.begin();
	for (; iter != m_svr_conhash.end(); ++iter)
	{
		conhash_s * phash = iter->second;
		if (phash)
		{
			conhash_fini(phash);
		}
	}

	std::map<int, node_s * >::iterator iter_map = m_nodes.begin();
	for (; iter_map != m_nodes.end(); ++iter_map)
	{
		node_s * node_array = iter_map->second;
		if (node_array)
		{
			delete[] node_array;
			node_array = NULL;
		}
	}
}

//add server connection.
void CSvrSessionManager::add_svr_conn(int svr_type, CTcpClient_ptr connection)
{
	boost::mutex::scoped_lock lock(svr_conn_mutex_);

    std::map<int, TCPCLIENT_SET >::iterator iter = svr_sessions_.find(svr_type);
    if (iter != svr_sessions_.end())
    {
        iter->second.insert(connection);
    }
    else
    {
        TCPCLIENT_SET tcpset;
        tcpset.insert(connection);
        svr_sessions_.insert(std::make_pair(svr_type, tcpset));
    }

	if (m_svr_conhash.end() == m_svr_conhash.find(svr_type))
	{
		conhash_s * phash = conhash_init(NULL);
		if (phash)
		{
			m_svr_conhash.insert(std::make_pair(svr_type, phash));
		}
	}
	
	std::map<int, SVR_CONNID_SET >::iterator iter_map = m_mapNode.find(svr_type);
	if (m_mapNode.end() == iter_map)
	{
		SVR_CONNID_SET connid_set;
		m_mapNode.insert(std::make_pair(svr_type, connid_set));
	}

	std::map<int, node_s * >::iterator iter_array = m_nodes.find(svr_type);
	if (m_nodes.end() == iter_array)
	{
		node_s * node_array = new node_s[MAX_NODE_NUM + 1];
		m_nodes.insert(std::make_pair(svr_type, node_array));
	}

	char cIdentify[128] = {0};
	unsigned int svr_conn = connection->getconn_ssn();
	sprintf(cIdentify, "mach%u", svr_conn);
	int nvirnum = 30;

	node_s * pnode = m_nodes[svr_type];
	conhash_set_node(&pnode[svr_conn], cIdentify, nvirnum);
	LOG_PRINT(log_info, "conhash_set_node success.svr_type:%u,svr_conn:%u,nvirnum:%u.", svr_type, svr_conn, nvirnum);
}

//add server hash node
void CSvrSessionManager::add_svr_node(unsigned int svr_type, unsigned int svr_conn)
{
	if (svr_conn >= MAX_NODE_NUM)
	{
		LOG_PRINT(log_error, "server connect id is larger than %u.", MAX_NODE_NUM);
		return;
	}

	boost::mutex::scoped_lock lock(svr_conn_mutex_);

	std::map<int, SVR_CONNID_SET >::iterator iter_map = m_mapNode.find(svr_type);
	if (m_mapNode.end() == iter_map)
	{
		LOG_PRINT(log_error, "m_mapNode cannot find this svr_type:%u.pls check config file.", svr_type);
		return;
	}

	SVR_CONNID_SET::iterator iter = iter_map->second.find(svr_conn);
	if (iter_map->second.end() == iter)
	{
		if (m_svr_conhash.end() != m_svr_conhash.find(svr_type) && m_nodes.end() != m_nodes.find(svr_type))
		{
			conhash_s * phash = m_svr_conhash[svr_type];
			node_s * pnode = m_nodes[svr_type];
			conhash_add_node(phash, &pnode[svr_conn]);
			iter_map->second.insert(svr_conn);
			LOG_PRINT(log_info, "conhash_add_node success.svr_type:%u,svr_conn:%u.", svr_type, svr_conn);
		}
		else
		{
			LOG_PRINT(log_error, "conhash_add_node failed.svr_type:%u,svr_conn:%u.", svr_type, svr_conn);
		}
	}
}

//delete server hash node
void CSvrSessionManager::del_svr_node(unsigned int svr_type, unsigned int svr_conn)
{
	boost::mutex::scoped_lock lock(svr_conn_mutex_);

	std::map<int, SVR_CONNID_SET >::iterator iter_map = m_mapNode.find(svr_type);
	if (m_mapNode.end() == iter_map)
	{
		LOG_PRINT(log_error, "m_mapNode cannot find this svr_type:%u.pls check config file.", svr_type);
		return;
	}

	std::set<unsigned int>::iterator iter = iter_map->second.find(svr_conn);
	if (iter != iter_map->second.end())
	{
		if (m_svr_conhash.end() != m_svr_conhash.find(svr_type) && m_nodes.end() != m_nodes.find(svr_type))
		{
			conhash_s * phash = m_svr_conhash[svr_type];
			node_s * pnode = m_nodes[svr_type];
			conhash_del_node(phash, &pnode[svr_conn]);
			iter_map->second.erase(svr_conn);
			LOG_PRINT(log_info, "conhash_del_node success.svr_type:%u,svr_conn:%u.", svr_type, svr_conn);
		}
		else
		{
			iter_map->second.erase(svr_conn);
			LOG_PRINT(log_error, "conhash_del_node failed.svr_type:%u,svr_conn:%u.", svr_type, svr_conn);
		}
	}
}

//增加一个新用户链接 
CTcpClient_ptr CSvrSessionManager::add_conn_inf(int svr_type, unsigned int idConn, const std::string & distributed_value)
{
    CTcpClient_ptr pMinSvrConnPtr;
	
    boost::mutex::scoped_lock lock(svr_conn_mutex_);

    std::map<int, TCPCLIENT_SET >::iterator iter_svrmap = svr_sessions_.find(svr_type);
    if (svr_sessions_.end() == iter_svrmap)
    {
        LOG_PRINT(log_error, "svr_sessions_ cannot find this svr_type:%u,connectid:%u", svr_type, idConn);
        return pMinSvrConnPtr;    
    }

    TCPCLIENT_SET & tcpset = iter_svrmap->second;

	if (distributed_value.empty())
	{
		//choose the min connection num
		unsigned int minConnNum = 99999999;
		int isfirst = 0;
		TCPCLIENT_SET::iterator iter = tcpset.begin();
		for (; iter != tcpset.end(); iter++)
		{
			CTcpClient_ptr pSvrConnPtr = *iter;

			if (!pSvrConnPtr)
			{
				continue;
			}

			//check if the connection is ok
			if (!pSvrConnPtr->is_connected())
			{
				continue;
			}

			//find out the minConnNum of server connection.
			if (isfirst == 0)
			{
				isfirst = 1;
				minConnNum = pSvrConnPtr->getconn_num();
				pMinSvrConnPtr = pSvrConnPtr;
			}
			else if (pSvrConnPtr->getconn_num() <  minConnNum)
			{
				minConnNum = pSvrConnPtr->getconn_num();
				pMinSvrConnPtr = pSvrConnPtr;
			}
		}
	}
	else
	{
		//arrange server according to distributed value,use consistent hash
		if (m_svr_conhash.end() == m_svr_conhash.find(svr_type))
		{
			LOG_PRINT(log_error, "m_svr_conhash cannot find this svr_type:%u,connectid:%u", svr_type, idConn);
			return pMinSvrConnPtr;    
		}
		else
		{
			conhash_s * phash = m_svr_conhash[svr_type];
			char cDistributed[128] = {0};
			sprintf(cDistributed, "%s", distributed_value.c_str());
			const struct node_s * node = conhash_lookup(phash, cDistributed);
			if (node)
			{
				char cIdentify[128] = {0};
				strcpy(cIdentify, node->iden);
				TCPCLIENT_SET::iterator iter = tcpset.begin();
				for (; iter != tcpset.end(); iter++)
				{
					CTcpClient_ptr pSvrConnPtr = *iter;
					
					if (!pSvrConnPtr)
					{
						continue;
					}

					//check if the connection is ok
					if (!pSvrConnPtr->is_connected())
					{
						continue;
					}

					char sNode[128] = {0};
					sprintf(sNode, "mach%u", pSvrConnPtr->getconn_ssn());
					if (strcmp(sNode, cIdentify) == 0)
					{
						pMinSvrConnPtr = pSvrConnPtr;
					}
				}
			}
		}
	}

    if (pMinSvrConnPtr != 0)
    {
        pMinSvrConnPtr->addconn_id(idConn);
        unsigned int svrid = pMinSvrConnPtr->getconn_ssn();

        std::map<unsigned int, SVRTYPE_CONNID_MAP >::iterator iter_sessmap = session_map_.find(idConn);
        if (session_map_.end() == iter_sessmap)
        {
            SVRTYPE_CONNID_MAP svr_conn;
            svr_conn.insert(std::make_pair(svr_type, svrid));
            session_map_.insert(std::make_pair(idConn, svr_conn));
            LOG_PRINT(log_debug, "Have added one user connection.svr_type:%u,connectid:%u.", svr_type, idConn);
        }
        else
        {
            iter_sessmap->second[svr_type] = svrid;
            LOG_PRINT(log_debug, "Have added one user connection.svr_type:%u,connectid:%u.", svr_type, idConn);
        }
    }

    return pMinSvrConnPtr;
}

//获取服务器链接信息
CTcpClient_ptr CSvrSessionManager::get_conn_inf(int svr_type, unsigned int idConn, const std::string & distributed_value)
{
    CTcpClient_ptr pSvrConnPtr;
	
    if (0 == svr_type)
    {
        LOG_PRINT(log_error, "svr_type is 0. client connect id:%u.", idConn);
        return pSvrConnPtr;
    }

    do 
    {
        boost::mutex::scoped_lock lock(svr_conn_mutex_);

        std::map<unsigned int, SVRTYPE_CONNID_MAP >::iterator iter = session_map_.find(idConn);
        if (iter == session_map_.end())
        {
            LOG_PRINT(log_warning, "cannot find this connectid.svr_type:%d,client connect id:%u.", svr_type, idConn);
            break;
        }

        SVRTYPE_CONNID_MAP & svr_map = iter->second;
        SVRTYPE_CONNID_MAP::iterator iter_svr = svr_map.find(svr_type);
        if (iter_svr == svr_map.end())
        {
            //LOG_PRINT(log_warning, "cannot find this type of server connectid.svr_type:%d,client connect id:%u.", svr_type, idConn);
            break;
        }

        //get server connect id
        unsigned int iSsnConn = iter_svr->second;

        //use svr_type and iSsnConn to find tcp client.
        std::map<int, TCPCLIENT_SET >::iterator iter_map = svr_sessions_.find(svr_type);
        if (iter_map == svr_sessions_.end())
        {
            LOG_PRINT(log_warning, "cannot find this type of server.svr_type:%d,client connect id:%u.", svr_type, idConn);
            break;
        }

        TCPCLIENT_SET & tcpset = iter_map->second;
        std::set<CTcpClient_ptr>::iterator iter_set = tcpset.begin();
        for (; iter_set != tcpset.end(); iter_set++)
        {
            pSvrConnPtr = *iter_set;
			if (!pSvrConnPtr)
			{
				continue;
			}

            //check if server connection is ok
            if (!pSvrConnPtr->is_connected())
            {
                continue;
            }

            if (pSvrConnPtr->getconn_ssn() == iSsnConn)
            {
                return pSvrConnPtr;
            }
        }
    } while (0);

	return this->add_conn_inf(svr_type, idConn, distributed_value);
}

//删除用户的链接
void CSvrSessionManager::del_conn_inf(unsigned int idConn)
{
    boost::mutex::scoped_lock lock(svr_conn_mutex_);

    do 
    {
        std::map<unsigned int, SVRTYPE_CONNID_MAP >::iterator iter = session_map_.find(idConn);
        if (iter == session_map_.end())
        {
            break;
        }

        SVRTYPE_CONNID_MAP & svr_map = iter->second;
        SVRTYPE_CONNID_MAP::iterator iter_svr = svr_map.begin();
        for (; iter_svr != svr_map.end(); ++iter_svr)
        {
            int svr_type = iter_svr->first;
            unsigned int iSsnConn = iter_svr->second;

            //use svr_type and iSsnConn to find TcpClient
            std::map<int, TCPCLIENT_SET >::iterator iter_sess = svr_sessions_.find(svr_type);
            if (iter_sess != svr_sessions_.end())
            {
                TCPCLIENT_SET & tcpset = iter_sess->second;

                TCPCLIENT_SET::iterator iter_set = tcpset.begin();
                for (; iter_set != tcpset.end(); ++iter_set)
                {
                    CTcpClient_ptr pSvrConnPtr = (*iter_set);
                    if (!pSvrConnPtr)
                    {
                        continue;
                    }

                    if (pSvrConnPtr->getconn_ssn() == iSsnConn)
                    {
                        pSvrConnPtr->delconn_id(idConn);
                        break;
                    }
                }
            }
        }
    } while (0);

    session_map_.erase(idConn);
	return;
}

void CSvrSessionManager::del_conn_inf_by_type(unsigned int idConn, unsigned int svr_type)
{
	boost::mutex::scoped_lock lock(svr_conn_mutex_);

	std::map<unsigned int, SVRTYPE_CONNID_MAP >::iterator iter = session_map_.find(idConn);
	if (iter != session_map_.end())
	{
		iter->second.erase(svr_type);
	}

	return;
}

//打印连接信息
void CSvrSessionManager::print_conn_inf()
{
	boost::mutex::scoped_lock lock(svr_conn_mutex_);

	std::map<int, TCPCLIENT_SET >::iterator iter = svr_sessions_.begin();
	for (; iter != svr_sessions_.end(); ++iter)
	{
        int type = iter->first;
        TCPCLIENT_SET & tcpset = iter->second;
        TCPCLIENT_SET::iterator iter_set = tcpset.begin();
        for (; iter_set != tcpset.end(); ++iter_set)
        {
            CTcpClient_ptr pSvrConnPtr = *iter_set;
			if (!pSvrConnPtr)
			{
				continue;
			}

            //check if server connection is ok
            if (!pSvrConnPtr->is_connected())
            {
                continue;
            }

			LOG_PRINT(log_debug, "print_conn_inf type:%d,svr_conn:%d,conn_num:%d.", type, pSvrConnPtr->getconn_ssn(), pSvrConnPtr->getconn_num());
        }
	}
}

//get usermgrsvr connection
void CSvrSessionManager::get_usermgr_svr(std::set<CTcpClient_ptr> & ret)
{
	
	ret.clear();

	boost::mutex::scoped_lock lock(svr_conn_mutex_);

	std::map<int, TCPCLIENT_SET >::iterator iter_svrmap = svr_sessions_.find(e_usermgrsvr_type);
	if (svr_sessions_.end() != iter_svrmap)
	{
		ret.insert(iter_svrmap->second.begin(), iter_svrmap->second.end());    
	}
	
}

/*************************************************************** 文件结束 *********************************************************************/


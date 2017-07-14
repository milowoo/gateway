
#include "clientsession_manager.h"
#include <iostream>
#include "message_vchat.h"
#include "cmd_vchat.h"
#include "CLogThread.h"
#include "GlobalSetting.h"

CClientSessionManager::CClientSessionManager()
:next_sessionid_(1),
last_alarmnotify_time_(0)
{
    m_mapuser.clear();
	m_user_connid_map.clear();
}

CClientSessionManager::~CClientSessionManager()
{

}

void CClientSessionManager::del_client(connection_ptr connection)
{
    if (!connection)
    {
        return;
    }

	boost::mutex::scoped_lock lock(client_session_mutex_);

	char sBuf[128]={0};
	sprintf(sBuf, "%d_%d_%d", connection->getuserid(), connection->getmobile(), connection->getlastlogintime());
	std::string strKey = std::string(sBuf);

	m_mapuser.erase(strKey);

	std::map<unsigned int, std::set<unsigned int> >::iterator iter = m_user_connid_map.find(connection->getuserid());
	if (iter != m_user_connid_map.end())
	{
		iter->second.erase(connection->connection_id());
		if (iter->second.empty())
		{
			m_user_connid_map.erase(iter);
		}
	}

	session_map_.erase(connection->connection_id());
	LOG_PRINT(log_debug, "CClientSessionManager::del_client()[id:%d,%s],total-size=[%d].", connection->connection_id(), strKey.c_str(), session_map_.size());
}

void CClientSessionManager::update_client_map(connection_ptr connection)
{
	boost::mutex::scoped_lock lock(client_session_mutex_);
	session_map_[connection->connection_id()] = connection;
	LOG_PRINT(log_debug, "CClientSessionManager::update_client_map() session[id:%d], total-size=%d.", connection->connection_id(), session_map_.size());
}

connection_ptr CClientSessionManager::find_client_map(unsigned int connect_id)
{
	connection_ptr connection;
	boost::mutex::scoped_lock lock(client_session_mutex_);
	if(session_map_.size() > 0)
	{
		std::map<unsigned int, connection_ptr >::iterator iter = session_map_.find(connect_id);
		if(iter != session_map_.end())
		{
			connection = iter->second;
		}
	}
	return connection;
}

//send msg to client connection by connID,0 means success, others means fail.
int CClientSessionManager::send_msg_to_client_by_connID(unsigned int connect_id, SL_ByteBuffer & buff)
{
	boost::mutex::scoped_lock lock(client_session_mutex_);
	std::map<unsigned int, connection_ptr >::iterator iter = session_map_.find(connect_id);
	if(iter != session_map_.end())
	{
		if (iter->second.get())
		{
			/*
			LOG_PRINT(log_debug, "[send_msg_to_client_by_connID]client connid:%u,%s:%u.msg len:%u", \
				connect_id, iter->second.get()->remote_ip().c_str(), iter->second.get()->remote_port(), buff.data_size());
			*/
			iter->second.get()->write_message(buff.data(), buff.data_size());
			return 0;
		}
	}
	return -1;
}

void CClientSessionManager::setuserconn(unsigned int userid, byte nmobile, unsigned int nlogintime, unsigned int idconn)
{
	char sBuf[128] = {0};
	sprintf(sBuf, "%d_%d_%d", userid, nmobile, nlogintime);
	std::string strKey = std::string(sBuf);

    boost::mutex::scoped_lock lock(client_session_mutex_);
    std::map<std::string, unsigned int>::iterator iter = m_mapuser.find(strKey);
    if (iter != m_mapuser.end())
    {
        iter->second = idconn;
    }
    else
    {
        m_mapuser.insert(std::make_pair(strKey, idconn));
    }

	std::map<unsigned int, std::set<unsigned int> >::iterator iter_map = m_user_connid_map.find(userid);
	if (iter_map != m_user_connid_map.end())
	{
		iter_map->second.insert(idconn);
	}
	else
	{
		std::set<unsigned int> connid_set;
		connid_set.insert(idconn);
		m_user_connid_map.insert(std::make_pair(userid, connid_set));
	}
}

connection_ptr CClientSessionManager::find_user_conn(unsigned int iduser,byte nmoblie, unsigned int nlogintime)
{
	connection_ptr connection;
	boost::mutex::scoped_lock lock(client_session_mutex_);

	char sBuf[128]={0};
	sprintf(sBuf, "%d_%d_%d", iduser, nmoblie, nlogintime);
	std::string strKey = std::string(sBuf);

	std::map<std::string, unsigned int>::iterator iter_user = m_mapuser.find(strKey);
	if (iter_user != m_mapuser.end())
	{
		unsigned int connect_id = iter_user->second;
		std::map<unsigned int, connection_ptr >::iterator iter = session_map_.find(connect_id);
		if(iter != session_map_.end())
		{
			connection = iter->second;
		}
	}
	else
	{
		LOG_PRINT(log_warning, "CClientSessionManager::find_user_conn() user :[%s] not found", sBuf);
	}
	return connection;
}

unsigned int CClientSessionManager::next_sessionid()
{
	boost::mutex::scoped_lock lock(sessionid_mutex_);
	next_sessionid_++;
	if(next_sessionid_ == 0)
		next_sessionid_ = 1;
	return next_sessionid_;
}

//上报用户登录信息
void CClientSessionManager::post_user_login(unsigned int userid, byte nmobile, unsigned int nlogintime)
{
	std::set<CTcpClient_ptr> nusermgr_set;
	CGlobalSetting::app_->svr_session_manager_->get_usermgr_svr(nusermgr_set);
	if (nusermgr_set.empty())
	{
		LOG_PRINT(log_warning, "post_user_login() begin userid %d,but nusermgr_set is empty.", userid);
		return;
	}

	std::set<CTcpClient_ptr>::iterator iter = nusermgr_set.begin();
	for (; iter != nusermgr_set.end(); ++iter)
	{
		CTcpClient_ptr usermgr_ptr = *iter;
		if (usermgr_ptr && usermgr_ptr->is_connected())
		{
			unsigned int usermgr_conn = usermgr_ptr->getconn_ssn();

			char szBuf[128] = {0};
			COM_MSG_HEADER * pHead = (COM_MSG_HEADER *)szBuf;
			pHead->version = MDM_Version_Value;
			pHead->checkcode = 0;
			pHead->maincmd = MDM_Vchat_Usermgr;
			pHead->subcmd = Sub_Vchat_LogonNot;

			//user number
			byte * nusernum = (byte *)(pHead->content);
			*nusernum = 1;

			CMDLogonClientInf_t * logoninf = (CMDLogonClientInf_t *)(pHead->content+ sizeof(byte));
			logoninf->m_userid = userid;
			logoninf->m_bmobile = nmobile;
			logoninf->m_logontime = nlogintime;

			int nMsgLen = sizeof(COM_MSG_HEADER) + sizeof(CMDLogonClientInf_t) + sizeof(byte);
			pHead->length = nMsgLen;

			SL_ByteBuffer buff;
			buff.write(szBuf, nMsgLen);

			usermgr_ptr->write_message(buff);
			LOG_PRINT(log_info, "post_user_login:userid %d,nmobile:%d,nlogintime:%u,usermgr_conn:%u.", userid, nmobile, nlogintime, usermgr_conn);
		}
	}

	return;
}

//批量上报用户登录信息
void CClientSessionManager::post_user_login_bat(std::vector<CMDLogonClientInf_t> &vecClientInf, CTcpClient_ptr connptr)
{
	if (vecClientInf.size() == 0 || vecClientInf.size() > 200)
		return;

	int npostnum = vecClientInf.size();

	char szBuf[10240] = {0};
	COM_MSG_HEADER * pHead = (COM_MSG_HEADER *)szBuf;
	pHead->version = MDM_Version_Value;
	pHead->checkcode = 0;
	pHead->maincmd = MDM_Vchat_Usermgr;
	pHead->subcmd = Sub_Vchat_LogonNot;

	pHead->length = sizeof(COM_MSG_HEADER) + sizeof(byte) + sizeof(CMDLogonClientInf_t) * npostnum ;

	//数量
	byte * nusernum = (byte *)(pHead->content);
	*nusernum = npostnum;

	for (unsigned int i = 0; i < vecClientInf.size(); i++)
	{
		CMDLogonClientInf_t & cClientInf = vecClientInf[i];
		CMDLogonClientInf_t * logoninf = (CMDLogonClientInf_t *)(pHead->content+ sizeof(byte) + i * sizeof(CMDLogonClientInf_t));
		logoninf->m_userid = cClientInf.m_userid;
		logoninf->m_bmobile = cClientInf.m_bmobile;
		logoninf->m_logontime =  cClientInf.m_logontime;
	}

	SL_ByteBuffer buff;
	buff.write(szBuf, pHead->length);

	if (connptr && connptr->is_connected())
	{
		connptr->write_message(buff);
	}
	
	return;
}

void CClientSessionManager::getallconnptr(std::vector<connection_ptr> &vecconn)
{
	boost::mutex::scoped_lock lock(client_session_mutex_);
	std::map<unsigned int, connection_ptr >::iterator iter = session_map_.begin();
	for(; iter != session_map_.end(); iter++)
		vecconn.push_back(iter->second);
}

void CClientSessionManager::post_all_user_login()
{
	std::set<CTcpClient_ptr> nusermgr_set;
	CGlobalSetting::app_->svr_session_manager_->get_usermgr_svr(nusermgr_set);
	if (nusermgr_set.empty())
	{
		LOG_PRINT(log_warning, "post_all_user_login(),but nusermgr_set is empty.");
		return;
	}

	std::set<CTcpClient_ptr>::iterator iter = nusermgr_set.begin();
	for (; iter != nusermgr_set.end(); ++iter)
	{
		CTcpClient_ptr usermgr_ptr = *iter;
		if (usermgr_ptr && usermgr_ptr->is_connected())
		{
			unsigned int usermgr_conn = usermgr_ptr->getconn_ssn();
			
			//先取出所有需要发送的用户连接
			std::vector<connection_ptr> vecconn;
			getallconnptr(vecconn);

			int count = 0;
			std::vector<CMDLogonClientInf_t> vecpostclient;

			int nbatnum = 160;
			for (int i = 0; i < vecconn.size(); i++)
			{
				connection_ptr connptr = vecconn[i];
				if (!connptr)
				{
					continue;
				}

				unsigned int userid = connptr->getuserid();

				CMDLogonClientInf_t cClientInf;
				cClientInf.m_userid = userid;
				cClientInf.m_bmobile =  connptr->getmobile();
				cClientInf.m_logontime =  connptr->getlastlogintime();

				//判断用户是否成功登录
				if (cClientInf.m_logontime == 0)
					continue;

				++count;
				if (i % nbatnum != 0 || i == 0)
				{
					vecpostclient.push_back(cClientInf);
				}
				else
				{
					if (vecpostclient.size() > 0)
					{
						post_user_login_bat(vecpostclient, usermgr_ptr);
						vecpostclient.clear();
					}
					vecpostclient.push_back(cClientInf);
				}
			}

			if (vecpostclient.size() > 0)
			{
				post_user_login_bat(vecpostclient, usermgr_ptr);
			}

			LOG_PRINT(log_info, "post_all_user_login end.size:%d.usermgr_conn:%u.", count, usermgr_conn);
		}
	}

	return;
}

void CClientSessionManager::kickout_user_not(CMDLogonClientInf_t * cCientInf)
{
    LOG_PRINT(log_debug, " CClientSessionManager::kickout_user_not() userid %d begin", cCientInf->m_userid);
	connection_ptr connptr = this->find_user_conn(cCientInf->m_userid, cCientInf->m_bmobile, cCientInf->m_logontime);
	if (connptr == 0)
	{
		LOG_PRINT(log_warning, "kickout_user_not() find_user_conn userid = %d m_bmobile %d m_logontime %d err", 
			  cCientInf->m_userid, cCientInf->m_bmobile, cCientInf->m_logontime);
		return;
	}

	char szBuf[128];
	COM_MSG_HEADER* pHead = (COM_MSG_HEADER *)szBuf;
	pHead->version = MDM_Version_Value;
	pHead->checkcode = 0;
	pHead->maincmd = MDM_Vchat_Login;
	pHead->subcmd = Sub_Vchat_ClientExistNot;

	CMDClientExistNot_t* logoninf = (CMDClientExistNot_t*)(pHead->content);
	logoninf->userid = connptr->getuserid();
	logoninf->m_ntype = 0;

	int nMsgLen = sizeof(COM_MSG_HEADER) + sizeof(CMDClientExistNot_t);
	pHead->length = nMsgLen;

	SL_ByteBuffer buff;
	buff.write(szBuf, nMsgLen);

	connptr->write_message(buff);
    LOG_PRINT(log_info, "kickout_user_not() userid %d end", cCientInf->m_userid);
   
	return;
}

//通知客户端退出系统
void CClientSessionManager::noticelogout(unsigned int userid, byte nmobile, unsigned int nlogintime)
{
	if (userid == 0)
		return;

	std::set<CTcpClient_ptr> nusermgr_set;
	CGlobalSetting::app_->svr_session_manager_->get_usermgr_svr(nusermgr_set);
	if (nusermgr_set.empty())
	{
		LOG_PRINT(log_warning, "noticelogout userid:%d,but nusermgr_set is empty.", userid);
		return;
	}

	std::set<CTcpClient_ptr>::iterator iter = nusermgr_set.begin();
	for (; iter != nusermgr_set.end(); ++iter)
	{
		CTcpClient_ptr usermgr_ptr = *iter;
		if (usermgr_ptr && usermgr_ptr->is_connected())
		{
			unsigned int usermgr_conn = usermgr_ptr->getconn_ssn();

			char szBuf[128] = {0};
			COM_MSG_HEADER * pHead = (COM_MSG_HEADER *)szBuf;
			pHead->version = MDM_Version_Value;
			pHead->checkcode = 0;
			pHead->maincmd = MDM_Vchat_Usermgr;
			pHead->subcmd = Sub_Vchat_LogoutNot;

			CMDLogonClientInf_t * clientInf = (CMDLogonClientInf_t*)(pHead->content);
			clientInf->m_userid = userid;
			clientInf->m_bmobile = nmobile;
			clientInf->m_logontime = nlogintime;

			int nMsgLen = sizeof(COM_MSG_HEADER) + sizeof(CMDLogonClientInf_t); 
			pHead->length = nMsgLen;

			SL_ByteBuffer buff;
			buff.write(szBuf, nMsgLen);
			usermgr_ptr->write_message(buff);
			LOG_PRINT(log_info, "post_user_logout:userid %d,nmobile:%d,nlogintime:%u,usermgr_conn:%u.", userid, nmobile, nlogintime, usermgr_conn);
		}
	}

	return;
}

void CClientSessionManager::broadcast_all_client(byte termtype, SL_ByteBuffer & buff)
{
    boost::mutex::scoped_lock lock(client_session_mutex_);

    int count = 0;
    std::map<unsigned int, connection_ptr >::iterator iter = session_map_.begin();
    for (; iter != session_map_.end(); ++iter)
    {
        if (iter->second.get())
        {
            if (e_Notice_AllType == termtype || termtype == iter->second.get()->getmobile())
            {
                iter->second.get()->write_message(buff.data(), buff.data_size());
                ++count;
            }
        }
    }

	LOG_PRINT(log_info, "[Broadcast all client]result has sent nmobile:%u,users count:%u.", termtype, count);
}

void CClientSessionManager::broadcast_room_all_connects(unsigned int roomid, unsigned int own_id, SL_ByteBuffer & buff)
{
	//get set of user connect id.
	std::set<unsigned int> user_conn_set;
	CGlobalSetting::app_->room_mgr_->get_user_connids(roomid, user_conn_set);

	if (user_conn_set.empty())
	{
		return;
	}

	int count = 0;
	//get connection_ptr to send msg
	std::set<unsigned int>::iterator iter_set = user_conn_set.begin();
	for (; iter_set != user_conn_set.end(); ++iter_set)
	{
		unsigned int connect_id = *iter_set;

		if (connect_id == own_id)
		{
			continue;
		}

		boost::mutex::scoped_lock lock(client_session_mutex_);

		std::map<unsigned int, connection_ptr >::iterator iter = session_map_.find(connect_id);
		if(iter != session_map_.end())
		{
			if (iter->second.get())
			{
				iter->second.get()->write_message(buff.data(), buff.data_size());
				++count;
			}
		}
	}

	LOG_PRINT(log_info, "[broadcast_room_all_connets]result has sent roomid:%u,own_connid:%u,users connect count:%u.", roomid, own_id, count);
}

void CClientSessionManager::broadcast_all_room_all_connects(unsigned int own_id, SL_ByteBuffer & buff)
{
	//get set of user connect id.
	std::set<unsigned int> user_conn_set;
	CGlobalSetting::app_->room_mgr_->get_all_user_connids(user_conn_set);
	if (user_conn_set.empty())
	{
		return;
	}
	
	int count = 0;
	//get connection_ptr to send msg
	std::set<unsigned int>::iterator iter_set = user_conn_set.begin();
	for (; iter_set != user_conn_set.end(); ++iter_set)
	{
		unsigned int connect_id = *iter_set;

		if (connect_id == own_id)
		{
			continue;
		}

		boost::mutex::scoped_lock lock(client_session_mutex_);

		std::map<unsigned int, connection_ptr >::iterator iter = session_map_.find(connect_id);
		if(iter != session_map_.end())
		{
			if (iter->second.get())
			{
				iter->second.get()->write_message(buff.data(), buff.data_size());
				++count;
			}
		}
	}

	LOG_PRINT(log_info, "[broadcast_all_room_all_connets]result has sent own_connid:%u,users connect count:%u.", own_id, count);
}

void CClientSessionManager::broadcast_user_all_connects(unsigned int userid, SL_ByteBuffer & buff)
{
	std::set<unsigned int> user_conn_set;

	{
		boost::mutex::scoped_lock lock(client_session_mutex_);
		std::map<unsigned int, std::set<unsigned int> >::iterator iter_map = m_user_connid_map.find(userid);
		if (iter_map != m_user_connid_map.end())
		{
			user_conn_set.insert(iter_map->second.begin(), iter_map->second.end());
		}
	}

	if (user_conn_set.empty())
	{
		return;
	}

	int count = 0;

	std::set<unsigned int>::iterator iter_set = user_conn_set.begin();
	for (; iter_set != user_conn_set.end(); ++iter_set)
	{
		unsigned int connect_id = *iter_set;

		boost::mutex::scoped_lock lock(client_session_mutex_);

		std::map<unsigned int, connection_ptr >::iterator iter = session_map_.find(connect_id);
		if(iter != session_map_.end())
		{
			if (iter->second.get())
			{
				//LOG_PRINT(log_debug, "[broadcast_user_all_connects]client:%s:%u.", iter->second.get()->remote_ip().c_str(), iter->second.get()->remote_port());
				iter->second.get()->write_message(buff.data(), buff.data_size());
				++count;
			}
		}
	}

	LOG_PRINT(log_info, "[broadcast_user_all_connects]result has sent userid:%u,connect count:%u.", userid, count);
}

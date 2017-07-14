
#include "tcp_client.hpp"
#include <iostream>
#include <boost/thread/thread.hpp>
#include <time.h>
#include <assert.h>
#include "CLogThread.h"
#include "GlobalSetting.h"
#include "message_comm.h"
#include "message_vchat.h"
#include "cmd_vchat.h"
#include "GlobalSetting.h"

CTcpClient::CTcpClient(boost::asio::io_service& io_service)
:io_service_(io_service),
recv_buffer_remainlen_(0),
socket_(io_service),
deadline_(io_service),
last_activetime_(0),
begin_connecttime_(0),
last_alarmnotify_time_(0),
connect_status_(en_connect_status_disconnected),
m_svr_type(0),
m_port(0)
{
	m_ipaddr = "";
	m_setconnid.clear();
	m_ngateid = 0;
	disconnect_alarm_time = time(NULL);
}

void CTcpClient::start()
{
	deadline_.expires_from_now(boost::posix_time::seconds(1));
	deadline_.async_wait(boost::bind(&CTcpClient::handle_timeout, shared_from_this(),
		boost::asio::placeholders::error));
}

void CTcpClient::stop()
{
	boost::system::error_code e;
	deadline_.cancel(e);
}

void CTcpClient::start_connect(const char * szip, int port)
{
	if(connect_status_ != en_connect_status_disconnected)
	{
		return;
	}

	boost::asio::ip::address addr = boost::asio::ip::address_v4::from_string(szip);
	endpoint_.address(addr);
	endpoint_.port(port);

	m_ipaddr = std::string(szip);
	m_port = port;

	LOG_PRINT(log_info, "CTcpClient::connect() Begin connect server[%s:%d]...", m_ipaddr.c_str(), m_port);

	recv_buffer_remainlen_ = 0;
	socket_.async_connect(endpoint_,
		boost::bind(&CTcpClient::handle_connect, shared_from_this(), 
		boost::asio::placeholders::error));
	connect_status_ = en_connect_status_connecting;
	begin_connecttime_ = time(0);
}

void CTcpClient::connect()
{
	if(connect_status_ != en_connect_status_disconnected)
	{
		return;
	}

	if(endpoint_.port() == 0) 
	{
		LOG_PRINT(log_error, "CTcpClient::connect() connect endpoint not set!");
		return;
	}

	LOG_PRINT(log_info, "CTcpClient::connect() Begin connect server[%s:%d]...", m_ipaddr.c_str(), m_port);

	recv_buffer_remainlen_ = 0;
	socket_.async_connect(endpoint_,
		boost::bind(&CTcpClient::handle_connect, shared_from_this(), 
		boost::asio::placeholders::error));
	connect_status_ = en_connect_status_connecting;
	begin_connecttime_ = time(0);
}

void CTcpClient::close()
{
	io_service_.post(boost::bind(&CTcpClient::do_close, shared_from_this()));
}

void CTcpClient::write_message(SL_ByteBuffer& message, bool bforced/*=false*/)
{
	if(connect_status_ == en_connect_status_connected || bforced)
	{
		io_service_.post(boost::bind(&CTcpClient::send_message, shared_from_this(), message, bforced));
	}
}

void CTcpClient::write_message(char* pdata, int datalen, bool bforced/*=false*/)
{
	if(connect_status_ == en_connect_status_connected || bforced)
	{
		SL_ByteBuffer buffer(datalen);
		buffer.write(pdata, datalen);
		io_service_.post(boost::bind(&CTcpClient::send_message, shared_from_this(), buffer, bforced));
	}
}

void CTcpClient::send_message(SL_ByteBuffer& message, bool bforced)
{
	if(connect_status_ == en_connect_status_connected || bforced)
	{
		time_t t = time(NULL);
		if(send_messages_.size() >= CGlobalSetting::alarm_queuesize_ && (t - last_alarmnotify_time_) > CGlobalSetting::alarmnotify_interval_)
		{
			//alarm notify
            char content[512] = {0};
			snprintf(content, 512, "[port:%d]send_messages_.size()==%d!", CGlobalSetting::listen_port_, send_messages_.size());
			CGlobalSetting::alarmnotify_->sendAlarmNoty(e_all_notitype, e_msgqueue, "webgate", "webgate alarm", "Yunwei,Usermgr", content);
			last_alarmnotify_time_ = t;
			LOG_PRINT(log_warning, "[message_size]server message_size:%u,server:%s:%u.", send_messages_.size(), m_ipaddr.c_str(), m_port);
		}

		boost::mutex::scoped_lock lock(send_messages_mutex_);
		bool write_in_progress =!send_messages_.empty();
		send_messages_.push_back(message);
		if(!write_in_progress)
		{
			SL_ByteBuffer* pslbuf=&(send_messages_.front());
			boost::asio::async_write(socket_,
				boost::asio::buffer(pslbuf->buffer(), pslbuf->data_end()),
				boost::bind(&CTcpClient::handle_write, shared_from_this(),
				boost::asio::placeholders::error,
				boost::asio::placeholders::bytes_transferred));
		}
	}
}

void CTcpClient::send_keeplive_command()
{
	SL_ByteBuffer outbuf(512);
	COM_MSG_HEADER * pingReq = (COM_MSG_HEADER*)outbuf.buffer();
	pingReq->version = MDM_Version_Value;
	pingReq->checkcode = 0;
	pingReq->maincmd = MDM_Vchat_Room;
	pingReq->subcmd = Sub_Vchat_ClientPing;

	CMDClientPing_t * pReq = (CMDClientPing_t *)pingReq->content;
	memset(pReq, 0, sizeof(CMDClientPing_t));
	pingReq->length = sizeof(COM_MSG_HEADER) + sizeof(CMDClientPing_t);

	outbuf.data_end(pingReq->length);
	send_message(outbuf, false);
}

void CTcpClient::send_hello_command()
{
	SL_ByteBuffer outbuf(512);
	COM_MSG_HEADER * pmsgheader = (COM_MSG_HEADER *)outbuf.buffer();
	pmsgheader->version = MDM_Version_Value;
	pmsgheader->checkcode = 0;
	pmsgheader->maincmd = MDM_Vchat_Login;
	pmsgheader->subcmd = Sub_Vchat_ClientHello;

	CMDClientHello_t * preq = (CMDClientHello_t *)(pmsgheader->content);
	preq->param1 = 12;
	preq->param2 = 8;
	preq->param3 = 7;
	preq->param4 = 1;
	pmsgheader->length = sizeof(COM_MSG_HEADER) + sizeof(CMDClientHello_t);
	outbuf.data_end(pmsgheader->length);
	send_message(outbuf, true);
	LOG_PRINT(log_info, "send Client-Hello MSG to Server:%s:%u.", m_ipaddr.c_str(), m_port);
}

void CTcpClient::handle_connect(const boost::system::error_code & e)
{
	if(!e)
	{
		LOG_PRINT(log_info, "Connect server OK! clear old queue-size(%d).server:%s:%u.", send_messages_.size(), m_ipaddr.c_str(), m_port);
		clear_conn_num();

		last_queue_size_time_ = time(0);

		boost::asio::ip::tcp::no_delay option(true);
		socket_.set_option(option);

		//1.send hello message
		send_hello_command();

		//2.send ping message
		send_keeplive_command();

		last_activetime_ = time(NULL);

		connect_status_ = en_connect_status_connected;

		CGlobalSetting::app_->svr_session_manager_->add_svr_node(m_svr_type, conn_ssn_);

		//start recv data...
		char * recv_buffer = recv_buffer_ + recv_buffer_remainlen_;
		std::size_t rev_buffer_size = en_msgbuffersize - recv_buffer_remainlen_;

		socket_.async_read_some(boost::asio::buffer((void*)recv_buffer, rev_buffer_size),
			boost::bind(&CTcpClient::handle_read, shared_from_this(),
			boost::asio::placeholders::error,
			boost::asio::placeholders::bytes_transferred));
	}
	else
	{
		LOG_PRINT(log_error, "CTcpClient::handle_connect() error:%s,server:%s:%u.", boost::system::system_error(e).what(),\
			m_ipaddr.c_str(), m_port);
	}
}

void CTcpClient::handle_timeout(const boost::system::error_code & e)
{
	if(!e)
	{
		time_t now = time(NULL);
		if(connect_status_ == en_connect_status_connecting && now - begin_connecttime_ > 5)
		{
			LOG_PRINT(log_warning, "Connect server time-out, then do_close() and try connect.server:%s:%u.", m_ipaddr.c_str(), m_port);
			do_close();
			connect();
		}
		else if(connect_status_ == en_connect_status_connected && now - last_activetime_ > 15)
		{
			send_keeplive_command();
			last_activetime_ = now;
		}
		else if(connect_status_ == en_connect_status_disconnected)
		{
			LOG_PRINT(log_info, "Server is disconnected, then try connect.server:%s:%u.", m_ipaddr.c_str(), m_port);
			connect();
		}

		if (connect_status_ == en_connect_status_connected && now - last_queue_size_time_ >= 120)
		{
			last_queue_size_time_ = now;
			unsigned int message_size = send_messages_.size();
			if (message_size)
			{
				LOG_PRINT(log_info, "[message_size]server message_size:%u.server:%s:%d.", message_size, m_ipaddr.c_str(), m_port);
			}
		}

		deadline_.expires_from_now(boost::posix_time::seconds(1));
		deadline_.async_wait(boost::bind(&CTcpClient::handle_timeout, shared_from_this(),
			boost::asio::placeholders::error));
	}
	else
	{
		LOG_PRINT(log_error, "CTcpClient::handle_timeout() error:%s,server:%s:%u.", boost::system::system_error(e).what(), \
			m_ipaddr.c_str(), m_port);
	}
}

void CTcpClient::handle_read(const boost::system::error_code& e,
							 std::size_t bytes_transferred)
{
	if(!e)
	{
		if(bytes_transferred == 0)
		{
			LOG_PRINT(log_warning, "Recv data-len from server is 0,close connect!server:%s:%u.", m_ipaddr.c_str(), m_port);
			do_close();
			return;
		}
		recv_buffer_remainlen_ += bytes_transferred;
		if(parse_message() == -1)
		{
			LOG_PRINT(log_warning, "Parse message from server failed!close connect!server:%s:%u", m_ipaddr.c_str(), m_port);
			do_close();
			return;
		}
		if(connect_status_ == en_connect_status_connected)
		{
			//start recv data...
			char * recv_buffer = recv_buffer_ + recv_buffer_remainlen_;
			std::size_t rev_buffer_size = en_msgbuffersize - recv_buffer_remainlen_;

			socket_.async_read_some(boost::asio::buffer((void*)recv_buffer, rev_buffer_size),
				boost::bind(&CTcpClient::handle_read, shared_from_this(),
				boost::asio::placeholders::error,
				boost::asio::placeholders::bytes_transferred));
		}
	}
	else
	{
		LOG_PRINT(log_error, "Handle_read() from server error:%s,server:%s:%u.", 
			boost::system::system_error(e).what(), m_ipaddr.c_str(), m_port);
		if(e != boost::asio::error::operation_aborted) 
			do_close();
	}
}


void CTcpClient::handle_write(const boost::system::error_code& e, std::size_t bytes_transferred)
{
	if(!e)
	{
		boost::mutex::scoped_lock lock(send_messages_mutex_);
		send_messages_.pop_front();
		if(!send_messages_.empty() && connect_status_ == en_connect_status_connected)
		{
			SL_ByteBuffer* pslbuf =&(send_messages_.front());
			boost::asio::async_write(socket_,
				boost::asio::buffer(pslbuf->buffer(), pslbuf->data_end()),
				boost::bind(&CTcpClient::handle_write, shared_from_this(),
				boost::asio::placeholders::error,
				boost::asio::placeholders::bytes_transferred));
		}
		else if(connect_status_ != en_connect_status_connected)
		{
			LOG_PRINT(log_warning, "handle_write() Server is not connected,send-queue size(%d).server:%s:%u.", \
				send_messages_.size(), m_ipaddr.c_str(), m_port);
		}
	}
	else
	{
		LOG_PRINT(log_error, "handle_write() to server error:%s,server:%s:%u.", 
			boost::system::system_error(e).what(), m_ipaddr.c_str(), m_port);
		if(e != boost::asio::error::operation_aborted)
			do_close();
	}
}

int CTcpClient::parse_message()
{
	char * p = recv_buffer_;
	while(recv_buffer_remainlen_ > 4)
	{
		int msglen = *((int*)p);
		if(msglen <= 0 || msglen > en_msgbuffersize)
		{
			recv_buffer_remainlen_ = 0;
			return -1;
		}
		else if(recv_buffer_remainlen_ < msglen)
		{
			break;
		}
		else 
		{
			if(handle_message(p, msglen) == -1)
			{
				recv_buffer_remainlen_ = 0;
				return -1;
			}
			recv_buffer_remainlen_ -= msglen;
			p += msglen;
		}
	}
	if(recv_buffer_remainlen_ >= en_msgmaxsize)
	{
		recv_buffer_remainlen_ = 0;
		return -1;
	}
	if(p != recv_buffer_ && recv_buffer_remainlen_ > 0)
	{
		memmove(recv_buffer_, p, recv_buffer_remainlen_);
	}
	return 0;
}

int CTcpClient::handle_message(const char * msg, int len)
{
    if (msg == NULL || len <  SIZE_IVM_HEADER + SIZE_IVM_CLIENTGATE)
    {
		LOG_PRINT(log_error, "handle_message() from server err!server:%s:%u.", m_ipaddr.c_str(), m_port);
        return 0;
    }

	DEF_IVM_HEADER(in_msg, msg);
	DEF_IVM_CLIENTGATE(pGateMask, msg);
	char * pData = (char *)DEF_IVM_DATA(msg);
	int nMsgLen2 = in_msg->length - SIZE_IVM_CLIENTGATE;
	int nDataLen2 = in_msg->length - SIZE_IVM_HEADER - SIZE_IVM_CLIENTGATE;
	
    if(in_msg->length != len) 
    {
		LOG_PRINT(log_warning,  "handle_message() from server in_msg length error!server:%s:%u.", m_ipaddr.c_str(), m_port);
		return 0;
	}

	if (CAST_USER_ALL_DEV == pGateMask->param3 && CAST_USER_ALL_DEV == pGateMask->param4 && pGateMask->param5)
	{
		handle_cast_user_connects_msg(msg, len);
		return 0;
	}

	//转发消息
	unsigned int pConnId = pGateMask->param2;
	//应该通过 再次 查找 一下该 conn 是否存在
	//直接使用变量进行 判断的原因 是防止 部分野指针 直接调用函数 引起的 奔溃
	connection_ptr pConn_This = CGlobalSetting::app_->client_session_manager_->find_client_map(pConnId);
	if(!pConn_This)
	{
		//当收到logonsvr的响应后，客户端已经关闭了
		LOG_PRINT(log_warning, "client fd is closed,client connid:%d,maincmd:%u,subcmd:%u.server:%s:%u.", \
			pConnId, in_msg->maincmd, in_msg->subcmd, m_ipaddr.c_str(), m_port);
		return 0;
	}
	else if(pConn_This->connection_id() != pConnId)
	{
		LOG_PRINT(log_warning, "handle_message err! client session_id not equal![old connid:%d, new connid:%d]",pConnId, pConn_This->connection_id());
	}
	else if(pConn_This->session_status() == CClientConnection::en_session_status_connected)  //连接状态
	{			
		//transfer msg to client
        SL_ByteBuffer buff(nMsgLen2);
        COM_MSG_HEADER * pOutMsg = (COM_MSG_HEADER *)buff.buffer();
        memcpy(pOutMsg, in_msg, SIZE_IVM_HEADER);
        memcpy(pOutMsg->content, pData, nDataLen2);

        pOutMsg->length = nMsgLen2;
        buff.data_end(pOutMsg->length);
        pConn_This->write_message(buff);
	}

	return 0;
}

/*
void CTcpClient::post_user_login(uint16 subcmd, char * respData, CClientConnection * pConn)
{
    unsigned int userid = 0;

    if (Sub_Vchat_logonSuccess2 == subcmd)
    {
        CMDUserLogonSuccess2_t * logonRet = (CMDUserLogonSuccess2_t *)respData;
        userid = logonRet->userid;
    }

    if (userid && pConn != NULL)
    {
        //因为客户端老版本的登录链接是不发ping包，所以connection里的userid是0，需要把登录成功的userid设置回connection里
        pConn->setuserid(userid);
        pConn->setlastlogintime();
        byte nmobile = pConn->getmobile();
        unsigned int nlogintime = pConn->getlastlogintime();
        unsigned int idconn = pConn->connection_id();
        CGlobalSetting::app_->client_session_manager_->setuserconn(userid, nmobile, nlogintime, idconn);
        //上报用户管理服务器信息
        CGlobalSetting::app_->client_session_manager_->post_user_login(userid, nmobile, nlogintime);
    }
}
*/

void CTcpClient::handle_cast_user_connects_msg(const char * msg, int len)
{
	if (!msg || !len)
	{
		return;
	}

	DEF_IVM_HEADER(in_msg, msg);
	DEF_IVM_CLIENTGATE(pGateMask, msg);
	char * pData = (char *)DEF_IVM_DATA(msg);
	int nMsgLen2 = in_msg->length - SIZE_IVM_CLIENTGATE;
	int nDataLen2 = in_msg->length - SIZE_IVM_HEADER - SIZE_IVM_CLIENTGATE;
	unsigned int maincmd = in_msg->maincmd;
	unsigned int subcmd = in_msg->subcmd;
	unsigned int userid = pGateMask->param5;
	
	SL_ByteBuffer buff(nMsgLen2);
	COM_MSG_HEADER * pOutMsg = (COM_MSG_HEADER *)buff.buffer();
	memcpy(pOutMsg, in_msg, SIZE_IVM_HEADER);
	memcpy(pOutMsg->content, pData, nDataLen2);
	pOutMsg->length = nMsgLen2;
	buff.data_end(pOutMsg->length);
    if (subcmd == Sub_Vchat_logonTokenNotify) 
	{
        CMDSessionTokenResp_t * pResp = (CMDSessionTokenResp_t *)(pOutMsg->content);	    
		LOG_PRINT(log_debug, "Broadcast user token:userid:%u,subcmd:%u,token:%s,validtime:%s from server:%s:%u,", userid, subcmd, pResp->sessiontoken, pResp->validtime, m_ipaddr.c_str(), m_port);
    }
	else
	{
		LOG_PRINT(log_debug, "Broadcast all connects of this user from server:%s:%u,userid:%u,maincmd:%u,subcmd:%u.", m_ipaddr.c_str(), m_port, userid, maincmd, subcmd);
	}
    
	CGlobalSetting::app_->client_session_manager_->broadcast_user_all_connects(userid, buff);
}

//broadcast all clients which connect on one server
void CTcpClient::handle_cast_clients_on_one_svr(const char * msg, int len)
{
	if (!msg || !len)
	{
		return;
	}

	std::set<unsigned int> client_conn_set;
	get_all_connid(client_conn_set);

	if (client_conn_set.empty())
	{
		LOG_PRINT(log_warning, "server:%s:%u has no client connection.", m_ipaddr.c_str(), m_port);
		return;
	}

	DEF_IVM_HEADER(in_msg, msg);
	DEF_IVM_CLIENTGATE(pGateMask, msg);
	char * pData = (char *)DEF_IVM_DATA(msg);
	int nMsgLen2 = in_msg->length - SIZE_IVM_CLIENTGATE;
	int nDataLen2 = in_msg->length - SIZE_IVM_HEADER - SIZE_IVM_CLIENTGATE;
	unsigned int maincmd = in_msg->maincmd;
	unsigned int subcmd = in_msg->subcmd;

	SL_ByteBuffer buff(nMsgLen2);
	COM_MSG_HEADER * pOutMsg = (COM_MSG_HEADER *)buff.buffer();
	memcpy(pOutMsg, in_msg, SIZE_IVM_HEADER);
	memcpy(pOutMsg->content, pData, nDataLen2);
	pOutMsg->length = nMsgLen2;
	buff.data_end(pOutMsg->length);
	LOG_PRINT(log_debug, "[Broadcast all client on one server]client connects which connect on server:%s:%u,maincmd:%u,subcmd:%u.client count:%u.msg len:%u.", \
		m_ipaddr.c_str(), m_port, maincmd, subcmd, client_conn_set.size(), nMsgLen2);
	
	int success_count = 0;
	std::set<unsigned int>::iterator iter = client_conn_set.begin();
	for (; iter != client_conn_set.end(); ++iter)
	{
		if (0 == CGlobalSetting::app_->client_session_manager_->send_msg_to_client_by_connID(*iter, buff))
		{
			++success_count;
		}
	}
	LOG_PRINT(log_info, "[Broadcast all client on one server]result has sent %u client connects which connect on server:%s:%u,maincmd:%u,subcmd:%u.msg len:%u.", \
		success_count, m_ipaddr.c_str(), m_port, maincmd, subcmd, nMsgLen2);
}

void CTcpClient::addconn_id(unsigned int idconn)
{ 
	boost::mutex::scoped_lock lock(add_connd_id_mutex_);
	m_setconnid.insert(idconn);
}

void CTcpClient::delconn_id(unsigned int idconn)
{ 
	boost::mutex::scoped_lock lock(add_connd_id_mutex_);
	m_setconnid.erase(idconn);
}

unsigned int CTcpClient::getconn_num()
{
	boost::mutex::scoped_lock lock(add_connd_id_mutex_);
	return m_setconnid.size();
}

void CTcpClient::clear_conn_num()
{
	boost::mutex::scoped_lock lock(add_connd_id_mutex_);
	if (m_setconnid.size() > 0)
	{
		m_setconnid.clear();
	}
}

void CTcpClient::get_all_connid(std::set<unsigned int> & ret)
{
	ret.clear();
	boost::mutex::scoped_lock lock(add_connd_id_mutex_);
	if (!m_setconnid.empty())
	{
		ret.insert(m_setconnid.begin(), m_setconnid.end());
	}
}

void CTcpClient::setsvr_type(int type)
{
    m_svr_type = type;
	m_svr_name = CGlobalSetting::app_->change_type_to_svrname(m_svr_type);
}

int CTcpClient::getsvr_type()
{
    return m_svr_type;
}

void CTcpClient::do_close()	
{
	socket_.close();
	
	if (is_connected())
	{
		CGlobalSetting::app_->svr_session_manager_->del_svr_node(m_svr_type, conn_ssn_);
	}

	connect_status_ = en_connect_status_disconnected;

	post_close_process();
	
	clear_conn_num();

	LOG_PRINT(log_warning, "[server connid:%u]disconnected with %s:%s:%u", conn_ssn_, m_svr_name.c_str(), m_ipaddr.c_str(), m_port);

	time_t now_t = time(NULL);
	if (now_t - disconnect_alarm_time > 180)
	{
		CGlobalSetting::alarmnotify_->sendAlarmNoty(e_all_notitype, e_network_conn, "webgate", "webgate", "Yunwei,Room,Usermgr", "[port:%u]disconnect with %s:%s:%u",
			CGlobalSetting::listen_port_, m_svr_name.c_str(), m_ipaddr.c_str(), m_port);
		disconnect_alarm_time = now_t;
	}
}

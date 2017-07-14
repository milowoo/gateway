
#include "client_session.hpp"
#include <iostream>
#include <boost/thread.hpp>
#include <boost/bind.hpp>
#include <assert.h>
#include <time.h>

#include "CLogThread.h"
#include "GlobalSetting.h"
#include "clientsession_manager.h"
#include "message_comm.h"
#include "cmd_vchat.h"
#include "message_vchat.h"
#include "sha1.h"
#include "base64.h"
#include "json/json.h"

CClientConnection::CClientConnection(boost::asio::io_service & io_service)
:socket_(io_service),
recv_buffer_remainlen_(0),
connection_id_(0),
deadline_(io_service),
stopped_(false),
last_activetime_(0),
session_status_(en_session_status_unkown),
client_manager_(0),
remote_port_(0)
{
	setuserid(0);
	setroomid(0);
	last_login_time = 0;
	m_nmobile = 0;
	m_exitroom = true;
	m_header_map_.clear();
	m_micindex = -1;
	m_micstate = 0;
}

CClientConnection::~CClientConnection()
{
	setuserid(0);
	setroomid(0);
	m_exitroom = true;
	m_header_map_.clear();
}

boost::asio::ip::tcp::socket & CClientConnection::socket()
{
	return socket_;
}

void CClientConnection::start()
{
	stopped_ = false;
	session_status_ = en_session_status_ready;
	tcp::no_delay option(true);
	socket_.set_option(option);

	char * recv_buffer = recv_buffer_ + recv_buffer_remainlen_;
	std::size_t rev_buffer_size = en_msgbuffersize - recv_buffer_remainlen_;

	socket_.async_read_some(boost::asio::buffer((void *)recv_buffer, rev_buffer_size),
		boost::bind(&CClientConnection::handle_read, shared_from_this(),
		boost::asio::placeholders::error,
		boost::asio::placeholders::bytes_transferred));

	last_activetime_ = time(NULL);
	//create timer to check_live
	deadline_.expires_from_now(boost::posix_time::seconds(en_checkactivetime));
	deadline_.async_wait(boost::bind(&CClientConnection::check_deadline, shared_from_this(),
		boost::asio::placeholders::error));
}

void CClientConnection::write_message(SL_ByteBuffer & slByte)
{
	if(stopped_) return;
	write_message(slByte.data(), slByte.data_size());
}

void CClientConnection::write_message(const char * pdata, int datalen)
{
	if(stopped_) return;

	Json::Value root;
	COM_MSG_HEADER * pOutMsg = (COM_MSG_HEADER *)pdata;
	root["length"] = Json::Value(pOutMsg->length);
	root["version"] = Json::Value(pOutMsg->version);
	root["checkcode"] = Json::Value(pOutMsg->checkcode);
	root["maincmd"] = Json::Value(pOutMsg->maincmd);
	root["subcmd"] = Json::Value(pOutMsg->subcmd);

	if (pOutMsg->length == sizeof(COM_MSG_HEADER))
	{
		root["data"] = Json::Value("");
	}
	else
	{
		unsigned int contentLen = pOutMsg->length - sizeof(COM_MSG_HEADER);
		const char * pBegin = pOutMsg->content;
		const char * pEnd = pOutMsg->content + contentLen;
		Json::Value jdata;
		char sub[128] = {0};
		sprintf(sub, "%u", pOutMsg->subcmd);
		int ret = CGlobalSetting::app_->cmdguide_mgr_->fillJsonParam(std::string(sub), &pBegin, pEnd, jdata);
		if (!ret)
		{
			if (!jdata.isNull())
			{
				root["data"] = jdata;
			}
		}
		else
		{
			root["data"] = Json::Value("");
		}
	}

	Json::FastWriter fast_writer;
	std::string strJRecList = fast_writer.write(root);

	if (Sub_Vchat_ClientPingResp != pOutMsg->subcmd)
	{
		LOG_PRINT(log_debug, "client connid:%u,%s:%u,subcmd:%u,roomid:%u,response json:%s.", \
			connection_id_, remote_ip_.c_str(), remote_port_, pOutMsg->subcmd, m_roomid, strJRecList.c_str());
	}
	
	SL_ByteBuffer buffer(strJRecList.size());
	buffer.write(strJRecList.c_str(), strJRecList.size());
	socket_.get_io_service().post(boost::bind(&CClientConnection::send_message, shared_from_this(), buffer));
}

void CClientConnection::close()
{
	socket_.get_io_service().post(boost::bind(&CClientConnection::do_close, shared_from_this()));
}

void CClientConnection::do_close()
{ 
	//notice usermgrsvr this user logout.
	CGlobalSetting::app_->client_session_manager_->noticelogout(userid, m_nmobile, last_login_time);

	LOG_PRINT(log_info, "do_close() [userid:%u,client connid:%u,%s:%d].", userid, connection_id_, remote_ip_.c_str(), remote_port_);
	if(!stopped_) 
    {
        stopped_ = true;
        socket().close();
    }
}

void CClientConnection::send_message(SL_ByteBuffer & slbuf)
{
	if(stopped_) return;
	boost::mutex::scoped_lock lock(send_messages_mutex_);
	bool write_in_progress = !send_messages_.empty();
	
	unsigned int new_len = calc_new_len(slbuf.data_size());
	//websocket head length max is 10 byte without mask
	SL_ByteBuffer new_buf(new_len);
	format_write_buf(slbuf.buffer(), slbuf.data_end(), new_buf.buffer());
	new_buf.data_end(new_len);

	send_messages_.push_back(new_buf);
	if(!write_in_progress && !stopped_) //first async-write data
	{
		SL_ByteBuffer * pslbuf = &(send_messages_.front());
		boost::asio::async_write(socket_,
			boost::asio::buffer(pslbuf->buffer(), pslbuf->data_end()),
			boost::bind(&CClientConnection::handle_write, shared_from_this(),
			boost::asio::placeholders::error,
			boost::asio::placeholders::bytes_transferred));
	}
}

void CClientConnection::handle_read(const boost::system::error_code & e, std::size_t bytes_transferred)
{
	if(!e && !stopped_) 
	{
		try {
			if(!remote_port_)
			{
				remote_ip_ = socket_.remote_endpoint().address().to_string();
				remote_port_ = socket_.remote_endpoint().port();
			}
		}catch(boost::system::system_error &ec)
		{
			LOG_PRINT(log_error, "handle_read() get remote ip/port error!then close it.[userid:%u,client connid:%u,%s:%d]",
				userid, connection_id_, remote_ip_.c_str(), remote_port_);
			notify_svr_exceptexit();
			do_close();
			return;
		}

		//parse recv_buffer_
		recv_buffer_remainlen_ += bytes_transferred;
		if(parse_message() == -1)
		{
			LOG_PRINT(log_error, "handle_read() Parse message failed! close socket.[userid:%u,client connid:%u,%s:%d]",
				userid, connection_id_, remote_ip_.c_str(), remote_port_);

			notify_svr_clientexit();
			do_close();
		}

		if(!stopped_)
		{
			//continue recv-data
			char * recv_buffer = recv_buffer_ + recv_buffer_remainlen_;
			std::size_t rev_buffer_size = en_msgbuffersize - recv_buffer_remainlen_;
			//continue to recv data.
			socket_.async_read_some(boost::asio::buffer((void*)recv_buffer, rev_buffer_size),
				boost::bind(&CClientConnection::handle_read, shared_from_this(),
				boost::asio::placeholders::error,
				boost::asio::placeholders::bytes_transferred));
		}
	}
	else if(stopped_)
	{
		LOG_PRINT(log_error, "handle_read() client-session is stopped, not continue.[userid:%u,client connid:%u,%s:%d]",
			userid, connection_id_, remote_ip_.c_str(), remote_port_);
	}
	else if(e)
	{
		LOG_PRINT(log_error, "handle_read() error:[%s], sess-status=[%d].[userid:%u,client connid:%u,%s:%d]", 
			boost::system::system_error(e).what(), session_status_, userid, connection_id_, remote_ip_.c_str(), remote_port_);

		if(e != boost::asio::error::operation_aborted)
		{
			if (e == boost::asio::error::eof)
			{
				notify_svr_clientexit();
			}else
			{
				notify_svr_exceptexit();
			}
			
			do_close();
		}
	}
}

void CClientConnection::handle_write(const boost::system::error_code& e, std::size_t bytes_transferred)
{
	if(!e)
	{
		//continue send message.
		boost::mutex::scoped_lock lock(send_messages_mutex_);
		send_messages_.pop_front();
		if(!send_messages_.empty() && !stopped_)
		{
			//wait all message send-out
			SL_ByteBuffer * pslbuf = &(send_messages_.front());
			boost::asio::async_write(socket_,
				boost::asio::buffer(pslbuf->buffer(), pslbuf->data_end()),
				boost::bind(&CClientConnection::handle_write, shared_from_this(),
				boost::asio::placeholders::error,
				boost::asio::placeholders::bytes_transferred));
		}
		else if(stopped_)
		{
			LOG_PRINT(log_error, "handle_write():client-session is stopped,not continue.[userid:%u,client connid:%u,%s:%d]",
				userid, connection_id_, remote_ip_.c_str(), remote_port_);
		}
	}
	else
	{
		LOG_PRINT(log_error, "handle_write() error:[%s].[userid:%u,client connid:%u,%s:%d]", 
			boost::system::system_error(e).what(), userid, connection_id_, remote_ip_.c_str(), remote_port_);

		//close socket while write error.
		if(e != boost::asio::error::operation_aborted)
		{ 
			notify_svr_exceptexit();
			do_close();
		}	
	}
}

unsigned int CClientConnection::calc_new_len(unsigned int in_len)
{
	if (in_len < 126)
	{
		return in_len + 2;

	}else if (in_len < 0xFFFF) 
	{
		return in_len + 4;
	}
	else
	{
		return in_len + 10;
	}
}

void CClientConnection::format_write_buf(char * in_data, unsigned int in_len, char * output)
{
	char * data = output;
	if (in_len < 126)
	{
		memset(data, 0, in_len + 2);
		data[0] = 0x81;
		data[1] = in_len;
		memcpy(data + 2, in_data, in_len);

	}else if (in_len < 0xFFFF) 
	{ 
		memset(data, 0, in_len + 4); 
		data[0] = 0x81; 
		data[1] = 126; 
		data[2] = (in_len >> 8 & 0xFF);
		data[3] = (in_len & 0xFF); 
		memcpy(data + 4, in_data, in_len);
	}
	else
	{
		memset(data, 0, in_len + 10);
		data[0] = 0x81;
		data[1] = 127;
		data[2] = (in_len >> 56 & 0xFF); //7*8
		data[3] = (in_len >> 48 & 0xFF); //6*8
		data[4] = (in_len >> 40 & 0xFF); //5*8
		data[5] = (in_len >> 32 & 0xFF); //4*8
		data[6] = (in_len >> 24 & 0xFF); //3*8
		data[7] = (in_len >> 16 & 0xFF); //2*8
		data[8] = (in_len >>  8 & 0xFF); //1*8
		data[9] = (in_len       & 0xFF);
		memcpy(data + 10, in_data, in_len);
	}
}

int CClientConnection::fetch_http_info()
{
	std::istringstream s(recv_buffer_);
	std::string request;

	std::getline(s, request);
	if (request[request.size() - 1] == '\r') 
	{
		request.erase(request.end() - 1);
	}
	else 
	{
		return -1;
	}

	std::string header;
	std::string::size_type end;

	while (std::getline(s, header) && header != "\r") 
	{
		if (header[header.size() - 1] != '\r') 
		{
			continue; //end
		}
		else 
		{
			header.erase(header.end() - 1);	//remove last char
		}

		end = header.find(": ",0);
		if (end != std::string::npos) 
		{
			std::string key = header.substr(0, end);
			std::string value = header.substr(end + 2);
			m_header_map_[key] = value;
		}
	}

	return 0;
}

std::string CClientConnection::parse_str()
{
	std::string message = "";
	message += "HTTP/1.1 101 Switching Protocols\r\n";
	message += "Connection: upgrade\r\n";
	message += "Sec-WebSocket-Accept: ";

	std::string server_key = m_header_map_["Sec-WebSocket-Key"];
	server_key += MAGIC_KEY;

	SHA1 sha;
	unsigned int message_digest[5];
	sha.Reset();
	sha << server_key.c_str();

	sha.Result(message_digest);
	for (int i = 0; i < 5; ++i) 
	{
		message_digest[i] = htonl(message_digest[i]);
	}

	server_key = base64_encode(reinterpret_cast<const unsigned char*>(message_digest), 20);
	server_key += "\r\n";

	message += server_key;
	message += "Upgrade: websocket\r\n\r\n";

	return message;
}

int CClientConnection::handshark()
{
	if (fetch_http_info())
	{
		LOG_PRINT(log_error, "fetch_http_info failed.");
		return -1;
	}

	std::string message = parse_str();

	memset(recv_buffer_, 0, sizeof(recv_buffer_));
	recv_buffer_remainlen_ = 0;

	boost::system::error_code ignored_error;
	socket_.write_some(boost::asio::buffer(message), ignored_error);

	session_status_ = en_session_status_connected;

	return 0;
}

int CClientConnection::fetch_fin(char * msg, int & pos)
{
	fin_ = (unsigned char)msg[pos] >> 7;
	return 0;
}

int CClientConnection::fetch_opcode(char * msg, int & pos)
{
	opcode_ = msg[pos] & 0x0f;
	++pos;
	return 0;
}

int CClientConnection::fetch_mask(char * msg, int & pos)
{
	mask_ = (unsigned char)msg[pos] >> 7;
	return 0;
}

int CClientConnection::fetch_masking_key(char * msg, int & pos)
{
	if(mask_ != 1)
		return 0;
	for(int i = 0; i < 4; i++)
		masking_key_[i] = msg[pos + i];
	pos += 4;
	return 0;
}

int CClientConnection::fetch_payload_length(char * msg, int & pos, unsigned long & payload_length_)
{
	payload_length_ = msg[pos] & 0x7f;
	++pos;
	if(payload_length_ == 126)
	{
		uint16_t length = 0;
		memcpy(&length, msg + pos, 2);
		pos += 2;
		payload_length_ = ntohs(length);
	}
	else if(payload_length_ == 127)
	{
		uint64_t length = 0;
		memcpy(&length, msg + pos, 8);
		pos += 8;
		payload_length_ = ntohl(length);
	}
	return 0;
}

int CClientConnection::fetch_payload(char * msg, int & pos, char * payload_, unsigned int payload_length_, unsigned int max_length)
{
	if (payload_length_ > max_length)
	{
		LOG_PRINT(log_error, "payload_length_:%u is larger than max length:%u.", payload_length_, max_length);
		return -1;
	}

	if(mask_ != 1)
	{
		memcpy(payload_, msg + pos, payload_length_);
	}
	else 
	{
		for(unsigned int i = 0; i < payload_length_; ++i)
		{
			int j = i % 4;
			payload_[i] = msg[pos + i] ^ masking_key_[j];
		}
	}
	pos += payload_length_;
	return 0;
}

int CClientConnection::parse_message()
{
	if(en_session_status_ready == session_status_)
	{
		handshark();
		return 0;
	}

	char * msg = recv_buffer_;

	while(recv_buffer_remainlen_ > 4)
	{
		int pos = 0;
		int pre_pos = pos;
		//frist byte
		fetch_fin(msg, pos);

		fetch_opcode(msg, pos);
		//second byte
		fetch_mask(msg, pos);

		//third and fourth byte
		unsigned long payload_length_ = 0;
		fetch_payload_length(msg, pos, payload_length_);
		if (payload_length_ <= 0 || payload_length_ >= en_msgbuffersize)
		{
			LOG_PRINT(log_error, "payload_length_:%u is wrong.", payload_length_);
			recv_buffer_remainlen_ = 0;
			return -1;
		}
		else if (payload_length_ > recv_buffer_remainlen_)
		{
			LOG_PRINT(log_error, "payload_length_:%u is larger than recv_buffer_remainlen_:%u !", payload_length_, recv_buffer_remainlen_);
			break;
		}
		else
		{
			fetch_masking_key(msg, pos);

			char payload_[en_msgbuffersize] = {0};
			if (fetch_payload(msg, pos, payload_, payload_length_, en_msgbuffersize))
			{
				recv_buffer_remainlen_ = 0;
				return -1;
			}

			if (-1 == parse_json_to_msg(payload_, payload_length_))
			{
				LOG_PRINT(log_error, "parse_json_to_msg error.");
				recv_buffer_remainlen_ = 0;
				return -1;
			}

			int len = pos - pre_pos;
			pre_pos = pos;
			recv_buffer_remainlen_ -= len;
			msg += len;
		}
	}

	if(recv_buffer_remainlen_ >= en_msgmaxsize)
	{
		recv_buffer_remainlen_ = 0;
		return -1;
	}
	if(msg != recv_buffer_ && recv_buffer_remainlen_ > 0)
	{
		memmove(recv_buffer_, msg, recv_buffer_remainlen_);
	}
	return 0;
}

int CClientConnection::parse_json_to_msg(const char * pdata, int msglen)
{
	if (pdata == NULL || msglen == 0)
	{
		LOG_PRINT(log_error, "parse_json_to_msg input error.");
		return -1;
	}

	std::string strData(pdata, msglen);

	Json::Reader reader(Json::Features::strictMode());
	Json::Value root;

	if (reader.parse(strData, root))
	{
		unsigned int length = root["length"].asInt();
		unsigned int version = root["version"].asInt();
		unsigned int checkcode = root["checkcode"].asInt();
		unsigned int maincmd = root["maincmd"].asInt();
		unsigned int subcmd = root["subcmd"].asInt();
		Json::Value jsonData = root.get("data", "");

		SL_ByteBuffer buf;
		if (!buf.reserve(length))
		{
			LOG_PRINT(log_error, "malloc memory failed,subcmd:%u,length:%u.", subcmd, length);
			return -1;
		}

		char * pData = buf.buffer();
		COM_MSG_HEADER * pHead = (COM_MSG_HEADER *)pData;
		pHead->length = length;
		pHead->version = version;
		pHead->checkcode = checkcode;
		pHead->maincmd = maincmd;
		pHead->subcmd = subcmd;

		unsigned int content_len = length - sizeof(COM_MSG_HEADER);

		char sub[128] = {0};
		sprintf(sub, "%u", subcmd);
		int ret = CGlobalSetting::app_->cmdguide_mgr_->fillCmdParam(std::string(sub), pHead->content, content_len, jsonData);
		if (-1 == ret)
		{
			LOG_PRINT(log_error, "fillCmdParam error.");
			return -1;
		}

		if (-2 == ret)
		{
			LOG_PRINT(log_error, "Json format error.");
			return 0;
		}

		if(-1 == handle_message(pData, length))
		{
			LOG_PRINT(log_error, "handle_message error.");
			return -1;
		}
	}
	else
	{
		LOG_PRINT(log_error, "parse Json failed.Json:%s.", strData.c_str());
		return -1;
	}

	return 0;
}

int CClientConnection::handle_message(const char* pdata, int msglen)
{
	if (pdata == NULL || msglen < SIZE_IVM_HEADER)
	{
		LOG_PRINT(log_warning, "handle_message() err. [userid:%u,client connid:%u,%s:%d]",
			userid, connection_id_, remote_ip_.c_str(), remote_port_);
		return 0;
	}
	
	COM_MSG_HEADER * in_msg = (COM_MSG_HEADER *)pdata;
	if(msglen < sizeof(COM_MSG_HEADER) || in_msg->length < sizeof(COM_MSG_HEADER))
	{
		LOG_PRINT(log_warning, "handle_message() Packet length check faild! [userid:%u,client connid:%u,%s:%d]", 
			userid, connection_id_, remote_ip_.c_str(), remote_port_);
		return 0;
	}

	if (in_msg->version != MDM_Version_Value)
	{
		LOG_PRINT(log_warning, "handle_message() Packet version checks faild! [userid:%u,client connid:%u,%s:%d]",
			userid, connection_id_, remote_ip_.c_str(), remote_port_);
		return 0;
	}

	if (in_msg->length != msglen)
	{
		LOG_PRINT(log_warning, "handle_message() msg len is wrong![userid:%u,client connid:%u,%s:%d]", 
			userid, connection_id_, remote_ip_.c_str(), remote_port_);
		return 0;
	}

	//status is not connected,not need to handle data.
	if(session_status_ != en_session_status_connected)
	{
		LOG_PRINT(log_error, "client-connection m_current_status != connected, then not deal with data![userid:%u,client connid:%u,%s:%d]",
			userid, connection_id_, remote_ip_.c_str(), remote_port_);
		return 0; 
	}

	//first handle hello packet.
	if(Sub_Vchat_ClientHello == in_msg->subcmd)
	{
		handle_hello_msg(in_msg->content);
		return 0;
	}

	//之后hello后才是合法的消息,其他消息不处理(等待链接活动过期自动被删除)
	if(connection_id_ == 0)
    {
		return 0;
	}

	if(Sub_Vchat_ClientPing == in_msg->subcmd && in_msg->length == (sizeof(COM_MSG_HEADER) + sizeof(CMDClientPing_t)))
	{
		handle_ping_msg((char *)in_msg);
		return 0;
	}

	remove_svr_connect_map((char *)in_msg);

	std::string distributed_value = get_distributed_key_msg((char *)in_msg);

    //according to subcmd,get svr_type
    SVR_TYPE_SET svr_type_set = CGlobalSetting::app_->cmdguide_mgr_->getSvrType(in_msg->subcmd);
    SVR_TYPE_SET::iterator iter_set = svr_type_set.begin();
    for (; iter_set != svr_type_set.end(); ++iter_set)
    {
        int svr_type = *iter_set;

        //according user's svr_type,connect id,get server connection
        CTcpClient_ptr pSvrConnPtr = CGlobalSetting::app_->svr_session_manager_->get_conn_inf(svr_type, connection_id_, distributed_value);
	    if (pSvrConnPtr == 0)
	    {
			std::string svr_name = CGlobalSetting::app_->change_type_to_svrname(svr_type);

		    time_t t = time(NULL);
		    if(t - client_manager_->get_last_alarmnotify_time() > CGlobalSetting::alarmnotify_interval_)
		    {
			    //alarm notify
                char content[512] = {0};
                snprintf(content, 512, "[port:%d]get server connection error,svr_name:%s.", CGlobalSetting::listen_port_, svr_name.c_str());
			    CGlobalSetting::alarmnotify_->sendAlarmNoty(e_all_notitype, e_network_conn, "webgate", "webgate alarm", "Yunwei,Usermgr", content);
			    client_manager_->set_last_alarmnotify_time(t);
		    }

		    LOG_PRINT(log_error, "server name:%s is down err [userid:%u,client connid:%u,%s:%d]", svr_name.c_str(), userid, connection_id_, remote_ip_.c_str(), remote_port_);
			
			//如果网关服务器没有与房间服务器建立好连接,并且不是用户管理器,则通知客户端
            char szBuf[128] = {0};
            COM_MSG_HEADER * pOutMsg = (COM_MSG_HEADER *)szBuf;
            pOutMsg->version = MDM_Version_Value;
            pOutMsg->checkcode = 0;
            pOutMsg->maincmd = MDM_Vchat_Login;
            pOutMsg->subcmd = Sub_Vchat_DoNotReachRoomServer;
            pOutMsg->length = sizeof(COM_MSG_HEADER);
            write_message(szBuf, pOutMsg->length);
	    }
	    else 
	    {
			std::string svr_ip = pSvrConnPtr->get_svr_ipaddr();
			unsigned int svr_port = pSvrConnPtr->get_svr_poirt();

			print_specail_cmd((char *)in_msg, svr_ip, svr_port);

		    //产生信息新消息
		    //如果网关服务器与房间服务器建立好连接,则转发给房间服务器
		    last_activetime_ = time(NULL);

			if (-1 == handle_roomsvr_msg((char *)in_msg, svr_ip, svr_port))
			{
				return 0;
			}
			
            int nMsgLen = msglen + sizeof(ClientGateMask_t);
		    SL_ByteBuffer buff(nMsgLen+1);
		    COM_MSG_HEADER * pOutMsg = (COM_MSG_HEADER *)buff.buffer();
		    ClientGateMask_t * pGateMask = (ClientGateMask_t *)(pOutMsg->content);
		    memset(pGateMask, 0, sizeof(ClientGateMask_t));
		    memcpy(pOutMsg, in_msg, sizeof(COM_MSG_HEADER));
		    if(msglen > sizeof(COM_MSG_HEADER) && in_msg->length - sizeof(COM_MSG_HEADER) > 0)
			    memcpy(pOutMsg->content+sizeof(ClientGateMask_t), in_msg->content, in_msg->length-sizeof(COM_MSG_HEADER));
		    pGateMask->param1 = (uint64)this;
		    pGateMask->param2 = (uint64)connection_id_;
			pGateMask->param4 = m_nmobile;
			pGateMask->param5 = ntohl(inet_addr(remote_ip_.c_str()));;
			pGateMask->param6 = remote_port_;
		    pOutMsg->length = in_msg->length + sizeof(ClientGateMask_t);
		    buff.data_end(pOutMsg->length);

		    pSvrConnPtr->write_message(buff);
	    }
    }
	return 0;
}


int CClientConnection::handle_roomsvr_msg(char * data, const std::string & svr_ip, unsigned int svr_port)
{
	COM_MSG_HEADER * in_msg = (COM_MSG_HEADER *)data;

	if(Sub_Vchat_JoinRoomReq == in_msg->subcmd)
	{
		unsigned int devtype = 0;
		if (in_msg->length == SIZE_IVM_HEADER + sizeof(CMDJoinRoomReq_t))
		{
			CMDJoinRoomReq_t * pReq = (CMDJoinRoomReq_t*)(in_msg->content);
			pReq->cIpAddr[IPADDRLEN - 1] = '\0';
			devtype = pReq->devtype;
			strcpy(pReq->cIpAddr, remote_ip_.c_str());
			LOG_PRINT(log_info, "[client connid:%u,userid:%d,roomid:%d,devtype:%u,client:%s:%d]JoinRoomReq,server:%s:%u.",
				connection_id_, pReq->userid, pReq->vcbid, devtype, remote_ip_.c_str(), remote_port_, svr_ip.c_str(), svr_port);

			if (pReq->userid)
			{
				setuserid(pReq->userid);
			}

			if (pReq->vcbid && !m_roomid)
			{
				setroomid(pReq->vcbid);
			}

			if (pReq->vcbid && pReq->vcbid != m_roomid)
			{
				notify_svr_exitroom(m_roomid, userid);

				CGlobalSetting::app_->room_mgr_->del_user_connid(m_roomid, userid, connection_id_);

				setroomid(pReq->vcbid);
			}

			m_nmobile = pReq->devtype;
			setlastlogintime();
			CGlobalSetting::app_->client_session_manager_->setuserconn(userid, m_nmobile, getlastlogintime(), connection_id_);

			m_exitroom = false;
		}
		else
		{
			LOG_PRINT(log_error, "JoinRoomReq length is wrong.size:%u.client:%s:%d.", in_msg->length, remote_ip_.c_str(), remote_port_);
			return -1;
		}
	}

	// user left room message
	if(Sub_Vchat_RoomUserExitReq == in_msg->subcmd)
	{
		CMDUserExitRoomInfo_t * pReq = (CMDUserExitRoomInfo_t *)(in_msg->content);
		LOG_PRINT(log_info, "[client connid:%u,userid:%d,roomid:%d,client:%s:%d]user left room request,server:%s:%u.",
			connection_id_, pReq->userid, pReq->vcbid, remote_ip_.c_str(), remote_port_, svr_ip.c_str(), svr_port);

		CGlobalSetting::app_->room_mgr_->del_user_connid(pReq->vcbid, pReq->userid, connection_id_);

		if (!m_roomid || pReq->vcbid == m_roomid)
		{
			setroomid(0);
			m_exitroom = true;
		}
		else
		{
			LOG_PRINT(log_warning, "client userid:%u send exit room %u request later than join room %u request.so do not handle it.", pReq->userid, pReq->vcbid, m_roomid);
			return -1;
		}
	}

	if(Sub_Vchat_SetMicStateReq == in_msg->subcmd)
	{
		CMDUserMicState_t * pReq = (CMDUserMicState_t *)(in_msg->content);
		m_micuserid = pReq->toid;
		m_micindex = pReq->micindex;
		m_micstate = pReq->micstate;
	}

	if (Sub_Vchat_RoomKickoutUserReq == in_msg->subcmd)
	{
		CMDUserKickoutRoomInfo_t * pReq = (CMDUserKickoutRoomInfo_t *)(in_msg->content);
		LOG_PRINT(log_info, "client send room kick out request.roomid:%u,kickout userid:%u.", pReq->vcbid, pReq->toid);
	}

	return 0;
}

void CClientConnection::clear_data()
{
	//svr_session_manager_ delete this connection.
	CGlobalSetting::app_->svr_session_manager_->del_conn_inf(connection_id_);

	//delete object
	if(client_manager_ != 0)
	{
		client_manager_->del_client(shared_from_this());
	}

	//print all connection inform
	CGlobalSetting::app_->svr_session_manager_->print_conn_inf();

	CGlobalSetting::app_->room_mgr_->del_user_connid(m_roomid, userid, connection_id_);
}

void CClientConnection::check_deadline(const boost::system::error_code & e)
{
	if(!e)
	{
		unsigned int msg_size = 0;
		{
			boost::mutex::scoped_lock lock(send_messages_mutex_);
			msg_size = send_messages_.size();
		}

		if(msg_size >= CGlobalSetting::alarm_queuesize_)
		{
			LOG_PRINT(log_info, "[message_size]client-session queue-size is %u larger than %u,close it.[userid:%u,client connid:%u,%s:%d]",\
				msg_size, CGlobalSetting::alarm_queuesize_, userid, connection_id_, remote_ip_.c_str(), remote_port_);

			notify_svr_clientexit();
			do_close();
		}

		if(!stopped_)
		{
			bool timeout = false;
            time_t now_time = time(NULL);
            if (!m_micstate && (now_time - last_activetime_ > CGlobalSetting::client_timeout_))
            {
				LOG_PRINT(log_warning, "client has not sent packet for %u seconds,close it.[userid:%u,roomid:%u,client connid:%u,%s:%d]",\
					CGlobalSetting::client_timeout_, userid, m_roomid, connection_id_, remote_ip_.c_str(), remote_port_);
				timeout = true;
            }

			if (m_micstate && (now_time - last_activetime_ > CGlobalSetting::on_mic_client_timeout_))
			{
				LOG_PRINT(log_warning, "on mic client has not sent packet for %u seconds,close it.[userid:%u,roomid:%u,client connid:%u,%s:%d]",\
					CGlobalSetting::on_mic_client_timeout_, userid, m_roomid, connection_id_, remote_ip_.c_str(), remote_port_);
				timeout = true;
			}

			if (timeout)
			{
				notify_svr_clienttimeout();
				do_close();
				clear_data();
				return;
			}

			deadline_.expires_from_now(boost::posix_time::seconds(en_checkactivetime));
			deadline_.async_wait(boost::bind(&CClientConnection::check_deadline, shared_from_this(), boost::asio::placeholders::error));
		}
		else
		{
			clear_data();
		}
	}
	else if(e)
	{
		LOG_PRINT(log_error, "timer error:[%s].[userid:%u,client connid:%u,%s:%d]", boost::system::system_error(e).what(), userid, connection_id_, remote_ip_.c_str(), remote_port_);
	}
}

void CClientConnection::handle_ping_msg(char * ping)
{
	if (!ping)
	{
		return;
	}

	last_activetime_ = time(NULL);

	COM_MSG_HEADER * req = (COM_MSG_HEADER *)ping;
	CMDClientPing_t * pPingMsg = (CMDClientPing_t *)req->content;
	unsigned int main_cmd = req->maincmd;

	//Client ping msg do not need to transfer to server.
	if (userid == 0)
	{
		setuserid(pPingMsg->userid);
		if (userid != 0) 
		{
			LOG_PRINT(log_info, "CClientConnection::handle_message() ping userid:%d,client connid:%d", userid, connection_id_);
		}
	}

	char szBuf[512] = {0};
	COM_MSG_HEADER * pHead = (COM_MSG_HEADER *)szBuf;
	pHead->version = MDM_Version_Value;
	pHead->checkcode = 0;
	pHead->maincmd = main_cmd;
	pHead->subcmd = Sub_Vchat_ClientPingResp;

	CMDClientPingResp_t * resp = (CMDClientPingResp_t*)(pHead->content);
	resp->userid = pPingMsg->userid;
	resp->roomid = pPingMsg->roomid;

	int nMsgLen = sizeof(COM_MSG_HEADER) + sizeof(CMDClientPingResp_t);
	pHead->length = nMsgLen;
	write_message(szBuf, nMsgLen);
}

void CClientConnection::handle_hello_msg(char * hello)
{
	if (!hello)
	{
		return;
	}

	CMDClientHello_t * pHelloMsg = (CMDClientHello_t *)hello;
	if(pHelloMsg->param1 == 12 &&  pHelloMsg->param2 == 8 && pHelloMsg->param3 == 7 && pHelloMsg->param4 == 1)
	{
		if(connection_id_ == 0) 
		{
			last_activetime_ = time(NULL);

			connection_id_ = CGlobalSetting::app_->client_session_manager_->next_sessionid();
			CGlobalSetting::app_->client_session_manager_->update_client_map(shared_from_this());

			LOG_PRINT(log_info, "recv new hello-msg,new conn_id=%d,client:%s:%d.", connection_id_, remote_ip_.c_str(), remote_port_);

			//print all connection information
			CGlobalSetting::app_->svr_session_manager_->print_conn_inf();
		}
	}
}

int CClientConnection::build_netmsg_svr(char * szBuf, int nBufLen, int mainCmdId, int subCmdId, void * pData, int pDataLen)
{
	if(szBuf == 0 || pData == 0)
	{
		LOG_PRINT(log_error, "(szBuf==0 || pData==0)");
		return -1;
	}

	int nMsgLen = SIZE_IVM_HEADER + SIZE_IVM_CLIENTGATE + pDataLen;
	if(nBufLen < nMsgLen)
	{
		LOG_PRINT(log_error, "(nBufLen <= nMsgLen)");
		return -1;
	}

	COM_MSG_HEADER * pHead = (COM_MSG_HEADER *)szBuf;
	pHead->version = MDM_Version_Value;
	pHead->checkcode = 0;
	pHead->maincmd = mainCmdId;
	pHead->subcmd = subCmdId;
	ClientGateMask_t * pClientGate = (ClientGateMask_t *)(pHead->content);
	memset(pClientGate, 0, sizeof(ClientGateMask_t));
	pClientGate->param1 = (uint64)this;
	pClientGate->param2 = (uint64)connection_id_;
	void * pContent = (void *)(pHead->content + SIZE_IVM_CLIENTGATE);
	memcpy(pContent, pData, pDataLen);
	pHead->length = SIZE_IVM_HEADER + SIZE_IVM_CLIENTGATE + pDataLen;

	return pHead->length;
}

void CClientConnection::rejoinroom(unsigned int roomid, unsigned int userid)
{
	if (!roomid || !userid)
	{
		return;
	}

	char szBuf[512] = {0};
	CMDGateJoinRoomReq_t msgInfo = {0};
	msgInfo.vcbid = roomid;
	msgInfo.userid = userid;
	strcpy(msgInfo.cIpAddr, remote_ip_.c_str());
	msgInfo.devtype = m_nmobile;
	msgInfo.micuserid = m_micuserid;
	msgInfo.micstate = m_micstate;
	msgInfo.micindex = m_micindex;

	char distributed_value[32] = {0};
	sprintf(distributed_value, "%u", userid);

	int nMsgLen = build_netmsg_svr(szBuf, sizeof(szBuf), MDM_Vchat_Room, Sub_Vchat_GateJoinRoom, &msgInfo, sizeof(CMDGateJoinRoomReq_t));
	SL_ByteBuffer buff;
	buff.write(szBuf, nMsgLen);

	CTcpClient_ptr pSvrConnPtr = CGlobalSetting::app_->svr_session_manager_->get_conn_inf(e_roomsvr_type, connection_id_, distributed_value);
	if (!pSvrConnPtr)
	{
		LOG_PRINT(log_error, "cannot get roomsvr connection.");
		return;
	}

	if (pSvrConnPtr->is_connected())
	{
		LOG_PRINT(log_info, "[rejoin room]userid:%u,user ip:%s,nmobile:%d,roomid:%u,client connid:%u.micuserid:%u.micindex:%d.", \
			userid, remote_ip_.c_str(), m_nmobile, roomid, connection_id_, m_micuserid, (int)m_micindex);
		pSvrConnPtr->write_message(buff);
	}
	else
	{
		LOG_PRINT(log_warning, "[rejoin room]userid:%u,user ip:%s,nmobile:%d,roomid:%u,client connid:%u.roomsvr connid:%u is disconnected.", \
			userid, remote_ip_.c_str(), m_nmobile, roomid, connection_id_, pSvrConnPtr->getconn_ssn());
	}
}

void CClientConnection::notify_svr_clientexit()
{
	//notify_svr_clientclosesocket();

	notify_svr_exitroom(m_roomid, userid);
}

void CClientConnection::notify_svr_exceptexit()
{
	//notify_svr_clientclosesocket();

	notify_svr_exceptexitroom(m_roomid, userid);
}

void CClientConnection::notify_svr_clienttimeout()
{
	//notify_svr_clientclosesocket();

	notify_svr_kickoutroom(m_roomid, userid, ERR_KICKOUT_TIMEOUT);
}

/*
void CClientConnection::notify_svr_clientclosesocket()
{
	if (userid == 0)
		return;

	LOG_PRINT(log_warning, "client close socket[userid:%u,connid:%u,%s:%d]", userid, connection_id_, remote_ip_.c_str(), remote_port_);

	CTcpClient_ptr pSvrConnPtr = CGlobalSetting::app_->svr_session_manager_->get_conn_inf(e_logonsvr_type, connection_id_);
	if (pSvrConnPtr == 0)
		return;

	CMDUserOnlineBaseInfoNoty_t onlineNoty;
	onlineNoty.userid = userid;
	onlineNoty.sessionid = 0;
	onlineNoty.devicetype = (unsigned int)m_nmobile;

	char szBuf[256] = {0};
	int nMsgLen = build_netmsg_svr(szBuf, sizeof(szBuf), MDM_Vchat_Login, Sub_Vchat_ClientCloseSocket_Req, &onlineNoty, sizeof(CMDUserOnlineBaseInfoNoty_t));
	SL_ByteBuffer buff;
	buff.write(szBuf, nMsgLen);

	pSvrConnPtr->write_message(buff);
}
*/

void CClientConnection::notify_svr_exceptexitroom(unsigned int roomid, unsigned int userid)
{
	if (!roomid || !userid)
	{
		return;
	}

	char szBuf[128] = {0};
	CMDUserExceptExitRoomInfo_t msgInfo = {0};
	msgInfo.vcbid = roomid;
	msgInfo.userid = userid;

	int nMsgLen = build_netmsg_svr(szBuf, sizeof(szBuf), MDM_Vchat_Room, Sub_Vchat_RoomUserExceptExitReq, &msgInfo, sizeof(CMDUserExceptExitRoomInfo_t));
	
	SL_ByteBuffer buff;
	buff.write(szBuf, nMsgLen);

	CTcpClient_ptr pSvrConnPtr = CGlobalSetting::app_->svr_session_manager_->get_conn_inf(e_roomsvr_type, connection_id_);
	if (!pSvrConnPtr)
	{
		LOG_PRINT(log_error, "cannot get roomsvr connection.");
		return;
	}

	if (pSvrConnPtr->is_connected())
	{
		LOG_PRINT(log_info, "[except exit room]userid:%u,user ip:%s,nmobile:%d,roomid:%u,client connid:%u.", userid, remote_ip_.c_str(), m_nmobile, roomid, connection_id_);
		pSvrConnPtr->write_message(buff);
	}
	else
	{
		LOG_PRINT(log_warning, "[except exit room]userid:%u,user ip:%s,nmobile:%d,roomid:%u,client connid:%u.roomsvr connid:%u is disconnected.", \
			userid, remote_ip_.c_str(), m_nmobile, roomid, connection_id_, pSvrConnPtr->getconn_ssn());
	}

	m_exitroom = true;
}

void CClientConnection::notify_svr_exitroom(unsigned int roomid, unsigned int userid)
{
	if (!roomid || !userid)
	{
		return;
	}

	char szBuf[128] = {0};
	CMDUserExitRoomInfo_t msgInfo = {0};
	msgInfo.vcbid = roomid;
	msgInfo.userid = userid;

	int nMsgLen = build_netmsg_svr(szBuf, sizeof(szBuf), MDM_Vchat_Room, Sub_Vchat_RoomUserExitReq, &msgInfo, sizeof(CMDUserExitRoomInfo_t));
	SL_ByteBuffer buff;
	buff.write(szBuf, nMsgLen);

	CTcpClient_ptr pSvrConnPtr = CGlobalSetting::app_->svr_session_manager_->get_conn_inf(e_roomsvr_type, connection_id_);
	if (!pSvrConnPtr)
	{
		LOG_PRINT(log_error, "cannot get roomsvr connection.");
		return;
	}

	if (pSvrConnPtr->is_connected())
	{
		LOG_PRINT(log_info, "[exit room]userid:%u,user ip:%s,nmobile:%d,roomid:%u,client connid:%u.", userid, remote_ip_.c_str(), m_nmobile, roomid, connection_id_);
		pSvrConnPtr->write_message(buff);
	}

	m_exitroom = true;
}

void CClientConnection::notify_svr_kickoutroom(unsigned int roomid, unsigned int userid, int reasonid)
{
	if (!roomid || !userid)
	{
		return;
	}

	char szBuf[512] = {0};
	CMDUserKickoutRoomInfo_t msgInfo = {0};
	msgInfo.vcbid = roomid;
	msgInfo.srcid = 0;
	msgInfo.toid = userid;
	msgInfo.resonid = reasonid;

	int nMsgLen = build_netmsg_svr(szBuf, sizeof(szBuf), MDM_Vchat_Room, Sub_Vchat_RoomKickoutUserReq, &msgInfo, sizeof(CMDUserKickoutRoomInfo_t));

	SL_ByteBuffer buff;
	buff.write(szBuf, nMsgLen);
	CTcpClient_ptr pSvrConnPtr = CGlobalSetting::app_->svr_session_manager_->get_conn_inf(e_roomsvr_type, connection_id_);
	if (!pSvrConnPtr)
	{
		LOG_PRINT(log_error, "cannot get roomsvr connection.");
		return;
	}

	if (pSvrConnPtr->is_connected())
	{
		LOG_PRINT(log_info, "[kick out room]userid:%u,user ip:%s,nmobile:%d,roomid:%u,client connid:%u.", userid, remote_ip_.c_str(), m_nmobile, roomid, connection_id_);
		pSvrConnPtr->write_message(buff);
	}

	m_exitroom = true;
}

std::string CClientConnection::get_distributed_key_msg(char * in_msg)
{
	char distributed_key[128] = {0};

	COM_MSG_HEADER * req = (COM_MSG_HEADER *)in_msg;
	switch(req->subcmd)
	{
	case Sub_Vchat_QueryVcbExistReq:
		{
			CMDQueryVcbExistReq_t * pData = (CMDQueryVcbExistReq_t *)(req->content);
			sprintf(distributed_key, "%u", pData->vcbid);
		}
		break;
	case Sub_Vchat_FavoriteVcbReq:
		{
			CMDFavoriteRoomReq_t * pData = (CMDFavoriteRoomReq_t *)(req->content);
			sprintf(distributed_key, "%u", pData->vcbid);
		}
		break;
	case Sub_Vchat_SetRoomInfoReq:
		{
			CMDSetRoomInfoReq_t * pData = (CMDSetRoomInfoReq_t *)(req->content);
			sprintf(distributed_key, "%u", pData->vcbid);
		}
		break;
	case Sub_Vchat_SetRoomInfoReq_v2:
		{
			CMDSetRoomInfoReq_v2_t * pData = (CMDSetRoomInfoReq_v2_t *)(req->content);
			sprintf(distributed_key, "%u", pData->vcbid);
		}
		break;
	case Sub_Vchat_SetRoomNoticeReq:
		{
			CMDSetRoomNoticeReq_t * pData = (CMDSetRoomNoticeReq_t *)(req->content);
			sprintf(distributed_key, "%u", pData->vcbid);
		}
		break;
	case Sub_Vchat_TradeGiftReq:
		{
			CMDTradeGiftRecord_t * pData = (CMDTradeGiftRecord_t *)(req->content);
			sprintf(distributed_key, "%u", pData->vcbid);
		}
		break;
	case Sub_Vchat_ViewpointTradeGiftReq:
		{
			CMDViewpointTradeGiftReq_t * pData = (CMDViewpointTradeGiftReq_t *)(req->content);
			sprintf(distributed_key, "%u", pData->roomid);
		}
		break;
	case Sub_Vchat_BuyPrivateVipReq:
		{
			CMDBuyPrivateVipReq_t * pData = (CMDBuyPrivateVipReq_t *)(req->content);
			sprintf(distributed_key, "%u", pData->teacherid);
		}
		break;
	case Sub_Vchat_AskQuestionReq:
		{
			CMDAskQuestionReq_t * pData = (CMDAskQuestionReq_t *)(req->content);
			sprintf(distributed_key, "%u", pData->roomid);
		}
		break;
	
	////////////////////////////////logonsvr//////////////////////////////////////////////////
	case Sub_Vchat_SetUserProfileReq:
		{
			 CMDSetUserProfileReq_t * pData = (CMDSetUserProfileReq_t *)(req->content);
			 sprintf(distributed_key, "%u", pData->userid);
		}
		break;
	case Sub_Vchat_SetUserMoreInfoReq:
		{
			CMDUserMoreInfo_t * pData = (CMDUserMoreInfo_t *)(req->content);
			sprintf(distributed_key, "%u", pData->userid);
		}
		break;
	case Sub_Vchat_SetUserPwdReq:
		{
			CMDSetUserPwdReq_t * pData = (CMDSetUserPwdReq_t *)(req->content);
			sprintf(distributed_key, "%u", pData->userid);
		}
		break;
	case Sub_Vchat_logonReq4:
		{
			CMDUserLogonReq4_t * pData = (CMDUserLogonReq4_t *)(req->content);
			if (strcmp(pData->cSerial, "") != 0)
			{
				sprintf(distributed_key, "%s", pData->cSerial);
				LOG_PRINT(log_debug, "[logonReq4]client key:%s.", distributed_key);
			}
			else if (!remote_ip_.empty())
			{
				unsigned int key = ntohl(inet_addr(remote_ip_.c_str()));
				sprintf(distributed_key, "%u", key);
				LOG_PRINT(log_debug, "[logonReq4]client ip:%s,key:%s.", remote_ip_.c_str(), distributed_key);
			}
		}
		break;
	case Sub_Vchat_logonReq5:
		{
			CMDUserLogonReq5_t * pData = (CMDUserLogonReq5_t *)(req->content);
			sprintf(distributed_key, "%u", pData->userid);
		}
		break;
	case Sub_Vchat_logonTokenReq:
		{
			CMDSessionTokenReq_t * pData = (CMDSessionTokenReq_t *)(req->content);
			sprintf(distributed_key, "%u", pData->userid);
		}
		break;

	////////////////////////////////roomsvr//////////////////////////////////////////////////
	case Sub_Vchat_PreJoinRoomReq:
		{
			CMDPreJoinRoomReq_t * pData = (CMDPreJoinRoomReq_t *)(req->content);
			sprintf(distributed_key, "%u", pData->userid);
		}
		break;
	case Sub_Vchat_JoinRoomReq:
		{
			CMDJoinRoomReq_t * pData = (CMDJoinRoomReq_t *)(req->content);
			sprintf(distributed_key, "%u", pData->userid);
		}
		break;
	case Sub_Vchat_SetMicStateReq:
		{
			CMDUserMicState_t * pData = (CMDUserMicState_t *)(req->content);
			sprintf(distributed_key, "%u", pData->vcbid);
		}
		break;
	case Sub_Vchat_RoomUserExitReq:
		{
			CMDUserExitRoomInfo_t * pData = (CMDUserExitRoomInfo_t *)(req->content);
			sprintf(distributed_key, "%u", pData->userid);
		}
		break;
	default:
		break;
	}

	return std::string(distributed_key);
}

void CClientConnection::print_specail_cmd(char * in_msg, const std::string & svr_ip, unsigned int svr_port)
{
	//print the server inform.
	COM_MSG_HEADER * req = (COM_MSG_HEADER *)in_msg;
	switch(req->subcmd)
	{
	case Sub_Vchat_QueryVcbExistReq:
		{
			CMDQueryVcbExistReq_t * pData = (CMDQueryVcbExistReq_t *)(req->content);
			LOG_PRINT(log_info, "[QueryVcbExist][client request]roomid:%u,server:%s:%u.", pData->vcbid, svr_ip.c_str(), svr_port);
		}
		break;
	case Sub_Vchat_FavoriteVcbReq:
		{
			CMDFavoriteRoomReq_t * pData = (CMDFavoriteRoomReq_t *)(req->content);
			LOG_PRINT(log_info, "[FavoriteVcb][client request]roomid:%u,server:%s:%u.", pData->vcbid, svr_ip.c_str(), svr_port);
		}
		break;
	case Sub_Vchat_SetRoomInfoReq:
		{
			CMDSetRoomInfoReq_t * pData = (CMDSetRoomInfoReq_t *)(req->content);
			LOG_PRINT(log_info, "[SetRoomInfo][client request]roomid:%u,server:%s:%u.", pData->vcbid, svr_ip.c_str(), svr_port);
		}
		break;
	case Sub_Vchat_SetRoomInfoReq_v2:
		{
			CMDSetRoomInfoReq_v2_t * pData = (CMDSetRoomInfoReq_v2_t *)(req->content);
			LOG_PRINT(log_info, "[SetRoomInfo_v2][client request]roomid:%u,server:%s:%u.", pData->vcbid, svr_ip.c_str(), svr_port);
		}
		break;
	case Sub_Vchat_SetRoomNoticeReq:
		{
			CMDSetRoomNoticeReq_t * pData = (CMDSetRoomNoticeReq_t *)(req->content);
			LOG_PRINT(log_info, "[SetRoomNotice][client request]roomid:%u,server:%s:%u.", pData->vcbid, svr_ip.c_str(), svr_port);
		}
		break;

	case Sub_Vchat_TradeGiftReq:
		{
			CMDTradeGiftRecord_t * pData = (CMDTradeGiftRecord_t *)(req->content);
			LOG_PRINT(log_info, "[TradeGift][client request]roomid:%u,server:%s:%u.", pData->vcbid, svr_ip.c_str(), svr_port);
		}
		break;
	case Sub_Vchat_ViewpointTradeGiftReq:
		{
			CMDViewpointTradeGiftReq_t * pData = (CMDViewpointTradeGiftReq_t *)(req->content);
			LOG_PRINT(log_info, "[ViewpointTradeGift][client request]roomid:%u,server:%s:%u.", pData->roomid, svr_ip.c_str(), svr_port);
		}
		break;
	case Sub_Vchat_BuyPrivateVipReq:
		{
			CMDBuyPrivateVipReq_t * pData = (CMDBuyPrivateVipReq_t *)(req->content);
			LOG_PRINT(log_info, "[BuyPrivateVip][client request]teacherid:%u,server:%s:%u.", pData->teacherid, svr_ip.c_str(), svr_port);
		}
		break;
	case Sub_Vchat_AskQuestionReq:
		{
			CMDAskQuestionReq_t * pData = (CMDAskQuestionReq_t *)(req->content);
			LOG_PRINT(log_info, "[AskQuestion][client request]roomid:%u,server:%s:%u.", pData->roomid, svr_ip.c_str(), svr_port);
		}
		break;

	case Sub_Vchat_ReportMediaGateReq:
		{
			CMDReportMediaGateReq_t * pData = (CMDReportMediaGateReq_t *)(req->content);
			LOG_PRINT(log_info, "[ReportMediaGate][client request]roomid:%u,server:%s:%u.", pData->vcbid, svr_ip.c_str(), svr_port);
		}
		break;
	case Sub_Vchat_SetMicStateReq:
		{
			CMDUserMicState_t * pData = (CMDUserMicState_t *)(req->content);
			LOG_PRINT(log_info, "[setmicstate][client request]roomid:%u,toid:%u,micstate:%d,server:%s:%u.", pData->vcbid, pData->toid, (int)pData->micstate, svr_ip.c_str(), svr_port);
		}
		break;

	////////////////////////////////logonsvr//////////////////////////////////////////////////
	case Sub_Vchat_SetUserProfileReq:
		{
			CMDSetUserProfileReq_t * pData = (CMDSetUserProfileReq_t *)(req->content);
			LOG_PRINT(log_info, "[SetUserProfile][client request]userid:%u,server:%s:%u.", pData->userid, svr_ip.c_str(), svr_port);
		}
		break;
	case Sub_Vchat_SetUserMoreInfoReq:
		{
			CMDUserMoreInfo_t * pData = (CMDUserMoreInfo_t *)(req->content);
			LOG_PRINT(log_info, "[SetUserMoreInfo][client request]userid:%u,server:%s:%u.", pData->userid, svr_ip.c_str(), svr_port);
		}
		break;
	case Sub_Vchat_SetUserPwdReq:
		{
			CMDSetUserPwdReq_t * pData = (CMDSetUserPwdReq_t *)(req->content);
			LOG_PRINT(log_info, "[SetUserPwd][client request]userid:%u,server:%s:%u.", pData->userid, svr_ip.c_str(), svr_port);
		}
		break;
	case Sub_Vchat_logonReq4:
		{
			CMDUserLogonReq4_t * pData = (CMDUserLogonReq4_t *)(req->content);
			LOG_PRINT(log_info, "[logonReq4][client request]client:%s,serial:%s,server:%s:%u.", remote_ip_.c_str(), pData->cSerial, svr_ip.c_str(), svr_port);
		}
		break;
	case Sub_Vchat_logonReq5:
		{
			CMDUserLogonReq5_t * pData = (CMDUserLogonReq5_t *)(req->content);
			LOG_PRINT(log_info, "[logonReq5][client request]userid:%u,server:%s:%u.", pData->userid, svr_ip.c_str(), svr_port);
		}
		break;
	case Sub_Vchat_logonTokenReq:
		{
			CMDSessionTokenReq_t * pData = (CMDSessionTokenReq_t *)(req->content);
			LOG_PRINT(log_info, "[logonTokenReq][client request]userid:%u,server:%s:%u.", pData->userid, svr_ip.c_str(), svr_port);
		}
		break;

	default:
		break;
	}
	return;
}

void CClientConnection::remove_svr_connect_map(char * in_msg)
{
	COM_MSG_HEADER * req = (COM_MSG_HEADER *)in_msg;
	unsigned int subcmd = req->subcmd;
	if (Sub_Vchat_JoinRoomReq == subcmd || Sub_Vchat_SetMicStateReq == subcmd || Sub_Vchat_RoomUserExitReq == subcmd)
	{
		CGlobalSetting::app_->svr_session_manager_->del_conn_inf_by_type(connection_id_, e_roomsvr_type);
	}
}


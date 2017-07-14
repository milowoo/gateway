/*
 * usermgrsvr_client.cpp
 *
 *  Created on: Apr 15, 2016
 *      Author: root
 */

#include "usermgr_client.h"
#include "message_vchat.h"
#include "message_comm.h"
#include "CLogThread.h"
#include "GlobalSetting.h"

CUsermgrClient::CUsermgrClient(boost::asio::io_service& io_service):CTcpClient(io_service)
{
}

CUsermgrClient::~CUsermgrClient() 
{
}

void CUsermgrClient::send_keeplive_command()
{
	
	LOG_PRINT(log_info, "[CUsermgrClient]send_keeplive_command");

	SL_ByteBuffer outbuf(512);
	COM_MSG_HEADER * pingReq = (COM_MSG_HEADER*)outbuf.buffer();
	pingReq->version = MDM_Version_Value;
	pingReq->checkcode = 0;
	pingReq->maincmd = MDM_Vchat_Usermgr;
	pingReq->subcmd = Sub_Vchat_ClientPing;

	CMDClientPing_t * pReq = (CMDClientPing_t *)pingReq->content;
	memset(pReq, 0, sizeof(CMDClientPing_t));
	pReq->userid = 0;
	pReq->roomid = WebSocketPingRoom;
	pingReq->length = sizeof(COM_MSG_HEADER) + sizeof(CMDClientPing_t);

	outbuf.data_end(pingReq->length);
	send_message(outbuf, false);
	
}

int CUsermgrClient::handle_message(const char * pdata, int msglen)
{
	
	if (NULL == pdata || 0 == msglen)
	{
		LOG_PRINT(log_error, "handle_message input error.msg is null or len is 0");
		return 0;
	}

	COM_MSG_HEADER * in_msg = (COM_MSG_HEADER *)pdata;
	LOG_PRINT(log_debug, "Packet from usermgrsvr,maincmd:%d,subcmd:%d.", in_msg->maincmd, in_msg->subcmd);
	if(in_msg->maincmd == MDM_Vchat_Usermgr && in_msg->subcmd == Sub_Vchat_GetAllUserReq)
	{
		//this msg request all login users.
		CGlobalSetting::app_->client_session_manager_->post_all_user_login();
		return 0;
	}

	//Others is push msg.format:COM_MSG_HEADER + ClientGateMask_t + CPushGateMask
	if (msglen < sizeof(COM_MSG_HEADER) + sizeof(ClientGateMask_t))
	{
		LOG_PRINT(log_error, "packet length is wrong.length:%d.server:%s:%u.", msglen, m_ipaddr.c_str(), m_port);
		return 0;
	}

	COM_MSG_HEADER * pHead = (COM_MSG_HEADER *)pdata;
	ClientGateMask_t * pClient = (ClientGateMask_t *)(pHead->content);
	byte termtype = byte(pClient->param1);
	unsigned int userid = 0;
	time_t logintime = time(0);
	bool bBroadcast = false;
	unsigned int roomid = 0;
	if (BROADCAST_TYPE == pClient->param3 && BROADCAST_TYPE == pClient->param4)
	{
		roomid = pClient->param5;
		bBroadcast = true;
	}
	else
	{
		userid = pClient->param3;
		logintime = (time_t)pClient->param2;
		LOG_PRINT(log_debug, "notice user(%u,%u,%u).", userid, termtype, logintime);
	}

	int newlen = msglen - sizeof(ClientGateMask_t);
	SL_ByteBuffer outbuf(newlen);
	char * buff = outbuf.buffer();
	COM_MSG_HEADER * pOutMsg = (COM_MSG_HEADER *)buff;
	memcpy(pOutMsg, pHead, sizeof(COM_MSG_HEADER));
	pOutMsg->length = newlen;

	int datalen = msglen - sizeof(ClientGateMask_t) - sizeof(COM_MSG_HEADER);
	char * pOutData = buff + sizeof(COM_MSG_HEADER);
	char * pInData = pHead->content + sizeof(ClientGateMask_t);
	memcpy(pOutData, pInData, datalen);
	outbuf.data_end(newlen);
	if (bBroadcast)
	{
		if (!roomid)
		{
			CGlobalSetting::app_->client_session_manager_->broadcast_all_client(termtype, outbuf);
		}
		else
		{
			CGlobalSetting::app_->client_session_manager_->broadcast_room_all_connects(roomid, 0, outbuf);
		}
	}
	else
	{
		connection_ptr connptr = CGlobalSetting::app_->client_session_manager_->find_user_conn(userid, termtype, (unsigned int)logintime);
		if (connptr.get())
		{
			connptr.get()->write_message(outbuf);
		}
		else
		{
			LOG_PRINT(log_warning, "Cannot find this connection of this user(%u,%u,%u).", userid, termtype, logintime);
		}
	}

	return 0;
}

/*
 * roomsvr_client.cpp
 *
 *  Created on: Apr 15, 2016
 *      Author: root
 */

#include "roomsvr_client.h"
#include "message_vchat.h"
#include "message_comm.h"
#include "CLogThread.h"
#include "GlobalSetting.h"

CRoomsvrClient::CRoomsvrClient(boost::asio::io_service& io_service):CTcpClient(io_service)
{
}

CRoomsvrClient::~CRoomsvrClient() 
{
}

void CRoomsvrClient::send_hello_command()
{
	SL_ByteBuffer outbuf(512);
	COM_MSG_HEADER * pmsgheader = (COM_MSG_HEADER *)outbuf.buffer();
	pmsgheader->version = MDM_Version_Value;
	pmsgheader->checkcode = 0;
	pmsgheader->maincmd = MDM_Vchat_Room;
	pmsgheader->subcmd = Sub_Vchat_ClientHello;

	CMDGateHello_t * preq = (CMDGateHello_t *)(pmsgheader->content);
	preq->param1 = 12;
	preq->param2 = 8;
	preq->param3 = 7;
	preq->param4 = 1;
	preq->gateid = m_ngateid;
	pmsgheader->length = sizeof(COM_MSG_HEADER) + sizeof(CMDGateHello_t);
	outbuf.data_end(pmsgheader->length);
	send_message(outbuf, true);

	LOG_PRINT(log_info, "send Client-Hello MSG to Server,gateid:%u,server:%s:%u.", m_ngateid, m_ipaddr.c_str(), m_port);
}

int CRoomsvrClient::handle_message(const char * msg, int len)
{
	if (msg == NULL || len <  SIZE_IVM_HEADER + SIZE_IVM_CLIENTGATE)
	{
		LOG_PRINT(log_error, "CRoomsvrClient handle_message() from server err.server:%s:%u.", m_ipaddr.c_str(), m_port);
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

	print_specail_cmd(msg, len);

	if (BROADCAST_TYPE == pGateMask->param3 && BROADCAST_TYPE == pGateMask->param4)
	{
		handle_broadcast_msg(msg, len);
		return 0;
	}

	if (CAST_USER_ALL_DEV == pGateMask->param3 && CAST_USER_ALL_DEV == pGateMask->param4 && pGateMask->param5)
	{
		handle_cast_user_connects_msg(msg, len);
		return 0;
	}

	if (CAST_CLIENTS_ON_ONE_SVR == pGateMask->param3 && CAST_CLIENTS_ON_ONE_SVR == pGateMask->param4)
	{
		handle_cast_clients_on_one_svr(msg, len);
		return 0;
	}

	//转发消息
	unsigned int pConnId = pGateMask->param2;
	//应该通过 再次 查找 一下该 conn 是否存在
	//直接使用变量进行 判断的原因 是防止 部分野指针 直接调用函数 引起的 奔溃
	connection_ptr pConn_This = CGlobalSetting::app_->client_session_manager_->find_client_map(pConnId);
	if(!pConn_This)
	{
		LOG_PRINT(log_error, "client fd is closed,client connid:%d,maincmd:%u,subcmd:%u.server:%s:%u.",\
			pConnId, in_msg->maincmd, in_msg->subcmd, m_ipaddr.c_str(), m_port);

		if (Sub_Vchat_JoinRoomResp == in_msg->subcmd)
		{
			CMDJoinRoomResp_t * pRes = (CMDJoinRoomResp_t *)(in_msg->content + SIZE_IVM_CLIENTGATE);
			LOG_PRINT(log_warning, "[join room resp]client fd is closed,need to notify exit room.client connid:%d,userid:%u,roomid:%u.server:%s:%u.",\
				pConnId, pRes->userid, pRes->vcbid, m_ipaddr.c_str(), m_port);
			notify_svr_exitroom(pRes->vcbid, pRes->userid, pGateMask);
		}

		if (Sub_Vchat_GateJoinRoomResp == in_msg->subcmd)
		{
			CMDGateJoinRoomResp_t * pRes = (CMDGateJoinRoomResp_t *)(in_msg->content + SIZE_IVM_CLIENTGATE);
			if (!pRes->errorid)
			{
				LOG_PRINT(log_warning, "[rejoin room resp]client fd is closed,need to notify exit room.client connid:%d,userid:%u,roomid:%u.server:%s:%u.",\
					pConnId, pRes->userid, pRes->vcbid, m_ipaddr.c_str(), m_port);
				notify_svr_exitroom(pRes->vcbid, pRes->userid, pGateMask);
			}
		}

		return 0;
	}
	else if(pConn_This->connection_id() != pConnId)
	{
		LOG_PRINT(log_warning, "handle_message err! client session_id not equal![old connid:%d, new connid:%d]", pConnId, pConn_This->connection_id());
	}
	else if(pConn_This->session_status() == CClientConnection::en_session_status_connected)  
	{
		if(Sub_Vchat_JoinRoomResp == in_msg->subcmd)
		{
			CMDJoinRoomResp_t * pRes = (CMDJoinRoomResp_t *)(in_msg->content + SIZE_IVM_CLIENTGATE);
			
			if (pConn_This->client_exit_room())
			{
				LOG_PRINT(log_warning, "client exit room but receive join room response,need to notify exit room.client connid:%u,userid:%u,roomid:%u.",\
					pConnId, pRes->userid, pRes->vcbid);
				notify_svr_exitroom(pRes->vcbid, pRes->userid, pGateMask);
				return 0;
			}
			else
			{
				CGlobalSetting::app_->room_mgr_->add_user_connid(pRes->vcbid, pRes->userid, pConnId);
			}
		}

		if (Sub_Vchat_GateJoinRoomResp == in_msg->subcmd)
		{
			CMDGateJoinRoomResp_t * pRes = (CMDGateJoinRoomResp_t *)(in_msg->content + SIZE_IVM_CLIENTGATE);
			if (!pRes->errorid)
			{
				if (pConn_This->client_exit_room())
				{
					LOG_PRINT(log_warning, "client exit room but receive rejoin room response,need to notify exit room.client connid:%u,userid:%u,roomid:%u.",\
						pConnId, pRes->userid, pRes->vcbid);
					notify_svr_exitroom(pRes->vcbid, pRes->userid, pGateMask);
				}
			}
			else
			{
				LOG_PRINT(log_warning, "[rejoin room resp]error:%d,need to clear data.client connid:%d,userid:%u,roomid:%u.server:%s:%u.",\
					pRes->errorid, pConnId, pRes->userid, pRes->vcbid, m_ipaddr.c_str(), m_port);
				CGlobalSetting::app_->room_mgr_->del_user_connid(pRes->vcbid, pRes->userid, pConnId);
				pConn_This->setroomid(0);
			}
			return 0;
		}

		if(Sub_Vchat_RoomKickoutUserNoty == in_msg->subcmd)
		{
			CMDUserKickoutRoomInfo_t * pRes = (CMDUserKickoutRoomInfo_t *)(in_msg->content + SIZE_IVM_CLIENTGATE);
			CGlobalSetting::app_->room_mgr_->del_user_connid(pRes->vcbid, pRes->toid, pConnId);
			pConn_This->setroomid(0);
		}

		//transfer msg to client if this is not usermgrsvr
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

void CRoomsvrClient::post_close_process()
{
	if (e_roomsvr_type == m_svr_type)
	{
		client_rejoinroom();
	}
}

void CRoomsvrClient::client_rejoinroom()
{
	std::set<unsigned int> client_conn_set;
	get_all_connid(client_conn_set);

	if (!client_conn_set.empty())
	{
		LOG_PRINT(log_info, "[client rejoinroom]client-connect size:%u.server:%s:%u.", client_conn_set.size(), m_ipaddr.c_str(), m_port);

		std::set<unsigned int>::iterator iter = client_conn_set.begin();
		for (; iter != client_conn_set.end(); ++iter)
		{
			unsigned int client_connid = *iter;
			connection_ptr pConn_This = CGlobalSetting::app_->client_session_manager_->find_client_map(client_connid);
			if(!pConn_This)
			{
				LOG_PRINT(log_error, "client fd is closed.client connid:%d.server:%s:%u.", client_connid, m_ipaddr.c_str(), m_port);
			}
			else if(pConn_This->connection_id() != client_connid)
			{
				LOG_PRINT(log_error, "handle_message() err! client session_id not equal![old connid:%d, new connid:%d]", client_connid, pConn_This->connection_id());
			}
			else if(pConn_This->session_status() == CClientConnection::en_session_status_connected)  
			{
				pConn_This->rejoinroom(pConn_This->getroomid(), pConn_This->getuserid());
			}
		}
	}
}

void CRoomsvrClient::handle_broadcast_msg(const char * msg, int len)
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

	SL_ByteBuffer buff(nMsgLen2);
	COM_MSG_HEADER * pOutMsg = (COM_MSG_HEADER *)buff.buffer();
	memcpy(pOutMsg, in_msg, SIZE_IVM_HEADER);
	memcpy(pOutMsg->content, pData, nDataLen2);
	pOutMsg->length = nMsgLen2;
	buff.data_end(pOutMsg->length);

	if (0 == pGateMask->param5)
	{
		/* means broadcast all connects online
			client devtype == pGateMask->param1 && 
						 0 == pGateMask->param2 && 
		    BROADCAST_TYPE == pGateMask->param3 && 
		    BROADCAST_TYPE == pGateMask->param4 &&
		                 0 == pGateMask->param5
		*/
		byte devtype = byte(pGateMask->param1);
		CGlobalSetting::app_->client_session_manager_->broadcast_all_client(devtype, buff);
		return;
	}

	if (BROADCAST_TYPE == pGateMask->param5 && BROADCAST_TYPE == pGateMask->param6)
	{
		/* means broadcast all room all connects 
		  BROADCAST_TYPE == pGateMask->param3 && 
		  BROADCAST_TYPE == pGateMask->param4 &&
		  BROADCAST_TYPE == pGateMask->param5 && 
		  BROADCAST_TYPE == pGateMask->param6 &&
		*/
		LOG_PRINT(log_debug, "Broadcast msg from server:%s:%u,maincmd:%u,subcmd:%u,need to broadcast all connects in all rooms.", m_ipaddr.c_str(), m_port, maincmd, subcmd);
		CGlobalSetting::app_->client_session_manager_->broadcast_all_room_all_connects(0, buff);
	}
	else
	{
		/* means broadcast all connects in one room except connid if connid is not 0
		          connid == pGateMask->param2 && 
		  BROADCAST_TYPE == pGateMask->param3 && 
		  BROADCAST_TYPE == pGateMask->param4 &&
		          roomid == pGateMask->param5 && 
		*/
		unsigned int roomid = pGateMask->param5;
		unsigned int connid = pGateMask->param2;

		if(Sub_Vchat_RoomKickoutUserNoty == in_msg->subcmd)
		{
			//kick out need to save connid to call del_user_connid but need to reset param2 to broadcast all connects in one room.
			pGateMask->param2 = 0;
		}

		LOG_PRINT(log_debug, "Broadcast msg from server:%s:%u,roomid:%u,client connid:%u,maincmd:%u,subcmd:%u.", m_ipaddr.c_str(), m_port, roomid, pGateMask->param2, maincmd, subcmd);
		CGlobalSetting::app_->client_session_manager_->broadcast_room_all_connects(roomid, pGateMask->param2, buff);
		if(Sub_Vchat_RoomKickoutUserNoty == in_msg->subcmd)
		{
			CMDUserKickoutRoomInfo_t * pRes = (CMDUserKickoutRoomInfo_t *)(in_msg->content + SIZE_IVM_CLIENTGATE);
			CGlobalSetting::app_->room_mgr_->del_user_connid(pRes->vcbid, pRes->toid, connid);
		}
	}	
}

void CRoomsvrClient::print_specail_cmd(const char * msg, int len)
{
	if (!msg || !len)
	{
		return;
	}

	DEF_IVM_HEADER(in_msg, msg);
	DEF_IVM_CLIENTGATE(pGateMask, msg);

	if(Sub_Vchat_RoomKickoutUserNoty == in_msg->subcmd)
	{
		CMDUserKickoutRoomInfo_t * pRes = (CMDUserKickoutRoomInfo_t *)(in_msg->content + SIZE_IVM_CLIENTGATE);
		LOG_PRINT(log_info, "[client connid:%llu,param3:%llu,param4:%llu][userid:%d,roomid:%d,reasonid:%d]receive kick out room request msg from roomsvr:%s:%u",
			pGateMask->param2, pGateMask->param3, pGateMask->param4, pRes->toid, pRes->vcbid, pRes->resonid, m_ipaddr.c_str(), m_port);
	}

	if(Sub_Vchat_RoomUserNoty == in_msg->subcmd)
	{
		CMDRoomUserInfo_t * pRes = (CMDRoomUserInfo_t *)(in_msg->content + SIZE_IVM_CLIENTGATE);
		LOG_PRINT(log_info, "[client connid:%llu,param3:%llu,param4:%llu][userid:%d,roomid:%d]receive user come room notity msg from roomsvr:%s:%u",
			pGateMask->param2, pGateMask->param3, pGateMask->param4, pRes->userid, pRes->vcbid, m_ipaddr.c_str(), m_port);
	}

	if(Sub_Vchat_RoomUserExitNoty == in_msg->subcmd)
	{
		CMDUserExitRoomInfo_ext_t * pRes = (CMDUserExitRoomInfo_ext_t *)(in_msg->content + SIZE_IVM_CLIENTGATE);
		LOG_PRINT(log_info, "[client connid:%llu,param3:%llu,param4:%llu][userid:%d,roomid:%d]receive user exit room notity msg from roomsvr:%s:%u",
			pGateMask->param2, pGateMask->param3, pGateMask->param4, pRes->userid, pRes->vcbid, m_ipaddr.c_str(), m_port);
	}

	if(Sub_Vchat_HitGoldEgg_ToClient_Noty == in_msg->subcmd)
	{
		CMDHitGoldEggClientNoty_t * pRes = (CMDHitGoldEggClientNoty_t *)(in_msg->content + SIZE_IVM_CLIENTGATE);
		LOG_PRINT(log_info, "[client connid:%llu,param3:%llu,param4:%llu][userid:%d,roomid:%d]receive hit gold egg response msg from roomsvr:%s:%u.",
			pGateMask->param2, pGateMask->param3, pGateMask->param4, pRes->userid, pRes->vcbid, m_ipaddr.c_str(), m_port);
	}

	if(Sub_Vchat_JoinRoomResp == in_msg->subcmd)
	{
		CMDJoinRoomResp_t * pRes = (CMDJoinRoomResp_t *)(in_msg->content + SIZE_IVM_CLIENTGATE);
		LOG_PRINT(log_info, "[client connid:%llu,param3:%llu,param4:%llu][userid:%d,roomid:%d]receive join room response msg from roomsvr:%s:%u.",
			pGateMask->param2, pGateMask->param3, pGateMask->param4, pRes->userid, pRes->vcbid, m_ipaddr.c_str(), m_port);
	}

	if(Sub_Vchat_SetMicStateNotify == in_msg->subcmd)
	{
		CMDUserMicState_t * pRes = (CMDUserMicState_t *)(in_msg->content + SIZE_IVM_CLIENTGATE);
		LOG_PRINT(log_info, "[client connid:%llu,param3:%llu,param4:%llu][toid:%d,roomid:%d,micstate:%d][setmicstate]set mic state response msg from roomsvr:%s:%u.",
			pGateMask->param2, pGateMask->param3, pGateMask->param4, pRes->toid, pRes->vcbid, (int)pRes->micstate, m_ipaddr.c_str(), m_port);
	}
}

void CRoomsvrClient::notify_svr_exitroom(unsigned int roomid, unsigned int userid, ClientGateMask_t * pGate)
{
	if (!roomid || !userid || !pGate)
	{
		return;
	}

	char szBuf[128] = {0};
	COM_MSG_HEADER * pHead = (COM_MSG_HEADER *)szBuf;
	pHead->version = MDM_Version_Value;
	pHead->checkcode = 0;
	pHead->maincmd = MDM_Vchat_Room;
	pHead->subcmd = Sub_Vchat_RoomUserExitReq;

	ClientGateMask_t * pClientGate = (ClientGateMask_t *)(pHead->content);
	memcpy(pClientGate, pGate, sizeof(ClientGateMask_t));

	CMDUserExitRoomInfo_t * pData = (CMDUserExitRoomInfo_t *)(pHead->content + SIZE_IVM_CLIENTGATE);
	memset(pData, 0, sizeof(CMDUserExitRoomInfo_t));
	pData->vcbid = roomid;
	pData->userid = userid;

	pHead->length = SIZE_IVM_HEADER + SIZE_IVM_CLIENTGATE + sizeof(CMDUserExitRoomInfo_t);

	SL_ByteBuffer buff;
	buff.write(szBuf, pHead->length);

	write_message(buff);
}

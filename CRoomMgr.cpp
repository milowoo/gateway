/*
 * CRoomMgr.cpp
 *
 *  Created on: Apr 23, 2016
 *      Author: root
 */

#include "CRoomMgr.h"
#include "CLogThread.h"

CRoomMgr::CRoomMgr()
{
	m_room_all_connect.clear();
}

CRoomMgr::~CRoomMgr()
{
	m_room_all_connect.clear();
}

void CRoomMgr::add_user_connid(unsigned int roomid, unsigned int userid, unsigned int connectid)
{
	if (!roomid || !connectid || !userid)
	{
		return;
	}

	boost::mutex::scoped_lock lock(room_mutex_);

	std::map<unsigned int, USER_CONNID_MAP >::iterator iter_room = m_room_all_connect.find(roomid);
	if (m_room_all_connect.end() == iter_room)
	{
		CONNECT_SET connects;
		connects.insert(connectid);
		USER_CONNID_MAP user_conn_map;
		user_conn_map.insert(std::make_pair(userid, connects));
		m_room_all_connect.insert(std::make_pair(roomid, user_conn_map));
	}
	else
	{
		USER_CONNID_MAP::iterator iter_user = iter_room->second.find(userid);
		if (iter_room->second.end() == iter_user)
		{
			CONNECT_SET connects;
			connects.insert(connectid);
			iter_room->second.insert(std::make_pair(userid, connects));
		}
		else
		{
			iter_user->second.insert(connectid);
		}
	}

	LOG_PRINT(log_debug, "add_user_connid:roomid:%u,userid:%u,client connid:%u.", roomid, userid, connectid);
}

void CRoomMgr::del_user_connid(unsigned int roomid, unsigned int userid, unsigned int connectid)
{
	if (!roomid || !connectid || !userid)
	{
		return;
	}

	boost::mutex::scoped_lock lock(room_mutex_);

	std::map<unsigned int, USER_CONNID_MAP >::iterator iter_room = m_room_all_connect.find(roomid);
	if (m_room_all_connect.end() != iter_room)
	{
		USER_CONNID_MAP::iterator iter_user = iter_room->second.find(userid);
		if (iter_room->second.end() != iter_user)
		{
			iter_user->second.erase(connectid);

			LOG_PRINT(log_debug, "del_user_connid:roomid:%u,userid:%u,client connid:%u.", roomid, userid, connectid);

			if (iter_user->second.empty())
			{
				iter_room->second.erase(userid);
			}
		}

		if (iter_room->second.empty())
		{
			m_room_all_connect.erase(roomid);
		}
	}
}

void CRoomMgr::get_user_connids(unsigned int roomid, std::set<unsigned int> & connectid_set)
{
	connectid_set.clear();
	if (!roomid)
	{
		return;
	}

	boost::mutex::scoped_lock lock(room_mutex_);
	std::map<unsigned int, USER_CONNID_MAP >::iterator iter_room = m_room_all_connect.find(roomid);
	if (m_room_all_connect.end() != iter_room)
	{
		USER_CONNID_MAP & user_connids = iter_room->second;
		USER_CONNID_MAP::iterator iter_user = user_connids.begin();
		for (; iter_user != user_connids.end(); ++iter_user)
		{
			connectid_set.insert(iter_user->second.begin(), iter_user->second.end());
		}
	}
}

void CRoomMgr::get_all_user_connids(std::set<unsigned int> & connectid_set)
{
	connectid_set.clear();

	boost::mutex::scoped_lock lock(room_mutex_);
	std::map<unsigned int, USER_CONNID_MAP >::iterator iter_room = m_room_all_connect.begin();
	for (; iter_room != m_room_all_connect.end(); ++iter_room)
	{
		USER_CONNID_MAP & user_connids = iter_room->second;
		USER_CONNID_MAP::iterator iter_user = user_connids.begin();
		for (; iter_user != user_connids.end(); ++iter_user)
		{
			connectid_set.insert(iter_user->second.begin(), iter_user->second.end());
		}		
	}
}

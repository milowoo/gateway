/*
 * CRoomMgr.h
 *
 *  Created on: Apr 23, 2016
 *      Author: root
 */

#ifndef __CROOMMGR_H__
#define __CROOMMGR_H__

#include <set>
#include <map>
#include <boost/thread/mutex.hpp>

typedef std::set<unsigned int> CONNECT_SET;
typedef std::map<unsigned int, CONNECT_SET > USER_CONNID_MAP;

class CRoomMgr
{
public:
	CRoomMgr();

	~CRoomMgr();

	void add_user_connid(unsigned int roomid, unsigned int userid, unsigned int connectid);

	void del_user_connid(unsigned int roomid, unsigned int userid, unsigned int connectid);

	void get_user_connids(unsigned int roomid, std::set<unsigned int> & connectid_set);

	void get_all_user_connids(std::set<unsigned int> & connectid_set);

private:

	boost::mutex room_mutex_;

	//key:roomid, value: user id connect id map
	std::map<unsigned int, USER_CONNID_MAP > m_room_all_connect;
};

#endif /* __CROOMMGR_H__ */

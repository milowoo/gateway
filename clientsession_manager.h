
#ifndef __CLIENT_SESSION_MANAGER_HH_20150608__
#define __CLIENT_SESSION_MANAGER_HH_20150608__

#include <list>
#include <set>
#include <boost/thread/mutex.hpp>
#include <boost/smart_ptr/detail/spinlock.hpp>
#include "client_session.hpp"
#include "cmd_vchat.h"
#include "tcp_client.hpp"

class CClientSessionManager
{
public:
	CClientSessionManager(void);

	virtual ~CClientSessionManager(void);

	void del_client(connection_ptr connection);

	void update_client_map(connection_ptr connection);

	connection_ptr find_client_map(unsigned int connect_id);

	//send msg to client connection by connID,0 means success, others means fail.
	int send_msg_to_client_by_connID(unsigned int connect_id, SL_ByteBuffer & buff);

    unsigned int next_sessionid();
    
	connection_ptr find_user_conn(unsigned int iduser, byte nmoblie, unsigned int nlogintime);

	void post_user_login(unsigned int userid, byte nmobile, unsigned int nlogintime);

	void post_user_login_bat(std::vector<CMDLogonClientInf_t> &vecClientInf, CTcpClient_ptr connptr);

	void post_all_user_login();

	void kickout_user_not(CMDLogonClientInf_t * cCientInf);

	void noticelogout(unsigned int userid, byte nmobile, unsigned int nlogintime);

	void setuserconn(unsigned int userid, byte nmobile, unsigned int nlogintime, unsigned int idconn);

	unsigned int get_last_alarmnotify_time(){return last_alarmnotify_time_;}

	void set_last_alarmnotify_time(unsigned int t){last_alarmnotify_time_ = t;}

    void broadcast_all_client(byte termtype, SL_ByteBuffer & buff);

	void broadcast_room_all_connects(unsigned int roomid, unsigned int own_id, SL_ByteBuffer & buff);

	void broadcast_all_room_all_connects(unsigned int own_id, SL_ByteBuffer & buff);

	void broadcast_user_all_connects(unsigned int userid, SL_ByteBuffer & buff);

private:

	void getallconnptr(std::vector<connection_ptr> & vecconn);

	boost::mutex sessionid_mutex_;
	unsigned int next_sessionid_;

	boost::mutex client_session_mutex_;
	
	//key:client connect id, value:connection_ptr
	std::map<unsigned int, connection_ptr > session_map_;

	//key:userid_nmobile_logintime, value:client connect id
	std::map<std::string, unsigned int> m_mapuser;

	//key:userid, value:set of client connect id
	std::map<unsigned int, std::set<unsigned int> > m_user_connid_map;

	unsigned int last_alarmnotify_time_;
};

#endif  //__CLIENT_SESSION_MANAGER_HH_20150608__



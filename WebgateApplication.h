

#ifndef __WEBGATE_SERVER_APPLICATION_HH__
#define __WEBGATE_SERVER_APPLICATION_HH__

#include "client_session.hpp"
#include "clientsession_manager.h"
#include "svrsession_manager.h"
#include "tcp_client.hpp"
#include "SL_Log.h"
#include "CCmdGuideMgr.h"
#include "CRoomMgr.h"

class WebgateApplication
{
public:
	WebgateApplication();

	~WebgateApplication();

	CClientSessionManager* client_session_manager_;

	CSvrSessionManager * svr_session_manager_;

	CCmdGuideMgr * cmdguide_mgr_;

	CRoomMgr * room_mgr_;

	std::string change_type_to_svrname(const unsigned int svr_type);

	SL_Log log_;
};


#endif //__WEBGATE_SERVER_APPLICATION_HH__



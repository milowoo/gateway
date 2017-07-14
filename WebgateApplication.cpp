
#include "WebgateApplication.h"

WebgateApplication::WebgateApplication()
:client_session_manager_(0),
svr_session_manager_(0),
cmdguide_mgr_(0)
{

}

WebgateApplication::~WebgateApplication()
{

}

std::string WebgateApplication::change_type_to_svrname(const unsigned int svr_type)
{
	std::string ret = "";
	switch(svr_type)
	{
	case e_logonsvr_type:
		{
			ret = "logonsvr";
		}
		break;
	case e_hallsvr_type:
		{
			ret = "hallsvr";
		}
		break;
	case e_roomsvr_type:
		{
			ret = "roomsvr";
		}
		break;
	case e_roommgr_type:
		{
			ret = "roommgr";
		}
		break;
	case e_roomusermgr_type:
		{
			ret = "roomusermgr";
		}
		break;
	case e_consumesvr_type:
		{
			ret = "consumesvr";
		}
		break;
	case e_roommisc_type:
		{
			ret = "roommisc";
		}
		break;
	case e_roomchat_type:
		{
			ret = "roomchat";
		}
		break;
	default:
		break;
	}

	return ret;
}


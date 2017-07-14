/*
 * usermgrsvr_client.h
 *
 *  Created on: Apr 15, 2016
 *      Author: root
 */

#ifndef __USERMGR_CLIENT_H__
#define __USERMGR_CLIENT_H__
#include "tcp_client.hpp"
#include "message_comm.h"

class CUsermgrClient: public CTcpClient
{
public:
	explicit CUsermgrClient(boost::asio::io_service & io_service);

	~CUsermgrClient();

protected:

	virtual int handle_message(const char * pdata, int msglen);

	virtual void send_keeplive_command();
};

#endif /* __USERMGR_CLIENT_H__ */

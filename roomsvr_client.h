/*
 * roomsvr_client.h
 *
 *  Created on: Apr 15, 2016
 *      Author: root
 */

#ifndef __ROOMSVR_CLIENT_H__
#define __ROOMSVR_CLIENT_H__
#include "tcp_client.hpp"
#include "message_comm.h"

class CRoomsvrClient: public CTcpClient
{
public:
	explicit CRoomsvrClient(boost::asio::io_service & io_service);

	~CRoomsvrClient();

protected:

	virtual int handle_message(const char * msg, int len);

	virtual void post_close_process();

	void client_rejoinroom();

	virtual void send_hello_command();

private:

	void handle_broadcast_msg(const char * msg, int len);

	void print_specail_cmd(const char * msg, int len);

	void notify_svr_exitroom(unsigned int roomid, unsigned int userid, ClientGateMask_t * pGate);
};

#endif /* __ROOMSVR_CLIENT_H__ */

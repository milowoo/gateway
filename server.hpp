
#ifndef __SERVER_HH_20150606__
#define __SERVER_HH_20150606__

#include <boost/asio.hpp>
#include <string>
#include <vector>
#include <list>
#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>
#include "client_session.hpp"
#include "io_service_pool.h"

//The top-level class of the Login server.
class CServer
	:private boost::noncopyable
{
public:
	explicit CServer(const std::string& address, const std::string& port,
		std::size_t io_service_pool_size);

	void run();
	void serverid(int id) {server_id_ =id; }
	int  serverid(void) {return server_id_; }

private:
	void start_accept();
	void handle_accept(connection_ptr session,
		const boost::system::error_code& e);
	void handle_stop();

	io_service_pool io_service_pool_;
	//boost::asio::signal_set signals_;
	boost::asio::ip::tcp::acceptor acceptor_;
	int server_id_;

};

typedef boost::shared_ptr<CServer> server_ptr;
typedef std::list<server_ptr> server_list;


#endif //__SERVER_HH_20150606__


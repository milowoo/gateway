
//server.cpp

#include "server.hpp"
#include <iostream>
#include <boost/bind.hpp>
#include "CLogThread.h"
#include "GlobalSetting.h"
#include "clientsession_manager.h"

using boost::asio::ip::tcp;

CServer::CServer(const std::string& address, const std::string& port, std::size_t io_service_pool_size)
:io_service_pool_(io_service_pool_size),
acceptor_(io_service_pool_.get_io_service()),
server_id_(0)
{
	//Open the acceptor with the option to reuse the address.
	tcp::resolver resolver(acceptor_.get_io_service());
	tcp::resolver::query query(address, port);
	tcp::resolver::iterator endpoint_iter = resolver.resolve(query);
	tcp::endpoint endpoint =*endpoint_iter;
	acceptor_.open(endpoint.protocol());
	acceptor_.set_option(tcp::acceptor::reuse_address(true));
	acceptor_.bind(endpoint);
	acceptor_.listen();

	LOG_PRINT(log_info, "######################################");
	LOG_PRINT(log_info, "webgate start listen[%s:%d]", endpoint.address().to_string().c_str(), endpoint.port());

	start_accept();
}

void CServer::run()
{
	io_service_pool_.run();
}

void CServer::start_accept()
{
	connection_ptr conn(new CClientConnection(io_service_pool_.get_io_service()));
	acceptor_.async_accept(conn->socket(),
		boost::bind(&CServer::handle_accept, this, conn, boost::asio::placeholders::error));
}

void CServer::handle_accept(connection_ptr session, 
							const boost::system::error_code& e)
{
	if(!e)
	{
		session->client_manager_ = CGlobalSetting::app_->client_session_manager_;
		session->start();
	}
	else
	{
		LOG_PRINT(log_info, "CServer::handle_accept() error:%s.",boost::system::system_error(e).what());
	}
	start_accept();
}

void CServer::handle_stop()
{
	io_service_pool_.stop();
}


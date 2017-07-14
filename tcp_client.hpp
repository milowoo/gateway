
#ifndef _TCP_CLIENT_HH_20150609__
#define _TCP_CLIENT_HH_20150609__

#include <set>
#include <deque>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/asio/deadline_timer_service.hpp>
#include <boost/noncopyable.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/enable_shared_from_this.hpp>
#include "SL_ByteBuffer.h"
#include "client_session.hpp"

using boost::asio::deadline_timer;
using boost::asio::ip::tcp;

class CTcpClient
	:public boost::enable_shared_from_this<CTcpClient>,
	private boost::noncopyable
{
public:
	explicit CTcpClient(boost::asio::io_service& io_service);

	virtual ~CTcpClient(){};

	void start();

	void stop();

	void start_connect(const char * szip, int port);

	void connect();

	void close();

	tcp::socket& socket() {	return socket_;	}

	bool is_connected() {return (connect_status_== en_connect_status_connected);}

	void write_message(SL_ByteBuffer& message, bool bforced = false);

	void write_message(char* pdata, int datalen, bool bforced = false);
	
	void get_all_connid(std::set<unsigned int> & ret);

	unsigned int getconn_num();

	void clear_conn_num();
	
	void addconn_id(unsigned int idconn);
	
	void delconn_id(unsigned int idconn);

	void setconn_ssn(unsigned int issn){conn_ssn_ = issn;}

	unsigned int getconn_ssn(){return conn_ssn_;}

    void setsvr_type(int type);

    int getsvr_type();

	enum {
		en_connect_status_disconnected = 0,
		en_connect_status_connecting = 1,
		en_connect_status_connected = 2,
	};

	void setgateid(uint16 idgate){m_ngateid = idgate;}

	std::string get_svr_ipaddr(){return m_ipaddr;}

	unsigned int get_svr_poirt(){return m_port;}

protected:
	void send_message(SL_ByteBuffer& message, bool bforced);

	void send_keeplive_command();

	virtual void send_hello_command();

	void handle_connect(const boost::system::error_code & e);

	void handle_timeout(const boost::system::error_code & e);

	void handle_read(const boost::system::error_code & e, std::size_t byte_transferred);

	void handle_write(const boost::system::error_code & e, std::size_t byte_transferred);

	int parse_message();

	virtual int handle_message(const char* msg, int len);

	void handle_cast_user_connects_msg(const char * msg, int len);

	//broadcast all clients which connect on one server
	void handle_cast_clients_on_one_svr(const char * msg, int len);

	void do_close();

	virtual void post_close_process(){return;}

    //void post_user_login(uint16 subcmd, char * respData, CClientConnection * pConn);

	boost::mutex add_connd_id_mutex_;
	
	std::set<unsigned int> m_setconnid;

	boost::asio::io_service& io_service_;

	tcp::socket socket_;

	enum {
		en_msgbuffersize = 1024*64,
		en_msgmaxsize = 1024*32,
	};

	//read message buffer
	char recv_buffer_[en_msgbuffersize];
	int recv_buffer_remainlen_;

	//send message queue
	std::deque<SL_ByteBuffer > send_messages_;
	boost::mutex send_messages_mutex_;

	unsigned int last_alarmnotify_time_;
	
	int connect_status_;
	deadline_timer deadline_;
	unsigned int last_activetime_;
	unsigned int begin_connecttime_;
	time_t last_queue_size_time_;
	tcp::endpoint endpoint_;

	//server connect id
	unsigned int conn_ssn_;

	//server type
	int m_svr_type;

	std::string m_svr_name;

	std::string m_ipaddr;

	unsigned int m_port;

	uint16 m_ngateid;

	time_t disconnect_alarm_time;
};

typedef boost::shared_ptr<CTcpClient > CTcpClient_ptr;

#endif //_TCP_CLIENT_HH_20150609__


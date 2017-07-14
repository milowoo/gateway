
#ifndef __CLIENT_SESSION_HPP__
#define __CLIENT_SESSION_HPP__

#include <deque>
#include <boost/asio.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/array.hpp>
#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/enable_shared_from_this.hpp>
#include "yc_datatypes.h"
#include "SL_ByteBuffer.h"

#define MAGIC_KEY "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

typedef std::map<std::string, std::string> HEADER_MAP;

using boost::asio::deadline_timer;
using boost::asio::ip::tcp;

class CClientSessionManager;

//represents a single connection from a client
class CClientConnection
	:public boost::enable_shared_from_this<CClientConnection>,
	private boost::noncopyable
{
public:

	//Construct a connection with the given io_service.
	explicit CClientConnection(boost::asio::io_service & io_service);

	virtual ~CClientConnection();

	tcp::socket& socket();

	//Start the first asynchronous operation for the connection.
	void start();

	unsigned int connection_id() {return connection_id_;}
	
	int session_status() { return session_status_; }
	
	bool isstop() {return stopped_; }
	
	std::string remote_ip() { return remote_ip_; }
	
	int remote_port() { return remote_port_; }

	void write_message(SL_ByteBuffer & slByte);
	
	void write_message(const char * pdata, int msglen);
	
	void close();

	void setlastlogintime(){last_login_time = time(NULL);}

	unsigned int getlastlogintime(){return last_login_time;}

	void setuserid(unsigned int iduser){userid = iduser;}

	unsigned int getuserid(){return userid;}

	byte getmobile(){return m_nmobile;}

	void setroomid(unsigned int idroom){m_roomid = idroom;}

	unsigned int getroomid(){return m_roomid;}

	void rejoinroom(unsigned int roomid, unsigned int userid);

	bool client_exit_room(){return m_exitroom;}

private:

	void do_close();
	
	void send_message(SL_ByteBuffer & slbuf);

	void handle_read(const boost::system::error_code & e, std::size_t bytes_transferred);
	
	void handle_write(const boost::system::error_code & e, std::size_t bytes_transferred);
	
	void check_deadline(const boost::system::error_code & e);

	int parse_message();

	int parse_json_to_msg(const char * pdata, int msglen);
	
	virtual int handle_message(const char* pdata, int msglen);
	
	void clear_data();
	
	int build_netmsg_svr(char * szBuf, int nBufLen, int mainCmdId, int subCmdId, void * pData, int pDataLen);

	void notify_svr_clienttimeout();

	void notify_svr_clientexit();

	void notify_svr_exceptexit();

	//void notify_svr_clientclosesocket();

	void notify_svr_exitroom(unsigned int roomid, unsigned int userid);

	void notify_svr_exceptexitroom(unsigned int roomid, unsigned int userid);

	void notify_svr_kickoutroom(unsigned int roomid, unsigned int userid, int reasonid);

	int handle_roomsvr_msg(char * data, const std::string & svr_ip, unsigned int svr_port);

	void handle_ping_msg(char * ping);

	void handle_hello_msg(char * hello);

	std::string get_distributed_key_msg(char * in_msg);

	void print_specail_cmd(char * data, const std::string & svr_ip, unsigned int svr_port);

	void remove_svr_connect_map(char * in_msg);

	///////////////////////////websocket protocol new interface//////////////////////////////////////////////////////

	int fetch_http_info();

	std::string parse_str();

	int handshark();

	int fetch_fin(char * msg, int & pos);

	int fetch_opcode(char * msg, int & pos);

	int fetch_mask(char * msg, int & pos);

	int fetch_masking_key(char * msg, int & pos);

	int fetch_payload_length(char * msg, int & pos, unsigned long & payload_length_);

	int fetch_payload(char * msg, int & pos, char * payload_, unsigned int payload_length_, unsigned int max_length);

	void format_write_buf(char * in_data, unsigned int in_len, char * output);

	unsigned int calc_new_len(unsigned int in_len);

public:
	enum {
		en_session_status_unkown    = 0,
		en_session_status_connected = 1,
		en_session_status_ready     = 2,
		en_session_status_needclose = 3,
	};

	CClientSessionManager * client_manager_;

private:
	enum {
		en_msgbuffersize     = 1024*64,
		en_msgmaxsize        = 1024*32,
		en_checkactivetime   = 5,   //s
		en_checkkeeplivetime = 20,  //s
	};

	volatile bool stopped_;
	
	tcp::socket   socket_;
	unsigned int  connection_id_;

	//read message buffer.
	char recv_buffer_[en_msgbuffersize];
	int  recv_buffer_remainlen_;

	//send message queue
	std::deque<SL_ByteBuffer > send_messages_;
	boost::mutex send_messages_mutex_;

	deadline_timer deadline_;
	unsigned int last_activetime_;
	
	int session_status_;
	std::string remote_ip_;
	int remote_port_;

	unsigned int userid;           //user ID
	unsigned int m_roomid;         //room ID
	unsigned int last_login_time;  //last login time
	byte   m_nmobile;              //client login devtype

	bool   m_blogon;               //mark this client session has logon or not.
	bool   m_exitroom;             //mark this client session has exit room.

	unsigned int m_micuserid;      //roomsvr mic state need this.
	char   m_micindex;             //roomsvr mic state need this.
	char   m_micstate;             //roomsvr mic state need this.

	HEADER_MAP m_header_map_;      //websocket protocol
	unsigned char fin_;            //websocket protocol
	unsigned char opcode_;         //websocket protocol
	unsigned char mask_;           //websocket protocol
	unsigned char masking_key_[4]; //websocket protocol
};

typedef boost::shared_ptr<CClientConnection> connection_ptr;

#endif //__CLIENT_SESSION_HPP__

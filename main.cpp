
#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/thread.hpp>
#include <boost/lexical_cast.hpp>
#include "server.hpp"
#include "tcp_client.hpp"
#include "roomsvr_client.h"
#include "usermgr_client.h"
#include "GlobalSetting.h"
#include "CLogThread.h"
#include "Config.h"
#include "split.h"

static const std::string dirname (const std::string &pathname)
{
	std::string::size_type idx = pathname.rfind("/");
	if (idx == std::string::npos)
		return std::string ("./");

	return pathname.substr (0, idx +1);
}

int main(int argc, char* argv[])
{
	try
	{
		bool daemonMode = false;
		char binPath[256],logPath[256],confPath[256],logfile[256];
		sprintf(binPath, "%s", dirname(argv[0]).c_str());
		sprintf(logPath, "%s/../log", binPath);

		if(argc == 3 && strcmp(argv[2],"-d") == 0)
		{
			daemonMode = true;
		}
		
		if(argc != 2 && argc != 3)
		{
			std::cerr << "Usage: webgate port [-d]";
			return -1;
		}

		//Daemon mode running
		signal (SIGPIPE, SIG_IGN );
		signal (SIGSEGV, SIG_IGN );
		signal (SIGALRM, SIG_IGN );
		if (daemonMode) 
		{
			daemon (1, 0);
		}

        //Load webgate config
		memset(confPath, 0, sizeof(confPath));
		sprintf(confPath, "%s/../etc/webgate.conf", binPath);
	    std::string conf_file(confPath);
	    Config config(conf_file);
        int line = 0;
	    if(!config.load(line))
        {
		    std::cerr << "load configure file webgate.conf failed\n";
		    exit(1);
	    }

		//new application
        WebgateApplication * app = new WebgateApplication();
		CGlobalSetting::app_ = app;

		uint16 gateid = config.getInt("gateid", std::string(argv[1]));
		if (!gateid)
		{
			LOG_PRINT(log_error, "config file has no gate_id of %s.", argv[1]);
			exit(1);
		}

        //log init
        int nlogmode = config.getInt("log", "logmode");;
        int nloglevel = config.getInt("log", "loglevel");
        int nusesyslog = config.getInt("log", "usesyslog");
        sprintf(logfile, "webgate_%d_log", atoi(argv[1]));
        app->log_.init(nlogmode,nloglevel,logPath,logfile,"txt",1);
        CLogThread::Instance(&app->log_, nusesyslog);

        //load cmdcode config and init application
        std::string cmdconfig = std::string(binPath) + "/../etc/";
        app->cmdguide_mgr_ = new CCmdGuideMgr(cmdconfig);
        app->cmdguide_mgr_->loadConfig();
		app->cmdguide_mgr_->loadCmdParamConfig();
		app->client_session_manager_ = new CClientSessionManager();
		app->svr_session_manager_ = new CSvrSessionManager();
        app->room_mgr_ = new CRoomMgr();
		
        //noticesvr config
        std::string strnoticeip = config.getString("noticesvr", "ip");
        int nnoticeport = config.getInt("noticesvr", "port");
        int nalarmqueuesize = config.getInt("noticesvr", "alarmqueuesize");
        CAlarmNotify * alarmnotify = new CAlarmNotify(strnoticeip, nnoticeport); 
        CGlobalSetting::alarmnotify_ = alarmnotify;
        if(nalarmqueuesize)
        {
            CGlobalSetting::alarm_queuesize_ = nalarmqueuesize;
        }

		//Initialize the tcp_server
		std::size_t num_threads = config.getInt("self", "workthread");
		CServer server("0.0.0.0", argv[1], num_threads);
		server.serverid(atoi(argv[1]));
        CGlobalSetting::listen_port_ = atoi(argv[1]);
		unsigned int clienttimeout = config.getInt("self", "client_timeout");
		if (clienttimeout)
		{
			CGlobalSetting::client_timeout_ = clienttimeout;
		}

		unsigned int on_mic_clienttimeout = config.getInt("self", "on_mic_client_timeout");
		if (on_mic_clienttimeout)
		{
			CGlobalSetting::on_mic_client_timeout_ = on_mic_clienttimeout;
		}

		io_service_pool io_service_pool_(num_threads);

        std::string svr_names = config.getString("server", "svr_name");
        std::list<std::string> svr_lst;
        splitStrToLst(svr_names, ',', svr_lst);
        std::list<std::string>::iterator iter = svr_lst.begin();
        for (; iter != svr_lst.end(); ++iter)
        {
            std::string & svr_name = *iter;
            int svr_type = config.getInt(svr_name, "svr_type");
            int svr_num = config.getInt(svr_name, "svrnum");
		    for (int i = 0; i < svr_num; i++)
		    {
			    char csvr_info[25] = {0};
			    sprintf(csvr_info, "svr_%d", i+1);
			    std::string strsvr_info = config.getString(svr_name, csvr_info);

				if (strsvr_info.empty())
				{
					LOG_PRINT(log_warning, "server inform is empty,please check config file.");
					continue;
				}

				std::vector<std::string> svr_vect = split(strsvr_info,":");
				if (svr_vect.size() != 2)
				{
					LOG_PRINT(log_warning, "server inform format is wrong.%s,,please check config file.", strsvr_info.c_str());
					continue;
				}
	            
				std::string strsvr_ip = svr_vect[0];
				int nsvr_port = atoi(svr_vect[1].c_str());

			    if (0 == nsvr_port || strsvr_ip.empty())
                {
					LOG_PRINT(log_warning, "server inform is wrong.%s,,please check config file.", strsvr_info.c_str());
                    continue;
                }

			    CTcpClient_ptr svr_client_;
				if (e_roomsvr_type <= svr_type && svr_type <= e_roomchat_type)
				{
					svr_client_.reset(new CRoomsvrClient(io_service_pool_.get_io_service()));
				}
				else
				{
					svr_client_.reset(new CTcpClient(io_service_pool_.get_io_service()));
				}

				svr_client_->setgateid(gateid);
			    svr_client_->setconn_ssn(i+1);
			    svr_client_->start();
                svr_client_->setsvr_type(svr_type);
			    svr_client_->start_connect(strsvr_ip.c_str(), nsvr_port);
			    app->svr_session_manager_->add_svr_conn(svr_type, svr_client_);
		    }
        }

		boost::thread thread1(boost::bind(&io_service_pool::run, &io_service_pool_));
		//Run the tcp_server until stopped
		server.run();
		thread1.join();
	}
	catch(std::exception & e)
	{
		std::cerr << " exception: " << e.what() << std::endl;
	}
	return 0;
}

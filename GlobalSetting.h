
#ifndef __GLOBAL_SETTING_HH__
#define __GLOBAL_SETTING_HH__

#include "WebgateApplication.h"
#include "CLogThread.h"
#include "CAlarmNotify.h"

class CGlobalSetting
{
public:

	CGlobalSetting();

	virtual ~CGlobalSetting();

public:

	static WebgateApplication * app_;

	static CAlarmNotify * alarmnotify_;

	static int alarm_queuesize_;

	static int alarmnotify_interval_;

    static int listen_port_;
	static unsigned int client_timeout_;
	static unsigned int on_mic_client_timeout_;
};

#endif //__GLOBAL_SETTING_HH__


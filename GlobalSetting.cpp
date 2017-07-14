#include "GlobalSetting.h"

WebgateApplication * CGlobalSetting::app_ = 0;
CAlarmNotify * CGlobalSetting::alarmnotify_ = NULL;
int CGlobalSetting::alarm_queuesize_ = 10000;
int CGlobalSetting::alarmnotify_interval_ = 300;
int CGlobalSetting::listen_port_ = 0;
unsigned int CGlobalSetting::client_timeout_ = 180;
unsigned int CGlobalSetting::on_mic_client_timeout_ = 60;

CGlobalSetting::CGlobalSetting(void)
{
	
}

CGlobalSetting::~CGlobalSetting(void)
{
}


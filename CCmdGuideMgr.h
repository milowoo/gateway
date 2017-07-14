/*
 * CCmdGuideMgr.h
 *
 *  Created on: Mar 23, 2016
 *      Author: root
 */

#ifndef CCMDGUIDEMGR_H_
#define CCMDGUIDEMGR_H_

#include <map>
#include <string>
#include <list>
#include <set>
#include <boost/thread/mutex.hpp>
#include "Config.h"
#include "json/json.h"

typedef std::map<unsigned int, unsigned int> CMD_MIN_MAX;
typedef std::set<int> SVR_TYPE_SET;
typedef std::vector<std::string> PARAM_NAME_TYPE;

class CCmdGuideMgr
{
public:
	CCmdGuideMgr(std::string & configpath);

	~CCmdGuideMgr();

	void loadConfig();

    SVR_TYPE_SET getSvrType(unsigned int cmdcode);

	void loadCmdParamConfig();

	int fillCmdParam(const std::string & keyword, char * pContent, unsigned int maxlen, const Json::Value & jsonData);

	int fillJsonParam(const std::string & keyword, const char ** pBeginContent, const char * pEnd, Json::Value & jsonData);

private:

    //key:cmd, value:set of server type
    std::map<unsigned int, SVR_TYPE_SET> m_cmd_svr_map;

    //key:server type, value:map<min,max>
    std::map<int, CMD_MIN_MAX> m_svr_cmdrange_map;

    std::string m_configpath;

    boost::mutex cmd_svr_mutex;

    boost::mutex svr_cmdrange_mutex;

	std::map<std::string, PARAM_NAME_TYPE > m_cmd_param_map;

	Config * m_cmd_param;

	std::map<std::string, unsigned int> m_paramtype_size;
};

#endif /* CCMDGUIDEMGR_H_ */

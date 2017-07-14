/*
 * CCmdGuideMgr.cpp
 *
 *  Created on: Mar 23, 2016
 *      Author: root
 */

#include "CCmdGuideMgr.h"
#include "CLogThread.h"
#include "GlobalSetting.h"
#include "split.h"
#include <boost/locale/conversion.hpp>
#include <boost/locale/encoding.hpp>

CCmdGuideMgr::CCmdGuideMgr(std::string & configpath)
{
    m_configpath = configpath;
    m_cmd_svr_map.clear();
    m_svr_cmdrange_map.clear();
	m_cmd_param_map.clear();
	m_cmd_param = NULL;

	m_paramtype_size["uint8"] = sizeof(uint8);
	m_paramtype_size["uint32"] = sizeof(uint32);
	m_paramtype_size["int16"] = sizeof(int16);
	m_paramtype_size["int32"] = sizeof(int32);
	m_paramtype_size["char_64"] = 64;
	m_paramtype_size["char_32"] = 32;
	m_paramtype_size["byte"] = sizeof(byte);
	m_paramtype_size["uint16"] = sizeof(uint16);
	m_paramtype_size["int64"] = sizeof(int64);
	m_paramtype_size["char_128"] = 128;
	m_paramtype_size["uint64"] = sizeof(uint64);
	m_paramtype_size["float"] = sizeof(float);
	m_paramtype_size["gbk_char_32"] = 32;
	m_paramtype_size["gbk_char_64"] = 64;
	m_paramtype_size["variable_uint16"] = sizeof(uint16);
	m_paramtype_size["member_num_uint32"] = sizeof(uint32);
	m_paramtype_size["char"] = sizeof(char);

	//for variable_array, the length is variable, not fixed
	m_paramtype_size["gbk_variable_array"] = 0;
}

CCmdGuideMgr::~CCmdGuideMgr()
{
}

void CCmdGuideMgr::loadConfig()
{
    if(m_configpath.empty())
    {
        LOG_PRINT(log_debug, "config path is empty.");
        return;
    }

	std::string cmd_guide_config = m_configpath + "webgate_cmd.conf";
    LOG_PRINT(log_debug, "config path:%s", cmd_guide_config.c_str());

    Config config(cmd_guide_config);
    int line = 0;
    if(!config.load(line))
    {
    	LOG_PRINT(log_error, "config path:%s", cmd_guide_config.c_str());
	    return;
    }

    std::string svrnames = config.getString("server", "svr_name");
    std::list<std::string> svr_lst;
    splitStrToLst(svrnames, ',', svr_lst);
    if (svr_lst.empty())
    {
        LOG_PRINT(log_warning, "svr_name is empty.config path:%s", cmd_guide_config.c_str());
        return;
    }
    
    std::map<unsigned int, SVR_TYPE_SET > cmd_svr_map;
    std::map<int, CMD_MIN_MAX> svr_cmdrange_map;

    std::list<std::string>::iterator iter = svr_lst.begin();
    for (; iter != svr_lst.end(); ++iter)
    {
        std::string & svr_name = *iter;
        int svr_type = config.getInt(svr_name, "svr_type");
        std::string strCmdlst = config.getString(svr_name, "cmdlist");
        if (!strCmdlst.empty())
        {
            std::list<unsigned int> cmd_lst;
            splitStrToLst(strCmdlst, ',', cmd_lst);

            std::list<unsigned int>::iterator iterlst = cmd_lst.begin();
            for (; iterlst != cmd_lst.end(); ++iterlst)
            {
                unsigned int cmdcode = *iterlst;
                std::map<unsigned int, SVR_TYPE_SET >::iterator itermap = cmd_svr_map.find(cmdcode);
                if (cmd_svr_map.end() != itermap)
                {
                    itermap->second.insert(svr_type);
                } 
                else
                {
                    SVR_TYPE_SET svr_type_set;
                    svr_type_set.insert(svr_type);
                    cmd_svr_map.insert(std::make_pair(cmdcode, svr_type_set));
                }                
            }
        }

        int rangenum = config.getInt(svr_name, "rangenum");
        for (int i = 0; i < rangenum; ++i)
        {
            char cCmdRange[25] = {0};
            sprintf(cCmdRange, "cmdrange_%d", i + 1);
            std::string strCmdRange = config.getString(svr_name, cCmdRange);
            if (strCmdRange.empty())
            {
                continue;
            }

            std::list<unsigned int> cmd_range;
            //format min:max
            splitStrToLst(strCmdRange, ':', cmd_range);
            if (2 != cmd_range.size())
            {
                LOG_PRINT(log_error, "cmdcode range config format error.svr_name:%s,cmdrange:%s.", \
                    svr_name.c_str(), strCmdRange.c_str());
                continue;
            }

            std::list<unsigned int>::iterator iterrange = cmd_range.begin();
            unsigned int mincmd = *iterrange;
            unsigned int maxcmd = *(++iterrange);

            std::map<int, CMD_MIN_MAX>::iterator iter_svr = svr_cmdrange_map.find(svr_type);
            if (svr_cmdrange_map.end() != iter_svr)
            {
                iter_svr->second.insert(std::make_pair(mincmd, maxcmd));
            }
            else
            {
                CMD_MIN_MAX min_max_map;
                min_max_map.insert(std::make_pair(mincmd, maxcmd));
                svr_cmdrange_map.insert(std::make_pair(svr_type, min_max_map));
            }
        }
    }

    if (!cmd_svr_map.empty())
    {
        LOG_PRINT(log_info, "load cmd_svr_map.size:%u.", cmd_svr_map.size());
        boost::mutex::scoped_lock lock(cmd_svr_mutex);
        m_cmd_svr_map.clear();
        m_cmd_svr_map.insert(cmd_svr_map.begin(), cmd_svr_map.end());
    }

    if (!svr_cmdrange_map.empty())
    {
        LOG_PRINT(log_info, "load svr_cmdrange_map.size:%u.", svr_cmdrange_map.size());
        boost::mutex::scoped_lock lock(svr_cmdrange_mutex);
        m_svr_cmdrange_map.clear();
        m_svr_cmdrange_map.insert(svr_cmdrange_map.begin(), svr_cmdrange_map.end());
    }
}

SVR_TYPE_SET CCmdGuideMgr::getSvrType(unsigned int cmdcode)
{
    {
        boost::mutex::scoped_lock lock(cmd_svr_mutex);
        std::map<unsigned int, SVR_TYPE_SET>::iterator iter = m_cmd_svr_map.find(cmdcode);
        if (iter != m_cmd_svr_map.end())
        {
            return iter->second;
        }
    }

    //cmdcode is not in m_cmd_svr_map,need to check cmd range
    //LOG_PRINT(log_info, "cmdcode:%u need to check cmd range.", cmdcode);

    bool bfind = false;
    SVR_TYPE_SET svr_type_set;
    int svr_type = 0;
    {
        boost::mutex::scoped_lock lock(svr_cmdrange_mutex);
        std::map<int, CMD_MIN_MAX>::iterator iter = m_svr_cmdrange_map.begin();
        for (; iter != m_svr_cmdrange_map.end(); ++iter)
        {
            CMD_MIN_MAX & cmd_min_max = iter->second;
            CMD_MIN_MAX::iterator itermap = cmd_min_max.begin();
            for (; itermap != cmd_min_max.end(); ++itermap)
            {
                //key:min cmdcode, value:max cmdcode
                if (cmdcode >= itermap->first && cmdcode <= itermap->second)
                {
                    bfind = true;
                    break;
                }
            }

            if (bfind)
            {
                svr_type = iter->first;
                break;
            }
        }
    }

    if (bfind)
    {
        LOG_PRINT(log_debug, "cmdcode:%u find svr_type:%d", cmdcode, svr_type);
        boost::mutex::scoped_lock lock(cmd_svr_mutex);
        svr_type_set.insert(svr_type);
        m_cmd_svr_map.insert(std::make_pair(cmdcode, svr_type_set));
    }
    return svr_type_set;
}

void CCmdGuideMgr::loadCmdParamConfig()
{
	if(m_configpath.empty())
	{
		LOG_PRINT(log_debug, "config path is empty.");
		return;
	}

	std::string cmd_param_config = m_configpath + "webgate_cmdparam.conf";
	LOG_PRINT(log_debug, "config path:%s", cmd_param_config.c_str());

	m_cmd_param = new Config(cmd_param_config);
	int line = 0;
	if(!m_cmd_param->load(line))
	{
		LOG_PRINT(log_error, "config path:%s", cmd_param_config.c_str());
		return;
	}

	std::string keywordlist = m_cmd_param->getString("server", "keywordlist");
	std::list<std::string> keyword_lst;
	splitStrToLst(keywordlist, ',', keyword_lst);
	if (keyword_lst.empty())
	{
		LOG_PRINT(log_warning, "cmdlist is empty.config path:%s", cmd_param_config.c_str());
		return;
	}

	std::list<std::string>::iterator iter = keyword_lst.begin();
	for (; iter != keyword_lst.end(); ++iter)
	{
		const std::string & keyword = *iter;
		std::string paramlist = m_cmd_param->getString(keyword, "paramlist");
		if (paramlist.empty())
		{
			LOG_PRINT(log_warning, "cmd:%s has no param list.", keyword.c_str());
			continue;
		}

		std::list<std::string> param_lst;
		splitStrToLst(paramlist, ',', param_lst);
		std::list<std::string>::iterator iter_param = param_lst.begin();
		for (; iter_param != param_lst.end(); ++iter_param)
		{
			const std::string & param_name = *iter_param;

			std::map<std::string, PARAM_NAME_TYPE >::iterator iter_map = m_cmd_param_map.find(keyword);
			if (iter_map != m_cmd_param_map.end())
			{
				iter_map->second.push_back(param_name);
			}
			else
			{
				PARAM_NAME_TYPE oParam;
				oParam.push_back(param_name);
				m_cmd_param_map.insert(std::make_pair(keyword, oParam));
			}
		}
	}
}

int CCmdGuideMgr::fillCmdParam(const std::string & keyword, char * pContent, unsigned int maxlen, const Json::Value & jsonData)
{
	std::map<std::string, PARAM_NAME_TYPE >::iterator iter_map = m_cmd_param_map.find(keyword);
	if (iter_map == m_cmd_param_map.end())
	{
		LOG_PRINT(log_error, "keyword:%s is not in config file.", keyword.c_str());
		return -2;
	}

	bool bErr = false;

	char * pEnd = pContent + maxlen;
	char * pInput = pContent;

	const PARAM_NAME_TYPE & params = iter_map->second;
	PARAM_NAME_TYPE::const_iterator iter_param = params.begin();
	for (; iter_param != params.end() && pInput < pEnd; ++iter_param)
	{
		const std::string & param_name = *iter_param;
		const std::string & param_type = m_cmd_param->getString(keyword, param_name);

		if (pInput + m_paramtype_size[param_type] > pEnd) 
		{
			LOG_PRINT(log_error, "pInput > pEnd,keyword:%s,param_name:%s,param_type:%s", keyword.c_str(), param_name.c_str(), param_type.c_str());
			return -1;
		}

		if ("uint8" == param_type)
		{
			if(jsonData[param_name.c_str()].isIntegral())
			{
				uint8 data = jsonData[param_name.c_str()].asInt();
				memcpy(pInput, &data, sizeof(uint8));
				pInput += sizeof(uint8);
			}
			else
			{
				bErr = true;
				break;
			}
		}
		else if ("uint32" == param_type)
		{
			if(jsonData[param_name.c_str()].isIntegral())
			{
				uint32 data = jsonData[param_name.c_str()].asUInt();
				memcpy(pInput, &data, sizeof(uint32));
				pInput += sizeof(uint32);
			}
			else
			{
				bErr = true;
				break;
			}
		}
		else if ("char_64" == param_type)
		{
			if (jsonData[param_name.c_str()].isString())
			{
				std::string strdata = jsonData[param_name.c_str()].asString();
				memset(pInput, 0, 64);
				strncpy(pInput, strdata.c_str(), 64);
				pInput += 64;
			}
			else
			{
				bErr = true;
				break;
			}
		}
		else if ("char_32" == param_type)
		{
			if (jsonData[param_name.c_str()].isString())
			{
				std::string strdata = jsonData[param_name.c_str()].asString();
				memset(pInput, 0, 32);
				strncpy(pInput, strdata.c_str(), 32);
				pInput += 32;
			}
			else
			{
				bErr = true;
				break;
			}
		}
		else if ("byte" == param_type)
		{
			if(jsonData[param_name.c_str()].isIntegral())
			{
				byte data = jsonData[param_name.c_str()].asInt();
				memcpy(pInput, &data, sizeof(byte));
				pInput += sizeof(byte);
			}
			else
			{
				bErr = true;
				break;
			}
		}
		else
		{
			LOG_PRINT(log_error, "Code do not handle this param_type:%s.", param_type.c_str());
		}
	}

	if (bErr)
	{
		Json::FastWriter fast_writer;
		std::string logprint = fast_writer.write(jsonData);
		LOG_PRINT(log_error, "Json data format is wrong!Json:%s.", logprint.c_str());
		return -2;
	}

	return 0;
}

int CCmdGuideMgr::fillJsonParam(const std::string & keyword, const char ** pBeginContent, const char * pEnd, Json::Value & jsonData)
{
	std::map<std::string, PARAM_NAME_TYPE >::iterator iter_map = m_cmd_param_map.find(keyword);
	if (iter_map == m_cmd_param_map.end())
	{
		LOG_PRINT(log_error, "keyword:%s is not in config file.", keyword.c_str());
		return -1;
	}

	const char * pOutput = *pBeginContent;

	unsigned int variable_len = 0;
	unsigned int member_num = 0;

	const PARAM_NAME_TYPE & params = iter_map->second;
	PARAM_NAME_TYPE::const_iterator iter_param = params.begin();
	for (; iter_param != params.end() && pOutput < pEnd; ++iter_param)
	{
		const std::string & param_name = *iter_param;
		const std::string & param_type = m_cmd_param->getString(keyword, param_name);

		if (pOutput + m_paramtype_size[param_type] > pEnd) 
		{
			LOG_PRINT(log_error, "pInput > pEnd,keyword:%s,param_name:%s,param_type:%s", keyword.c_str(), param_name.c_str(), param_type.c_str());
			break;
		}

		if ("uint8" == param_type)
		{
			uint8 data = 0;
			memcpy(&data, pOutput, sizeof(uint8));
			jsonData[param_name.c_str()] = Json::Value(data);
			pOutput += sizeof(uint8);
		}
		else if ("uint32" == param_type)
		{
			uint32 data = 0;
			memcpy(&data, pOutput, sizeof(uint32));
			jsonData[param_name.c_str()] = Json::Value(data);
			pOutput += sizeof(uint32);
		}
		else if ("int16" == param_type)
		{
			int16 data = 0;
			memcpy(&data, pOutput, sizeof(int16));
			jsonData[param_name.c_str()] = Json::Value(data);
			pOutput += sizeof(int16);
		}
		else if ("int32" == param_type)
		{
			int32 data = 0;
			memcpy(&data, pOutput, sizeof(int32));
			jsonData[param_name.c_str()] = Json::Value(data);
			pOutput += sizeof(int32);
		}
		else if ("byte" == param_type)
		{
			byte data = 0;
			memcpy(&data, pOutput, sizeof(byte));
			jsonData[param_name.c_str()] = Json::Value((int)data);
			pOutput += sizeof(byte);
		}
		else if ("uint16" == param_type)
		{
			uint16 data = 0;
			memcpy(&data, pOutput, sizeof(uint16));
			jsonData[param_name.c_str()] = Json::Value(data);
			pOutput += sizeof(uint16);
		}
		else if ("int64" == param_type)
		{
			int64 data = 0;
			memcpy(&data, pOutput, sizeof(int64));
			std::stringstream strdata;
			strdata << data;
			jsonData[param_name.c_str()] = Json::Value(strdata.str());
			pOutput += sizeof(int64);
		}
		else if ("float" == param_type)
		{
			float data = 0.0;
			memcpy(&data, pOutput, sizeof(float));
			jsonData[param_name.c_str()] = Json::Value(data);
			pOutput += sizeof(float);
		}
		else if ("char" == param_type)
		{
			int data = 0;
			data = *pOutput;
			jsonData[param_name.c_str()] = Json::Value(data);
			pOutput += sizeof(char);
		}
		else if ("char_32" == param_type)
		{
			char data[32] = {0};
			memcpy(data, pOutput, sizeof(data));
			jsonData[param_name.c_str()] = Json::Value(data);
			pOutput += sizeof(data);
		}
		else if ("char_128" == param_type)
		{
			char data[128] = {0};
			memcpy(data, pOutput, sizeof(data));
			jsonData[param_name.c_str()] = Json::Value(data);
			pOutput += sizeof(data);
		}
		else if ("char_64" == param_type)
		{
			char data[64] = {0};
			memcpy(data, pOutput, sizeof(data));
			jsonData[param_name.c_str()] = Json::Value(data);
			pOutput += sizeof(data);
		}
		else if ("uint64" == param_type)
		{
			uint64 data = 0;
			memcpy(&data, pOutput, sizeof(uint64));
			std::stringstream strdata;
			strdata << data;
			jsonData[param_name.c_str()] = Json::Value(strdata.str());
			pOutput += sizeof(uint64);
		}
		else if ("gbk_char_32" == param_type)
		{
			char data[32 + 1] = {0};
			memcpy(data, pOutput, 32);
			pOutput += 32;

			std::string utfdata = boost::locale::conv::between(std::string(data), "UTF-8", "GBK");
			jsonData[param_name.c_str()] = Json::Value(utfdata);
		}
		else if ("gbk_char_64" == param_type)
		{
			char data[64 + 1] = {0};
			memcpy(data, pOutput, 64);
			pOutput += 64;

			std::string utfdata = boost::locale::conv::between(std::string(data), "UTF-8", "GBK");
			jsonData[param_name.c_str()] = Json::Value(utfdata);
		}
		else if ("member_num_uint32" == param_type)
		{
			uint32 data = 0;
			memcpy(&data, pOutput, sizeof(uint32));
			member_num = data;
			pOutput += sizeof(uint32);
		}
		else if ("list_member" == param_name)
		{
			std::string mem_class_name = m_cmd_param->getString(keyword, param_name);

			for (int i = 0; i < member_num; ++i)
			{
				Json::Value jdata;
				int ret = fillJsonParam(mem_class_name, &pOutput, pEnd, jdata);
				if (!ret)
				{
					char member[64] = {0};
					sprintf(member, "%u", i+1);
					jsonData[member] = jdata;
				}
			}

			//list_member is the last parameter in the msg,so just break here.
			break;
		}
		else if ("variable_uint16" == param_type)
		{
			uint16 data = 0;
			memcpy(&data, pOutput, sizeof(uint16));
			jsonData[param_name.c_str()] = Json::Value(data);
			pOutput += sizeof(uint16);

			variable_len += data;
		}
		else if ("gbk_variable_array" == param_type)
		{
			if (variable_len && pOutput + variable_len <= pEnd)
			{
				char * data = new char[variable_len + 1];
				if (data != NULL)
				{
					memset(data, 0, variable_len + 1);
					memcpy(data, pOutput, variable_len);
					LOG_PRINT(log_info, "before content:%s.", data);
					std::string utfdata = boost::locale::conv::between(std::string(data), "UTF-8", "GBK");
					LOG_PRINT(log_info, "after change to utf,result:%s.", utfdata.c_str());
					jsonData[param_name.c_str()] = Json::Value(std::string(utfdata));
				}

				if (data != NULL)
				{
					delete[] data;
					data = NULL;
				}

				pOutput += variable_len;
			}
			
			//variable_param is the last parameter in the msg,so just break here.
			break;
		}
	}

	*pBeginContent = pOutput;

	return 0;
}



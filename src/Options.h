/* XMRig
 * Copyright 2010      Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2012-2014 pooler      <pooler@litecoinpool.org>
 * Copyright 2014      Lucas Jones <https://github.com/lucasjones>
 * Copyright 2014-2016 Wolf9466    <https://github.com/OhGodAPet>
 * Copyright 2016      Jay D Dee   <jayddee246@gmail.com>
 * Copyright 2017-2018 XMR-Stak    <https://github.com/fireice-uk>, <https://github.com/psychocrypt>
 * Copyright 2016-2018 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __OPTIONS_H__
#define __OPTIONS_H__


#include <stdint.h>
#include <vector>
#include <string>

#include "xmrig.h"
#include "rapidjson/fwd.h"


class Url;
struct option;


class Options
{
public:
	enum AlgoVia
	{
		AV0_AUTO = 0,
		AV1_AESNI = 1,
		AV2_AESNI_DOUBLE = 2,
		AV3_SOFT_AES = 3,
		AV4_SOFT_AES_DOUBLE = 4,
		AV_MAX
	};

	struct Donate
	{
	public:
		std::string m_url;
#ifndef XMRIG_NO_AEON
		std::string m_url_little;
#endif
		std::string m_user;
		std::string m_pass;
		bool m_keepAlive;
		bool m_niceHash;
#ifndef XMRIG_NO_SSL
		bool m_ssl;
#endif
		unsigned short m_donateMinutes;
		unsigned short m_minutesInCicle;
	};

	static inline Options* i()
	{
		return m_self;
	}
	static Options* parse(int argc, char** argv);

	inline bool background() const
	{
		return m_background;
	}
	inline bool colors() const
	{
		return m_colors;
	}
	inline bool isDebug() const
	{
		return m_debug;
	}
	inline void toggleDebug()
	{
		m_debug = !m_debug;
	}
	inline bool doubleHash() const
	{
		return m_doubleHash;
	}
	inline bool dryRun() const
	{
		return m_dryRun;
	}
	inline bool hugePages() const
	{
		return m_hugePages;
	}
	inline bool syslog() const
	{
		return m_syslog;
	}
	inline const std::string apiToken() const
	{
		return m_apiToken;
	}
	inline const std::string & apiWorkerId() const
	{
		return m_apiWorkerId;
	}
	inline const std::string & logFile() const
	{
		return m_logFile;
	}
	inline const std::string & userAgent() const
	{
		return m_userAgent;
	}
	inline const std::vector<Url> & pools() const
	{
		return m_pools;
	}
	inline xmrig::Algo algo() const
	{
		return m_algo;
	}
	inline Options::AlgoVia algoVia() const
	{
		return m_algoVia;
	}
	inline int apiPort() const
	{
		return m_apiPort;
	}

#ifndef XMRIG_NO_DONATE
	inline unsigned short donateMinutes() const
	{
		return m_donateOpt.m_donateMinutes;
	}
	inline unsigned short minutesInCicle() const
	{
		return m_donateOpt.m_minutesInCicle;
	}
	inline const Donate & donate() const
	{
		return m_donateOpt;
	}
#endif

	inline int printTime() const
	{
		return m_printTime;
	}
	inline int priority() const
	{
		return m_priority;
	}
	inline int retries() const
	{
		return m_retries;
	}
	inline int retryPause() const
	{
		return m_retryPause;
	}
	inline int threads() const
	{
		return m_threads;
	}
	inline int64_t affinity() const
	{
		return m_affinity;
	}
	inline void setColors(bool colors)
	{
		m_colors = colors;
	}
	inline void setVerbose(bool verbose)
	{
		m_verbose = verbose;
	}
	inline void toggleVerbose()
	{
		m_verbose = !m_verbose;
	}

	inline static void release()
	{
		delete m_self;
	}

	const char* algoName() const;

private:
	Options(int argc, char** argv);
	~Options();

	inline bool isReady() const
	{
		return m_ready;
	}

	static Options* m_self;

	bool getJSON(const std::string & fileName, rapidjson::Document & doc);
	bool parseArg(int key, const std::string & arg);
	bool parseArg(int key, uint64_t arg);
	bool parseBoolean(int key, bool enable);
	Url parseUrl(const std::string & arg) const;
	void adjust();
	bool parseConfig(const std::string & fileName);
	bool parseJSON(const struct option* option, const rapidjson::Value & object);
	void showUsage(int status) const;
	void showVersion(void);

	bool setAlgo(const std::string & algo);

	Options::AlgoVia getAlgoVia() const;

#   ifndef XMRIG_NO_AEON
	Options::AlgoVia getAlgoViaLite() const;
#   endif

	bool m_background;
	bool m_colors;
	bool m_debug;
	bool m_doubleHash;
	bool m_dryRun;
	bool m_hugePages;
	bool m_ready;
	bool m_safe;
	bool m_syslog;
	bool m_verbose;
	std::string m_apiToken;
	std::string m_apiWorkerId;
	std::string m_logFile;
	std::string m_userAgent;
	xmrig::Algo m_algo;
	Options::AlgoVia m_algoVia;
	int m_apiPort;
	int m_maxCpuUsage;
	int m_printTime;
	int m_priority;
	int m_retries;
	int m_retryPause;
	int m_threads;
	int64_t m_affinity;
	std::vector<Url> m_pools;

#ifndef XMRIG_NO_DONATE
	Donate m_donateOpt;
#endif
};

#endif /* __OPTIONS_H__ */

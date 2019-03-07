/* XMRig
 * Copyright 2010      Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2012-2014 pooler      <pooler@litecoinpool.org>
 * Copyright 2014      Lucas Jones <https://github.com/lucasjones>
 * Copyright 2014-2016 Wolf9466    <https://github.com/OhGodAPet>
 * Copyright 2016      Jay D Dee   <jayddee246@gmail.com>
 * Copyright 2016-2017 XMRig       <support@xmrig.com>
 *
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


#include <string.h>
#include <uv.h>


#ifdef _MSC_VER
#include "getopt/getopt.h"
#else
#include <getopt.h>
#endif


#ifndef XMRIG_NO_HTTPD
#include <microhttpd.h>
#endif

#include "interfaces/interface.h"

#include "Cpu.h"

#ifndef XMRIG_NO_DONATE
#include "donate.h"
#endif

#include "net/Url.h"
#include "Options.h"
#include "Platform.h"
#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "rapidjson/filereadstream.h"
#include "version.h"
#include "xmrig.h"


#ifndef ARRAY_SIZE
#   define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif


Options* Options::m_self = nullptr;


#ifndef XMRIG_NO_STRINGS
static char const usage[] = "Usage: \" APP_ID [OPTIONS]\"" "\n"
                            "Options: " "\n"
#ifndef XMRIG_NO_AEON
                            "  -a, --algo=ALGO          cryptonight (default) or cryptonight-lite\n"
#else
                            "  -a, --algo=ALGO          cryptonight (only)\n"
#endif
                            "-o, --url=URL            URL of mining server" "\n"
                            "-O, --userpass=U:P       username:password pair for mining server" "\n"
                            "-u, --user=USERNAME      username for mining server" "\n"
                            "-p, --pass=PASSWORD      password for mining server" "\n"
                            "-t, --threads=N          number of miner threads" "\n"
                            "-v, --av=N               algorithm via, 0 auto select" "\n"
                            "-k, --keepalive          send keepalived for prevent timeout (need pool support)" "\n"
                            "-r, --retries=N          number of times to retry before switch to backup server (default: 5)" "\n"
                            "-R, --retry-pause=N      time to pause between retries (default: 5)" "\n"
                            "    --cpu-affinity       set process affinity to CPU core(s), mask 0x3 for cores 0 and 1" "\n"
                            "    --cpu-priority       set process priority (0 idle, 2 normal to 5 highest)" "\n"
                            "    --no-huge-pages      disable huge pages support" "\n"
                            "    --no-color           disable colored output" "\n"
                            "    --variant            algorithm PoW variant" "\n"
#ifndef XMRIG_NO_DONATE
                            "    --donate-level=N     donate level, default 5%% (5 minutes in 100 minutes)" "\n"
#endif
                            "    --user-agent         set custom user-agent string for pool" "\n"
                            "-B, --background         run the miner in the background" "\n"
                            "-c, --config=FILE        load a JSON-format configuration file" "\n"
                            "-l, --log-file=FILE      log all output to a file" "\n"
#ifdef HAVE_SYSLOG_H
                            "-S, --syslog             use system log for output messages" "\n"
#endif
                            "    --max-cpu-usage=N    maximum CPU usage for automatic threads mode (default 75)" "\n"
                            "    --safe               safe adjust threads and av settings for current CPU" "\n"
                            "    --nicehash           enable nicehash/xmrig-proxy support" "\n"
#ifndef XMRIG_NO_SSL
                            "    --ssl                enable ssl over tcp" "\n"
#endif
#ifndef XMRIG_NO_UDP
                            "    --udp                connect use udp" "\n"
                            "    --udp-blind          listen on udp port" "\n"
#endif
                            "    --print-time=N       print hashrate report every N seconds" "\n"
                            "    --api-port=N         port for the miner API" "\n"
                            "    --api-access-token=T access token for API" "\n"
                            "    --api-worker-id=ID   custom worker-id for API" "\n"
                            "-h, --help               display this help and exit" "\n"
                            "-V, --version            output version information and exit";
#else
static char const usage[] = "See man.";
#endif

static char const short_options[] = "a:c:khBp:Px:r:R:s:t:T:o:u:O:v:Vl:S";


static struct option const options[] =
{
	{ "algo",              required_argument, nullptr, 'a'  },
	{ "api-access-token",  required_argument, nullptr, 4001 },
	{ "api-port",          required_argument, nullptr, 4000 },
	{ "api-worker-id",     required_argument, nullptr, 4002 },
	{ "av",                required_argument, nullptr, 'v'  },
	{ "background",        no_argument,       nullptr, 'B'  },
	{ "config",            required_argument, nullptr, 'c'  },
	{ "cpu-affinity",      required_argument, nullptr, 1020 },
	{ "cpu-priority",      required_argument, nullptr, 1021 },
	{ "debug",             no_argument,       nullptr, 1101 },
#ifndef XMRIG_NO_DONATE
	{ "donate-level",      required_argument, nullptr, 1003 },
#endif
	{ "dry-run",           no_argument,       nullptr, 5000 },
	{ "help",              no_argument,       nullptr, 'h'  },
	{ "keepalive",         no_argument,       nullptr, 'k'  },
	{ "log-file",          required_argument, nullptr, 'l'  },
	{ "max-cpu-usage",     required_argument, nullptr, 1004 },
	{ "nicehash",          no_argument,       nullptr, 1006 },
#ifndef XMRIG_NO_SSL
	{ "ssl",               no_argument,       nullptr, 1088 },
#else
	{ "ssl",               no_argument,       nullptr, 1188 },
#endif
#ifndef XMRIG_NO_UDP
	{ "udp",               no_argument,       nullptr, 1089 },
	{ "udp-blind",         required_argument, nullptr, 1090 },
#else
	{ "udp",               no_argument,       nullptr, 1189 },
	{ "udp-blind",         required_argument, nullptr, 1190 },
#endif
	{ "no-color",          no_argument,       nullptr, 1002 },
	{ "no-huge-pages",     no_argument,       nullptr, 1009 },
	{ "variant",           required_argument, nullptr, 1010 },
	{ "pass",              required_argument, nullptr, 'p'  },
	{ "print-time",        required_argument, nullptr, 1007 },
	{ "retries",           required_argument, nullptr, 'r'  },
	{ "retry-pause",       required_argument, nullptr, 'R'  },
	{ "safe",              no_argument,       nullptr, 1005 },
	{ "syslog",            no_argument,       nullptr, 'S'  },
	{ "threads",           required_argument, nullptr, 't'  },
	{ "url",               required_argument, nullptr, 'o'  },
	{ "user",              required_argument, nullptr, 'u'  },
	{ "user-agent",        required_argument, nullptr, 1008 },
	{ "userpass",          required_argument, nullptr, 'O'  },
	{ "verbose",           no_argument,       nullptr, 1100 },
	{ "version",           no_argument,       nullptr, 'V'  },
#ifndef XMRIG_NO_DONATE
	{ "donate-url",        required_argument, nullptr, 1391 },
#ifndef XMRIG_NO_AEON
	{ "donate-url-little", required_argument, nullptr, 1392 },
#endif
	{ "donate-user",       required_argument, nullptr, 1393 },
	{ "donate-pass",       required_argument, nullptr, 1394 },
	{ "donate-userpass",   required_argument, nullptr, 1395 },
	{ "donate-keepalive",  no_argument,       nullptr, 1396 },
	{ "donate-nicehash",   no_argument,       nullptr, 1397 },
#ifndef XMRIG_NO_SSL
	{ "donate-ssl",        no_argument,       nullptr, 1388 },
#endif
	{ "donate-minutes",    required_argument, nullptr, 1398 },
	{ "minutes-in-cicle",  required_argument, nullptr, 1399 },
#endif
	{ 0, 0, 0, 0 }
};


static struct option const config_options[] =
{
	{ "algo",          1, nullptr, 'a'  },
	{ "av",            1, nullptr, 'v'  },
	{ "background",    0, nullptr, 'B'  },
	{ "colors",        0, nullptr, 2000 },
	{ "cpu-affinity",  1, nullptr, 1020 },
	{ "cpu-priority",  1, nullptr, 1021 },
#ifndef XMRIG_NO_DONATE
	{ "donate-level",  1, nullptr, 1003 },
#endif
	{ "dry-run",       0, nullptr, 5000 },
	{ "huge-pages",    0, nullptr, 1009 },
	{ "log-file",      1, nullptr, 'l'  },
	{ "max-cpu-usage", 1, nullptr, 1004 },
	{ "print-time",    1, nullptr, 1007 },
	{ "retries",       1, nullptr, 'r'  },
	{ "retry-pause",   1, nullptr, 'R'  },
	{ "safe",          0, nullptr, 1005 },
	{ "syslog",        0, nullptr, 'S'  },
	{ "threads",       1, nullptr, 't'  },
	{ "user-agent",    1, nullptr, 1008 },
	{ "verbose",       0, nullptr, 1100 },
	{ "workers",       0, nullptr, 1103 },
	{ 0, 0, 0, 0 }
};

#ifndef XMRIG_NO_DONATE
static struct option const donate_options[] =
{
	{ "donate-url",          required_argument, nullptr, 1391 },
#ifndef XMRIG_NO_AEON
	{ "donate-url-little",   required_argument, nullptr, 1392 },
#endif
	{ "donate-user",         required_argument, nullptr, 1393 },
	{ "donate-pass",         required_argument, nullptr, 1394 },
	{ "donate-userpass",     required_argument, nullptr, 1395 },
	{ "donate-keepalive",    no_argument,       nullptr, 1396 },
	{ "donate-nicehash",     no_argument,       nullptr, 1397 },
#ifndef XMRIG_NO_SSL
	{ "donate-ssl",          no_argument,       nullptr, 1388 },
#endif
	{ "donate-minutes",      required_argument, nullptr, 1398 },
	{ "minutes-in-cicle",    required_argument, nullptr, 1399 },
	{ 0, 0, 0, 0 }
};
#endif

static struct option const pool_options[] =
{
	{ "url",           required_argument, nullptr, 'o'  },
	{ "pass",          required_argument, nullptr, 'p'  },
	{ "user",          required_argument, nullptr, 'u'  },
	{ "userpass",      required_argument, nullptr, 'O'  },
	{ "keepalive",     no_argument,       nullptr, 'k'  },
	{ "variant",       required_argument, nullptr, 1010 },
	{ "nicehash",      no_argument,       nullptr, 1006 },
#ifndef XMRIG_NO_SSL
	{ "ssl",           no_argument,       nullptr, 1088 },
#else
	{ "ssl",           no_argument,       nullptr, 1188 },
#endif
#ifndef XMRIG_NO_UDP
	{ "udp",           no_argument,       nullptr, 1089 },
	{ "udp-blind",     required_argument, nullptr, 1090 },
#else
	{ "udp",           no_argument,       nullptr, 1189 },
	{ "udp-blind",     required_argument, nullptr, 1190 },
#endif
	{ 0, 0, 0, 0 }
};


static struct option const api_options[] =
{
	{ "port",         required_argument, nullptr, 4000 },
	{ "access-token", required_argument, nullptr, 4001 },
	{ "worker-id",    required_argument, nullptr, 4002 },
	{ 0, 0, 0, 0 }
};


static const char* algo_names[] =
{
	"cryptonight",
#   ifndef XMRIG_NO_AEON
	"cryptonight-lite"
#   endif
};


Options* Options::parse(int argc, char** argv)
{
	Options* options = new Options(argc, argv);
	if(options->isReady())
	{
		m_self = options;
		return m_self;
	}

	delete options;
	return nullptr;
}


const char* Options::algoName() const
{
	return algo_names[m_algo];
}


Options::Options(int argc, char** argv) :
	m_background(false),
	m_colors(false),
	m_debug(false),
	m_doubleHash(false),
	m_dryRun(false),
	m_hugePages(true),
	m_ready(false),
	m_safe(false),
	m_syslog(false),
	m_verbose(false),
	m_apiToken(""),
	m_apiWorkerId(""),
	m_logFile(""),
	m_userAgent(""),
	m_algo(xmrig::ALGO_CRYPTONIGHT),
	m_algoVia(Options::AV0_AUTO),
	m_apiPort(0),
	m_maxCpuUsage(100),
	m_printTime(60),
	m_priority(-1),
	m_retries(5),
	m_retryPause(5),
	m_threads(0),
	m_affinity(-1L)
{
#ifndef XMRIG_NO_DONATE
	m_donateOpt.m_url = kDonateUrl;
#ifndef XMRIG_NO_AEON
	m_donateOpt.m_url_little = kDonateUrlLittle;
#endif
	m_donateOpt.m_user = kDonateUser;
	m_donateOpt.m_pass = kDonatePass;
	m_donateOpt.m_keepAlive = kDonateKeepAlive;
	m_donateOpt.m_niceHash = kDonateNiceHash;
#ifndef XMRIG_NO_SSL
	m_donateOpt.m_ssl = kDonateSsl;
#endif
	m_donateOpt.m_donateMinutes = kDonateMinutes;
	m_donateOpt.m_minutesInCicle = kMinutesInCicle;
#endif

	m_pools.push_back(Url());

	while(1)
	{
		const int key = getopt_long(argc, argv, short_options, options, NULL);
		if(key < 0)
		{
			break;
		}

		if(!parseArg(key, optarg == NULL ? "" : optarg))
		{
			return;
		}
	}

	if(optind < argc)
	{
		fprintf(stderr, "%s: unsupported non-option argument '%s'\n", argv[0], argv[optind]);
		return;
	}

	if(!m_pools[0].isValid())
	{
		if(false == parseConfig(Platform::defaultConfigName()))
		{
			return;
		}
	}

	if(!m_pools[0].isValid())
	{
		fprintf(stderr, "No pool URL supplied. Exiting.\n");
		return;
	}

	m_algoVia = getAlgoVia();
	if(m_algoVia == AV2_AESNI_DOUBLE || m_algoVia == AV4_SOFT_AES_DOUBLE)
	{
		m_doubleHash = true;
	}

	if(!m_threads)
	{
		m_threads = Cpu::optimalThreadsCount(m_algo, m_doubleHash, m_maxCpuUsage);
	}
	else if(m_safe)
	{
		const int count = Cpu::optimalThreadsCount(m_algo, m_doubleHash, m_maxCpuUsage);
		if(m_threads > count)
		{
			m_threads = count;
		}
	}

	if(m_doubleHash && m_algoVia != AV2_AESNI_DOUBLE && m_algoVia != AV4_SOFT_AES_DOUBLE)
	{
		fprintf(stdout, "Double!\n");

		if(m_algoVia == AV1_AESNI)
		{
			m_algoVia = AV2_AESNI_DOUBLE;
		}

		if(m_algoVia == AV3_SOFT_AES)
		{
			m_algoVia = AV4_SOFT_AES_DOUBLE;
		}
	}

	adjust();

	m_ready = true;
}


Options::~Options()
{
	m_pools.clear();
}


bool Options::getJSON(const std::string & fileName, rapidjson::Document & doc)
{
	uv_fs_t req;
	const int fd = uv_fs_open(uv_default_loop(), &req, fileName.c_str(), O_RDONLY, 0644, nullptr);
	if(fd < 0)
	{
		fprintf(stderr, "unable to open %s: %s\n", fileName.c_str(), uv_strerror(fd));
		return false;
	}

	uv_fs_req_cleanup(&req);

	FILE* fp = fdopen(fd, "rb");
	char buf[8192];
	rapidjson::FileReadStream is(fp, buf, sizeof(buf));

	doc.ParseStream(is);

	uv_fs_close(uv_default_loop(), &req, fd, nullptr);
	uv_fs_req_cleanup(&req);

	if(doc.HasParseError())
	{
		printf("%s:%d: %s\n", fileName.c_str(), (int) doc.GetErrorOffset(),
		       rapidjson::GetParseError_En(doc.GetParseError()));
		return false;
	}

	return doc.IsObject();
}


bool Options::parseArg(int key, const std::string & arg)
{
	switch(key)
	{
	case 'a': /* --algo */
		if(!setAlgo(arg))
		{
			return false;
		}
		break;

	case 'o': /* --url */
		if(m_pools.size() > 1 || m_pools[0].isValid())
		{
			Url url(arg);
			if(url.isValid())
			{
				m_pools.push_back(url);
			}
		}
		else
		{
			m_pools[0].parse(arg);
		}

		if(!m_pools.back().isValid())
		{
			return false;
		}
		break;

	case 'O': /* --userpass */
		if(!m_pools.back().setUserpass(arg))
		{
			return false;
		}
		break;

	case 'u': /* --user */
		m_pools.back().setUser(arg);
		break;

	case 'p': /* --pass */
		m_pools.back().setPassword(arg);
		break;

	case 'l': /* --log-file */
		m_logFile = arg;
		break;

	case 4001: /* --access-token */
		m_apiToken = arg;
		break;

	case 4002: /* --worker-id */
		m_apiWorkerId = arg;
		break;

	case 'r':  /* --retries */
	case 'R':  /* --retry-pause */
	case 'v':  /* --av */
	case 1004: /* --max-cpu-usage */
	case 1007: /* --print-time */
	case 1021: /* --cpu-priority */
	case 4000: /* --api-port */
	case 1010: /* --variant */
		return parseArg(key, strtol(arg.c_str(), nullptr, 10));

	case 'B':  /* --background */
	case 'k':  /* --keepalive */
	case 'S':  /* --syslog */
	case 1005: /* --safe */
	case 1006: /* --nicehash */
#ifndef XMRIG_NO_SSL
	case 1088: /* --ssl*/
#else
	case 1188: /* --ssl*/
#endif
#ifndef XMRIG_NO_UDP
	case 1089: /* --udp*/
#else
	case 1189: /* --udp*/
#endif
	case 1100: /* --verbose */
	case 1101: /* --debug */
		return parseBoolean(key, true);

	case 1002: /* --no-color */
	case 1009: /* --no-huge-pages */
		return parseBoolean(key, false);

#ifndef XMRIG_NO_DONATE
	case 1003: /* --donate-level */
		if(arg == "")
		{
			m_donateOpt.m_donateMinutes = 0;
		}
		else
		{
			parseArg(key, strtol(arg.c_str(), nullptr, 10));
		}
		break;

	case 1391: //donate-url
		m_donateOpt.m_url = arg;
		break;

#ifndef XMRIG_NO_AEON
	case 1392: //donate-url-little
		m_donateOpt.m_url_little = arg;
		break;
#endif

	case 1393: //donate-user
		m_donateOpt.m_user = arg;
		break;
	case 1394: //donate-pass
		m_donateOpt.m_pass = arg;
		break;
	case 1395: //donate-userpass
	{
		const size_t p = arg.find_first_of(':');
		if(p != std::string::npos)
		{
			m_donateOpt.m_user = arg.substr(0, p);
			m_donateOpt.m_pass = arg.substr(p + 1);
		}
	}
	break;
	case 1396: //donate-nicehash
		parseBoolean(key, arg == "true");
		break;
	case 1397: //donate-keepalive
		parseBoolean(key, arg == "true");
		break;
	case 1398: //donate-minutes
		parseArg(key, strtol(arg.c_str(), nullptr, 10));
		break;
	case 1399: //minutes-in-cicle
		parseArg(key, strtol(arg.c_str(), nullptr, 10));
		break;
#ifndef XMRIG_NO_SSL
	case 1388: //donate-ssl
		parseBoolean(key, arg == "true");
		break;
#endif

#endif

#ifndef XMRIG_NO_UDP
	case 1090: /* --udp-blind */
		m_pools.back().setUdpBlind(strtol(arg.c_str(), nullptr, 10));
		break;
#else
	case 1190: /* --udp-blind */
		fprintf(stderr, "UDP blind is not supported.\n");
		break;
#endif

	case 't':  /* --threads */
		if(arg == "all")
		{
			m_threads = Cpu::threads();
			return true;
		}

		return parseArg(key, strtol(arg.c_str(), nullptr, 10));

	case 'V': /* --version */
		showVersion();
		return false;

	case 'h': /* --help */
		showUsage(0);
		return false;

	case 'c': /* --config */
		return parseConfig(arg);
		break;

	case 1020:   /* --cpu-affinity */
	{
		const size_t p = arg.find("0x");
		return parseArg(key, p != std::string::npos ? strtoul(arg.substr(p).c_str(), nullptr, 16) :
		                strtoul(arg.c_str(), nullptr, 10));
	}

	case 1008: /* --user-agent */
		m_userAgent = arg;
		break;

	default:
		showUsage(1);
		return false;
	}

	return true;
}


bool Options::parseArg(int key, uint64_t arg)
{
	switch(key)
	{
	case 'r': /* --retries */
		if(arg < 1 || arg > 1000)
		{
			showUsage(1);
			return false;
		}

		m_retries = (int) arg;
		break;

	case 'R': /* --retry-pause */
		if(arg < 1 || arg > 3600)
		{
			showUsage(1);
			return false;
		}

		m_retryPause = (int) arg;
		break;

	case 't': /* --threads */
		if(arg < 0 || arg > 1024)
		{
			showUsage(1);
			return false;
		}

		m_threads = (int) arg;
		break;

	case 'v': /* --av */
		if(arg > 1000)
		{
			showUsage(1);
			return false;
		}

		m_algoVia = (Options::AlgoVia) arg;
		break;

#ifndef XMRIG_NO_DONATE
	case 1003: /* --donate-level */
		if(arg >= 0 || arg <= 60)
		{
			m_donateOpt.m_donateMinutes = (unsigned short) arg;
		}
		break;

	case 1391: //donate-url
	case 1392: //donate-user
	case 1393: //donate-pass
	case 1394: //donate-userpass
	case 1395: //donate-keepalive
	case 1396: //donate-nicehash
#ifndef XMRIG_NO_SSL
	case 1388: //donate-ssl
#endif
		break;

	case 1398: //donate-minutes
		m_donateOpt.m_donateMinutes = (unsigned short)arg;
		break;

	case 1399: //minutes-in-cicle
		m_donateOpt.m_minutesInCicle = (unsigned short)arg;
		break;
#endif

#ifndef XMRIG_NO_UDP
	case 1090: /* --udp-blind */
		m_pools.back().setUdpBlind(arg);
		break;
#else
	case 1190: /* --udp-blind */
		fprintf(stderr, "UDP blind is not supported.\n");
		return false;
#endif

	case 1004: /* --max-cpu-usage */
		if(arg < 1 || arg > 100)
		{
			showUsage(1);
			return false;
		}

		m_maxCpuUsage = (int) arg;
		break;

	case 1007: /* --print-time */
		if(arg > 1000)
		{
			showUsage(1);
			return false;
		}

		m_printTime = (int) arg;
		break;

	case 1010: /* --variant */
		m_pools.back().setVariant((xmrig::Variant) arg);
		break;

	case 1020: /* --cpu-affinity */
		if(arg)
		{
			m_affinity = arg;
		}
		break;

	case 1021: /* --cpu-priority */
		if(arg <= 5)
		{
			m_priority = (int) arg;
		}
		break;

	case 4000: /* --api-port */
		if(arg <= 65536)
		{
			m_apiPort = (int) arg;
		}
		break;

	default:
		break;
	}

	return true;
}


bool Options::parseBoolean(int key, bool enable)
{
	switch(key)
	{
	case 'k': /* --keepalive */
		m_pools.back().setKeepAlive(enable);
		break;

	case 'B': /* --background */
		m_background = enable;
		m_colors = enable ? false : m_colors;
		break;

	case 'S': /* --syslog */
		m_syslog = enable;
		m_colors = enable ? false : m_colors;
		break;

	case 1002: /* --no-color */
		m_colors = enable;
		break;

	case 1100: /* --verbose */
		m_verbose = enable;
		break;

	case 1101: /* --debug */
		m_debug = enable;
		break;

	case 1005: /* --safe */
		m_safe = enable;
		break;

	case 1006: /* --nicehash */
		m_pools.back().setNicehash(enable);
		break;

	case 1088: /* --ssl */
#ifdef XMRIG_NO_SSL
		if(enable == true)
		{
			fprintf(stderr, "SSL is not supported.\n");
			return false;
		}
		else
		{
			m_pools.back().setSslFalse();
		}
#else
		m_pools.back().setSsl(enable);
#endif
		break;

#ifndef XMRIG_NO_UDP
	case 1089: /* --udp */
		m_pools.back().setUdp(enable);
		break;
#else
	case 1189: /* --udp*/
		fprintf(stderr, "UDP is not supported.\n");
		return false;
#endif

	case 1009: /* --no-huge-pages */
		m_hugePages = enable;
		break;

	case 2000: /* colors */
		m_colors = enable;
		break;

	case 5000: /* --dry-run */
		m_dryRun = enable;
		break;

#ifndef XMRIG_NO_DONATE
	case 1396: //donate-keepalive
		m_donateOpt.m_keepAlive = enable;
		break;

	case 1397: //donate-nicehash
		m_donateOpt.m_niceHash = enable;
		break;

#ifndef XMRIG_NO_SSL
	case 1388: //donate-ssl
		m_donateOpt.m_ssl = enable;
		break;
#endif

	case 1391: //donate-url
#ifndef XMRIG_NO_AEON
	case 1392: //donate-url-little
#endif
	case 1393: //donate-user
	case 1394: //donate-pass
	case 1395: //donate-userpass
	case 1398: //donate-minutes
	case 1399: //minutes-in-cicle
#endif
	default:
		break;
	}

	return true;
}


Url Options::parseUrl(const std::string & arg) const
{
	return Url(arg);
}

void Options::adjust()
{
	for(size_t i = 0; i < m_pools.size(); ++i)
	{
		Url & url = m_pools[i];
		url.adjust(m_algo);
	}
}

bool Options::parseConfig(const std::string & fileName)
{
	rapidjson::Document doc;
	if(!getJSON(fileName, doc))
	{
		return false;
	}

	for(size_t i = 0; i < ARRAY_SIZE(config_options); i++)
	{
		if(false == parseJSON(&config_options[i], doc))
		{
			return false;
		}
	}

#ifndef XMRIG_NO_DONATE
	const rapidjson::Value & donate = doc["donate-level"];
	if(donate.IsArray())
	{
		for(size_t i = 0; i < donate.GetArray().Size(); ++i)
		{
			const rapidjson::Value & value = donate.GetArray()[i];
			if(!value.IsObject())
			{
				continue;
			}

			for(size_t i = 0; i < ARRAY_SIZE(donate_options); i++)
			{
				if(false == parseJSON(&donate_options[i], value))
				{
					return false;
				}
			}
		}
	}
#endif

	const rapidjson::Value & pools = doc["pools"];
	if(pools.IsArray())
	{
		for(size_t i = 0; i < pools.GetArray().Size(); ++i)
		{
			const rapidjson::Value & value = pools.GetArray()[i];
			if(!value.IsObject())
			{
				continue;
			}

			for(size_t i = 0; i < ARRAY_SIZE(pool_options); i++)
			{
				if(false == parseJSON(&pool_options[i], value))
				{
					return false;
				}
			}
		}
	}

	const rapidjson::Value & api = doc["api"];
	if(api.IsObject())
	{
		for(size_t i = 0; i < ARRAY_SIZE(api_options); i++)
		{
			if(false == parseJSON(&api_options[i], api))
			{
				return false;
			}
		}
	}
	return true;
}


bool Options::parseJSON(const struct option* option, const rapidjson::Value & object)
{
	if(!option->name || !object.HasMember(option->name))
	{
		return true;
	}

	const rapidjson::Value & value = object[option->name];

	if(option->has_arg && value.IsString())
	{
		return parseArg(option->val, value.GetString());
	}
	else if(option->has_arg && value.IsUint64())
	{
		return parseArg(option->val, value.GetUint64());
	}
	else if(!option->has_arg && value.IsBool())
	{
		return parseBoolean(option->val, value.IsTrue());
	}

	return true;
}


void Options::showUsage(int status) const
{
	if(status)
	{
		fprintf(stderr, "Try \"" APP_ID "\" --help' for more information.\n");
	}
	else
	{
		printf(usage);
	}
}


void Options::showVersion()
{
	printf(APP_NAME " " APP_VERSION "\n built on " __DATE__

#   if defined(__clang__)
	       " with clang " __clang_version__);
#   elif defined(__GNUC__)
	       " with GCC");
	printf(" %d.%d.%d", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#   elif defined(_MSC_VER)
	       " with MSVC");
	printf(" %d", MSVC_VERSION);
#   else
	      );
#   endif

	printf("\n features:"
#   if defined(__i386__) || defined(_M_IX86)
	       " i386"
#   elif defined(__x86_64__) || defined(_M_AMD64)
	       " x86_64"
#   endif

#   if defined(__AES__) || defined(_MSC_VER)
	       " AES-NI"
#   endif
	       "\n");

	printf("\nlibuv/%s\n", uv_version_string());

#   ifndef XMRIG_NO_HTTPD
	printf("libmicrohttpd/%s\n", MHD_get_version());
#   endif
}


bool Options::setAlgo(const std::string & algo)
{
	for(size_t i = 0; i < ARRAY_SIZE(algo_names); i++)
	{
		if(algo_names[i] && algo == algo_names[i])
		{
			m_algo = (xmrig::Algo) i;
			break;
		}

#       ifndef XMRIG_NO_AEON
		if(i == ARRAY_SIZE(algo_names) - 1 && algo == "cryptonight-light")
		{
			m_algo = xmrig::ALGO_CRYPTONIGHT_LITE;
			break;
		}
#       endif

		if(i == ARRAY_SIZE(algo_names) - 1)
		{
			showUsage(1);
			return false;
		}
	}

	return true;
}


Options::AlgoVia Options::getAlgoVia() const
{
#   ifndef XMRIG_NO_AEON
	if(m_algo == xmrig::ALGO_CRYPTONIGHT_LITE)
	{
		return getAlgoViaLite();
	}
#   endif

	if(m_algoVia <= AV0_AUTO || m_algoVia >= AV_MAX)
	{
		return Cpu::hasAES() ? AV1_AESNI : AV3_SOFT_AES;
	}

	if(m_safe && !Cpu::hasAES() && m_algoVia <= AV2_AESNI_DOUBLE)
	{
		return m_algoVia == AV1_AESNI ? AV3_SOFT_AES : AV4_SOFT_AES_DOUBLE;
	}

	return m_algoVia;
}


#ifndef XMRIG_NO_AEON
int Options::getAlgoViaLite() const
{
	if(m_algoVia <= AV0_AUTO || m_algoVia >= AV_MAX)
	{
		return Cpu::hasAES() ? AV2_AESNI_DOUBLE : AV4_SOFT_AES_DOUBLE;
	}

	if(m_safe && !Cpu::hasAES() && m_algoVia <= AV2_AESNI_DOUBLE)
	{
		return m_algoVia + 2;
	}

	return m_algoVia;
}
#endif

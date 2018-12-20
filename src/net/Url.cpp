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
#include <stdlib.h>
#include <algorithm>

#ifndef _WIN32
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#else
#include <winsock2.h>
#undef min
#undef max
#endif

#include "net/Url.h"
#include "xmrig.h"
#include "interfaces/interface.h"

#ifdef _MSC_VER
#define strncasecmp(x,y,z) _strnicmp(x,y,z)
#endif

Url::Url()
	: m_keepAlive(false),
	  m_nicehash(false),
#ifndef XMRIG_NO_SSL
	  m_ssl(false),
#endif
#ifndef XMRIG_NO_UDP
	  m_udp(false),
	  m_udpBlind(0),
#endif
	  m_host(),
	  m_password(),
	  m_user(),
	  m_algo(xmrig::ALGO_CRYPTONIGHT),
	  m_variant(xmrig::VARIANT_AUTO),
	  m_port(kDefaultPort),
	  m_proxy_host(),
	  m_proxy_port(kDefaultProxyPort),
	  m_keystream()
{
}

Url::Url(const std::string & url)
	: m_keepAlive(false),
	  m_nicehash(false),
#ifndef XMRIG_NO_SSL
	  m_ssl(false),
#endif
#ifndef XMRIG_NO_UDP
	  m_udp(false),
	  m_udpBlind(0),
#endif
	  m_host(),
	  m_password(),
	  m_user(),
	  m_algo(xmrig::ALGO_CRYPTONIGHT),
	  m_variant(xmrig::VARIANT_AUTO),
	  m_port(kDefaultPort),
	  m_proxy_host(),
	  m_proxy_port(kDefaultProxyPort),
	  m_keystream()
{
	parse(url);
}

Url::Url(const std::string & host,
         uint16_t port,
         const std::string & user,
         const std::string & password,
         bool keepAlive,
         bool ssl,
         bool nicehash,
         xmrig::Variant variant)
	: m_keepAlive(keepAlive),
	  m_nicehash(nicehash),
#ifndef XMRIG_NO_SSL
	  m_ssl(ssl),
#endif
#ifndef XMRIG_NO_UDP
	  m_udp(false),
	  m_udpBlind(0),
#endif
	  m_host(host),
	  m_password(password),
	  m_user(user),
	  m_algo(xmrig::ALGO_CRYPTONIGHT),
	  m_variant(variant),
	  m_port(port),
	  m_proxy_host(),
	  m_proxy_port(kDefaultProxyPort),
	  m_keystream()
{
}

Url::~Url()
{
}

/**
 * @brief Parse url.
 *
 * Valid urls:
 * example.com
 * example.com:3333
 * example.com:3333#keystream
 * example.com:3333@proxy
 * example.com:3333@proxy:8080
 * example.com:3333#keystream@proxy
 * example.com:3333#keystream@proxy:8080
 * stratum+tcp://example.com
 * stratum+tcp://example.com:3333
 * stratum+tcp://example.com:3333#keystream
 * stratum+tcp://example.com:3333@proxy
 * stratum+tcp://example.com:3333@proxy:8080
 * stratum+tcp://example.com:3333#keystream@proxy
 * stratum+tcp://example.com:3333#keystream@proxy:8080
 *
 * @param url
 */
bool Url::parse(const std::string & url)
{
	size_t base = 0;

	const size_t p = url.find("://");
	if(p != std::string::npos)
	{
		static const std::string STRATUM_PREFIX = "stratum+tcp://";
		if(strncasecmp(url.c_str(), STRATUM_PREFIX.c_str(), STRATUM_PREFIX.size()))
		{
			return false;
		}

		base = STRATUM_PREFIX.size();
	}

	const std::string path = url.substr(base);
	if(path.empty() || path[0] == '/')
	{
		return false;
	}

	const size_t port = path.find_first_of(':');
	size_t portini = port;
	if(port != std::string::npos)
	{
		m_host = path.substr(0, port);
		m_port = (uint16_t) strtol(path.substr(port + 1).c_str(), nullptr, 10);
	}
	else
	{
		portini = 0;
	}

	const size_t proxy = path.find_first_of('@', portini);
	const size_t keystream = path.find_first_of('#', portini);
	if(keystream != std::string::npos)
	{
		if(port == std::string::npos)
		{
			m_host = path.substr(0, keystream);
		}
		if(proxy != std::string::npos)
		{
			m_keystream = path.substr(keystream + 1, proxy - keystream - 1);
		}
		else
		{
			m_keystream = path.substr(keystream + 1);
		}
	}

	if(proxy == std::string::npos)
	{
		if(port == std::string::npos && keystream == std::string::npos)
		{
			m_host = path;
		}
		return true;
	}
	else
	{
		if(port == std::string::npos && keystream == std::string::npos)
		{
			m_host = path.substr(0, proxy);
		}
	}

	const size_t proxyini = proxy + 1;

	const size_t proxyport = path.find_first_of(':', proxyini);
	if(proxyport == std::string::npos)
	{
		m_proxy_host = path.substr(proxyini);
		return false;
	}

	m_proxy_host = path.substr(proxyini, proxyport - proxyini);
	m_proxy_port = (uint16_t) strtol(path.substr(proxyport + 1).c_str(), nullptr, 10);

	return true;
}

bool Url::setUserpass(const std::string & userpass)
{
	const size_t p = userpass.find_first_of(':');
	if(p == std::string::npos)
	{
		return false;
	}

	setUser(userpass.substr(0, p));
	setPassword(userpass.substr(p + 1));

	return true;
}

void Url::adjust(const xmrig::Algo algo)
{
	if(!isValid())
	{
		return;
	}

	m_algo = algo;


	if(m_host.find(".nicehash.com") != std::string::npos)
	{
		m_keepAlive = false;
		m_nicehash  = true;
	}

	if(m_host.find(".minergate.com") != std::string::npos)
	{
		m_keepAlive = false;
	}
}

static std::string & Replace(std::string & str, const std::string & what, const std::string & other)
{
	if(str.empty() || what.empty() || what == other)
	{
		return str;
	}

	size_t start_pos = 0;
	while((start_pos = str.find(what, start_pos)) != std::string::npos)
	{
		str.replace(start_pos, what.length(), other);
		start_pos += other.length();
	}

	return str;
}

static std::string GetHostName()
{
	char hostname[1024] = {'\0'};
	if(0 == gethostname(hostname, sizeof(hostname) - 1))
	{
		// get hostname
		for(int i = 0; hostname[i] != '\0'; ++i)
		{
			if(hostname[i] == '.' || hostname[i] == '+')
			{
				hostname[i] = '_';
			}
		}
	}

	return hostname;
}

static std::string GetIpAddrs()
{
	std::string ret;
#ifndef _WIN32
	struct ifaddrs* ifAddrStruct = NULL;
	struct ifaddrs* ifa = NULL;
	void* tmpAddrPtr = NULL;

	if(0 == getifaddrs(&ifAddrStruct))
	{
		for(ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next)
		{
			if(!ifa->ifa_addr)
			{
				continue;
			}
			if(ifa->ifa_addr->sa_family == AF_INET)    // check it is IP4
			{
				// is a valid IP4 Address
				tmpAddrPtr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
				char addressBuffer[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
				ret = addressBuffer;
			}
			else if(ifa->ifa_addr->sa_family == AF_INET6)      // check it is IP6
			{
				// is a valid IP6 Address
				tmpAddrPtr = &((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr;
				char addressBuffer[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6, tmpAddrPtr, addressBuffer, INET6_ADDRSTRLEN);
				ret = addressBuffer;
			}
		}
	}
	if(ifAddrStruct != NULL)
	{
		freeifaddrs(ifAddrStruct);
	}
#else
	char hostname[1024] = {'\0'};
	gethostname(hostname, sizeof(hostname) - 1);
	struct hostent* hostentry = gethostbyname(hostname);

	// get ip
	if(hostentry != NULL)
	{
		const char* const ipbuf = inet_ntoa(*((struct in_addr*)hostentry->h_addr_list[0]));
		if(ipbuf != NULL)
		{
			ret = ipbuf;
		}
	}
#endif
	for(size_t i = 0; i < ret.size(); ++i)
	{
		if(ret[i] == '.' || ret[i] == '+' || ret[i] == '_')
		{
			ret[i] = '_';
		}
	}
	return ret;
}

static std::string replaceWithTokens(const std::string & value)
{
	static const std::string HOST_NAME = GetHostName();
	static const std::string IP_ADDRS = GetIpAddrs();

	// set user replacing tokens
	std::string ret = value;
	ret = Replace(ret, "%HOST_NAME%", HOST_NAME);
	ret = Replace(ret, "%IP_ADDRS%", IP_ADDRS);
	return ret;
}

void Url::setPassword(const std::string & password)
{
	m_password = replaceWithTokens(password);
}


void Url::setUser(const std::string & user)
{
	m_user = replaceWithTokens(user);
}

void Url::setVariant(const xmrig::Variant variant)
{
	switch(variant)
	{
	case xmrig::VARIANT_AUTO:
	case xmrig::VARIANT_NONE:
	case xmrig::VARIANT_V1:
	case xmrig::VARIANT_V2:
		m_variant = variant;
		break;

	default:
		break;
	}
}

void Url::copyKeystream(char* keystreamDest, const size_t keystreamLen) const
{
	if(hasKeystream())
	{
		memset(keystreamDest, 1, keystreamLen);
		memcpy(keystreamDest, m_keystream.c_str(), std::min(keystreamLen, m_keystream.size()));
	}
}

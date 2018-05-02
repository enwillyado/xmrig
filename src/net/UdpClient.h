/* XMRig
 * Copyright 2010      Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2012-2014 pooler      <pooler@litecoinpool.org>
 * Copyright 2014      Lucas Jones <https://github.com/lucasjones>
 * Copyright 2014-2016 Wolf9466    <https://github.com/OhGodAPet>
 * Copyright 2016      Jay D Dee   <jayddee246@gmail.com>
 * Copyright 2016-2017 XMRig       <support@xmrig.com>
 * Copyright 2018      enWILLYado  <xmrig@enwillyado.com>
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

#ifndef __UDP_CLIENT_H__
#define __UDP_CLIENT_H__

#ifndef XMRIG_NO_UDP

#include "uv.h"

#include <string>
#include <time.h>

class UdpClientKey
{
public:
	UdpClientKey();
	UdpClientKey(const std::string & sender, const unsigned short port);
	~UdpClientKey();

	const std::string & sender() const;

	const unsigned short & port() const;

	bool operator<(const UdpClientKey & other) const;

private:
	std::string m_sender;
	unsigned short m_port;
};

class UdpClientValue
{
public:
	UdpClientValue();
	~UdpClientValue();

	void setId(const unsigned short id);

	void timealive();

	const unsigned short & id() const;

	uv_udp_send_t send_req;

private:
	unsigned short m_id;
	time_t m_last_time;
	bool m_valid;
};

class UdpClient
{
public:
	UdpClient();
	UdpClient(const UdpClientKey & key, const UdpClientValue & value);
	~UdpClient();

	void setKey(const UdpClientKey & key);
	void setValue(const UdpClientValue & key);

	const UdpClientKey & key() const;
	const UdpClientValue & value() const;

private:
	UdpClientKey m_key;
	UdpClientValue m_value;
};

#endif

#endif /* __UDP_CLIENT_H__ */

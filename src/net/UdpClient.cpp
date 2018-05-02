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
#ifndef XMRIG_NO_UDP

#include <net/UdpClient.h>
#include <log/Log.h>

UdpClientKey::UdpClientKey()
	: m_sender(),
	  m_port(0)
{
}

UdpClientKey::UdpClientKey(const std::string & sender, const unsigned short port)
	: m_sender(sender),
	  m_port(port)
{
}

UdpClientKey::~UdpClientKey()
{

}

const std::string & UdpClientKey::sender() const
{
	return m_sender;
}

const unsigned short & UdpClientKey::port() const
{
	return m_port;
}

bool UdpClientKey::operator<(const UdpClientKey & other) const
{
	return (m_sender + Log::ToString(m_port)) < (other.m_sender + Log::ToString(other.m_port));
}

//////////////////////////////////////////////////////////////////////////

UdpClientValue::UdpClientValue()
	: send_req(),
	  m_id(),
	  m_last_time(time(NULL))
{
}

UdpClientValue::~UdpClientValue()
{
}

void UdpClientValue::setId(const unsigned short id)
{
	m_id = id;
}

void UdpClientValue::timealive()
{
	m_last_time = time(NULL);
}

const unsigned short & UdpClientValue::id() const
{
	return m_id;
}

//////////////////////////////////////////////////////////////////////////

UdpClient::UdpClient()
	: m_key(),
	  m_value()
{
}

UdpClient::UdpClient(const UdpClientKey & key, const UdpClientValue & value)
	: m_key(key),
	  m_value(value)
{
}

UdpClient::~UdpClient()
{
}

const UdpClientKey & UdpClient::key() const
{
	return m_key;
}

const UdpClientValue & UdpClient::value() const
{
	return m_value;
}


#endif
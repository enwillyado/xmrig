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

UdpClient::UdpClient()
	: m_sender(),
	  m_port(0),
	  m_id(0),
	  m_valid(false)
{
}

UdpClient::UdpClient(const std::string & sender, const unsigned short port)
	: m_sender(sender),
	  m_port(port),
	  m_id(0),
	  m_valid(true)
{
}

UdpClient::~UdpClient()
{

}

void UdpClient::setId(const unsigned short id)
{
	m_id = id;
}

const std::string & UdpClient::sender() const
{
	return m_sender;
}

const unsigned short & UdpClient::port() const
{
	return m_port;
}

const unsigned short & UdpClient::id() const
{
	return m_id;
}

bool UdpClient::operator<(const UdpClient & other) const
{
	return (m_sender + Log::ToString(m_port)) < (other.m_sender + Log::ToString(other.m_port));
}

#endif

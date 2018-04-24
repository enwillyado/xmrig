/* XMRig
 * Copyright 2010      Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2012-2014 pooler      <pooler@litecoinpool.org>
 * Copyright 2014      Lucas Jones <https://github.com/lucasjones>
 * Copyright 2014-2016 Wolf9466    <https://github.com/OhGodAPet>
 * Copyright 2016      Jay D Dee   <jayddee246@gmail.com>
 * Copyright 2016-2018 XMRig       <support@xmrig.com>
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

#include <inttypes.h>
#include <iterator>
#include <stdio.h>
#include <string.h>
#include <utility>

#include <assert.h>

#include "interfaces/IClientListener.h"
#include "log/Log.h"
#include "net/Client.h"
#include "net/Url.h"
#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#ifdef XMRIG_PROXY_PROJECT
#include "proxy/JobResult.h"
#else
#include "net/JobResult.h"
#endif


#ifdef _MSC_VER
#define strncasecmp(x,y,z) _strnicmp(x,y,z)
#endif


int64_t Client::m_sequence = 1;


Client::Client(int id, const std::string & agent, IClientListener* listener) :
	m_ipv6(false),
	m_nicehash(false),
	m_quiet(false),
	m_encrypted(false),
	m_agent(agent),
	m_listener(listener),
	m_id(id),
	m_retryPause(5000),
	m_failures(0),
	m_recvBufPos(0),
	m_state(UnconnectedState),
	m_expire(0),
	m_req(),
	m_stream(nullptr),
	m_socket(),
	m_ctx(),
	m_tls()
{
	memset(&m_hints, 0, sizeof(m_hints));
	memset(m_keystream, 0, sizeof(m_keystream));

	m_resolver.data = this;

	m_hints.ai_family   = AF_UNSPEC;
	m_hints.ai_socktype = SOCK_STREAM;
	m_hints.ai_protocol = IPPROTO_TCP;

	m_recvBuf.base = m_buf;
	m_recvBuf.len  = sizeof(m_buf);

#ifndef XMRIG_PROXY_PROJECT
	m_keepAliveTimer.data = this;
	uv_timer_init(uv_default_loop(), &m_keepAliveTimer);
#endif
}


Client::~Client()
{
}


void Client::connect()
{
	resolve(m_url.host());
}


/**
 * @brief Connect to server.
 *
 * @param url
 */
void Client::connect(const Url & url)
{
	setUrl(url);
	resolve(m_url.host());
}


void Client::setUrl(const Url & url)
{
	if(false == url.isValid())
	{
		return;
	}

	if(url.hasKeystream())
	{
		url.copyKeystream(m_keystream, sizeof(m_keystream));
		m_encrypted = true;
	}
	else
	{
		m_encrypted = false;
	}

	m_url = url;
}


void Client::tick(uint64_t now)
{
	if(m_expire == 0 || now < m_expire)
	{
		return;
	}

	if(m_state == ConnectedState)
	{
		LOG_DEBUG_ERR("[" << m_url.host() << ":" << m_url.port() << "] timeout");
		close();
	}


	if(m_state == ConnectingState)
	{
		connect();
	}
}

bool Client::disconnect()
{
#ifndef XMRIG_PROXY_PROJECT
	uv_timer_stop(&m_keepAliveTimer);
#endif

	m_expire   = 0;
	m_failures = -1;

	return close();
}


int64_t Client::submit(const JobResult & result)
{
#ifdef XMRIG_PROXY_PROJECT
	const std::string nonce = result.nonce;
	const std::string data  = result.result;
#else
	char nonce_buffer[9];
	char data_buffer[65];

	char* nonceChar = (char*)(&result.nonce);
	Job::toHex(std::string(nonceChar, 4), nonce_buffer);
	nonce_buffer[8] = '\0';

	char* resultChar = (char*)(&result.result);
	Job::toHex(std::string(resultChar, 32), data_buffer);
	data_buffer[64] = '\0';

	const std::string nonce = nonce_buffer;
	const std::string data  = data_buffer;
#endif

	const size_t size = snprintf(m_sendBuf, sizeof(m_sendBuf),
	                             "{\"id\":%" PRIu64
	                             ",\"jsonrpc\":\"2.0\",\"method\":\"submit\",\"params\":{\"id\":\"%s\",\"job_id\":\"%s\",\"nonce\":\"%s\",\"result\":\"%s\"}}\n",
	                             m_sequence, m_rpcId.data().c_str(), result.jobId.data().c_str(), nonce.c_str(), data.c_str());

	m_results[m_sequence] = SubmitResult(m_sequence, result.diff, result.actualDiff());
	return send(size);
}


bool Client::close()
{
	if(m_state == UnconnectedState || m_state == ClosingState || m_stream == nullptr || !uv_is_writable(m_stream))
	{
		return false;
	}

	setState(ClosingState);

	if(uv_is_closing(reinterpret_cast<uv_handle_t*>(&m_socket)) == 0)
	{
		uv_close(reinterpret_cast<uv_handle_t*>(&m_socket), Client::onClose);
	}

	return true;
}


bool Client::isCriticalError(const std::string & message)
{
	if(message.empty())
	{
		return false;
	}

	if(message == "Unauthenticated")
	{
		return true;
	}

	if(message == "your IP is banned")
	{
		return true;
	}

	if(message == "IP Address currently banned")
	{
		return true;
	}

	return false;
}


bool Client::parseJob(const rapidjson::Value & params, int* code)
{
	if(!params.IsObject())
	{
		*code = 2;
		return false;
	}

	Job job(m_id, m_nicehash, m_url.algo(), m_url.variant());
	if(!job.setId(params["job_id"].GetString()))
	{
		*code = 3;
		return false;
	}

	if(!job.setBlob(params["blob"].GetString()))
	{
		*code = 4;
		return false;
	}

	if(!job.setTarget(params["target"].GetString()))
	{
		*code = 5;
		return false;
	}

	if(params.HasMember("coin"))
	{
		job.setCoin(params["coin"].GetString());
	}

	if(params.HasMember("variant"))
	{
		job.setVariant(params["variant"].GetInt());
	}

	if(m_job != job)
	{
		m_jobs++;
		m_job = std::move(job);
		return true;
	}

	if(m_jobs == 0)    // https://github.com/xmrig/xmrig/issues/459
	{
		return false;
	}

	if(!m_quiet)
	{
		LOG_WARN("[" << m_url.host() << ":" << m_url.port() << "] duplicate job received, reconnect");
	}

	close();
	return false;
}


bool Client::parseLogin(const rapidjson::Value & result, int* code)
{
	if(!m_rpcId.setId(result["id"].GetString()))
	{
		*code = 1;
		return false;
	}

	m_nicehash = m_url.isNicehash();

	const rapidjson::Value & keystream = result["keystream"];
	if(true == keystream.IsString())
	{
		const std::string newkeystream = keystream.GetString();
		memcpy(m_keystream, newkeystream.c_str(), std::min(sizeof(m_keystream), newkeystream.size()));
		m_encrypted = true;
	}

	if(result.HasMember("extensions"))
	{
		parseExtensions(result["extensions"]);
	}

	const bool rc = parseJob(result["job"], code);
	m_jobs = 0;

	return rc;
}


int Client::resolve(const std::string & host)
{
	setState(HostLookupState);

	m_expire     = 0;
	m_recvBufPos = 0;

	if(m_failures == -1)
	{
		m_failures = 0;
	}

	const int r = uv_getaddrinfo(uv_default_loop(), &m_resolver, Client::onResolved, host.c_str(), NULL, &m_hints);
	if(r)
	{
		if(!m_quiet)
		{
			LOG_ERR("[" << host << ":" << m_url.port() << "] getaddrinfo error: \"" << uv_strerror(r) << "\"");
		}
		return 1;
	}

	return 0;
}


int64_t Client::send(size_t size, const bool encrypted)
{
	LOG_DEBUG("[" << m_url.host() << ":" << m_url.port() << "] send(" << size << " bytes): \"" << m_sendBuf <<
	          "\"");
	if((state() != ConnectedState && state() != ProxingState) || !uv_is_writable(m_stream))
	{
		LOG_DEBUG_ERR("[" << m_url.host() << ":" << m_url.port() << "] send failed, invalid state: " << m_state);
		return -1;
	}

	if(encrypted && m_encrypted)
	{
		// Encrypt
		for(size_t i = 0; i < std::min(size, sizeof(SendBuf)); ++i)
		{
			m_sendBuf[i] ^= m_keystream[i];
		}

		char* send_encr_hex = static_cast<char*>(malloc(size * 2 + 1));
		memset(send_encr_hex, 0, size * 2 + 1);
		Job::toHex(std::string(m_sendBuf, size), send_encr_hex);
		send_encr_hex[size * 2] = '\0';
		LOG_DEBUG("[" << m_url.host() << ":" << m_url.port() << "] send encr.(" << size << " bytes): \"0x"  <<
		          send_encr_hex << "\"");
		free(send_encr_hex);
	}

	uv_buf_t buf = uv_buf_init(m_sendBuf, (unsigned int) size);

	if(m_url.isSsl())
	{
		uv_buf_t dcrypted;
		dcrypted.base = m_sendBuf;
		dcrypted.len = size;
		uv_tls_write(&m_tls, &dcrypted, Client::onWriteTls);
	}
	else
	{
		if(uv_try_write(m_stream, &buf, 1) < 0)
		{
			close();
			return -1;
		}
	}

	m_expire = uv_now(uv_default_loop()) + kResponseTimeout;
	return m_sequence++;
}

void Client::onWriteTls(uv_tls_t* utls, int status)
{
	if(status == -1)
	{
		fprintf(stderr, "error on_write");
		return;
	}

	uv_tls_read(utls, Client::onReadTls);
}

void Client::onReadTls(uv_tls_t* strm, ssize_t nrd, const uv_buf_t* buf)
{
	uv_tcp_t* socket = (uv_tcp_t*)strm->tcp_hdl->read_req.data;
	auto client = getClientFromSocket(socket);
	client->m_recvBuf = *buf;
	client->processRead(nrd, buf);
}

void Client::connect(const std::vector<addrinfo*> & ipv4, const std::vector<addrinfo*> & ipv6)
{
	addrinfo* addr = nullptr;
	m_ipv6         = ipv4.empty() && !ipv6.empty();

	if(m_ipv6)
	{
		addr = ipv6[ipv6.size() == 1 ? 0 : rand() % ipv6.size()];
		uv_ip6_name(reinterpret_cast<sockaddr_in6*>(addr->ai_addr), (char*)m_ip.c_str(), 45);
	}
	else
	{
		addr = ipv4[ipv4.size() == 1 ? 0 : rand() % ipv4.size()];
		uv_ip4_name(reinterpret_cast<sockaddr_in*>(addr->ai_addr), (char*)m_ip.c_str(), 16);
	}

	connect(addr->ai_addr);
}


void Client::connect(struct sockaddr* addr)
{
	setState(ConnectingState);

	reinterpret_cast<struct sockaddr_in*>(addr)->sin_port = htons(m_url.port());

	m_req.data = this;
	m_socket.data = this;

	uv_tcp_init(uv_default_loop(), &m_socket);
	uv_tcp_nodelay(&m_socket, 1);

#ifndef WIN32
	uv_tcp_keepalive(&m_socket, 1, 60);
#endif

	if(m_url.isSsl())
	{
		evt_ctx_init_ex(&m_ctx, NULL, NULL);
		evt_ctx_set_nio(&m_ctx, NULL, uv_tls_writer);
		getClientFromSocket(&m_socket) = this;
		uv_tcp_connect(&m_req, &m_socket, reinterpret_cast<const sockaddr*>(addr), Client::onConnect);
	}
	else
	{
		uv_tcp_connect(&m_req, &m_socket, reinterpret_cast<const sockaddr*>(addr), Client::onConnect);
	}
}

void Client::prelogin()
{
	if(m_url.isProxyed())
	{
		setState(ProxingState);
		const std::string buffer = std::string("CONNECT ") + m_url.finalHost() + ":" +
		                           std::to_string((unsigned long long)(m_url.finalPort())) + " HTTP/1.1\n";

		const size_t size = buffer.size();
		memcpy(m_sendBuf, buffer.c_str(), size);
		m_sendBuf[size]     = '\n';
		m_sendBuf[size + 1] = '\0';

		LOG_DEBUG("Prelogin send (" << size << " bytes): \"" << m_sendBuf << "\"");
		send(size + 1, false);
	}
	else
	{
		setState(ConnectedState);
		login();
	}
}

void Client::login()
{
	m_results.clear();

	rapidjson::Document doc;
	doc.SetObject();

	auto & allocator = doc.GetAllocator();

	doc.AddMember("id",      1,       allocator);
	doc.AddMember("jsonrpc", "2.0",   allocator);
	doc.AddMember("method",  "login", allocator);

	rapidjson::Value params(rapidjson::kObjectType);
	params.AddMember("login", rapidjson::StringRef(m_url.user().c_str()),     allocator);
	params.AddMember("pass",  rapidjson::StringRef(m_url.password().c_str()), allocator);
	params.AddMember("agent", rapidjson::StringRef(m_agent.c_str()),	      allocator);

	doc.AddMember("params", params, allocator);

	rapidjson::StringBuffer buffer(0, 512);
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	doc.Accept(writer);

	const size_t size = buffer.GetSize();
	if(size > (sizeof(m_buf) - 2))
	{
		return;
	}

	memcpy(m_sendBuf, buffer.GetString(), size);
	m_sendBuf[size]     = '\n';
	m_sendBuf[size + 1] = '\0';

	send(size + 1);
}


void Client::parse(char* line, size_t len)
{
	startTimeout();

	line[len - 1] = '\0';

	LOG_DEBUG("[" << m_url.host() << ":" << m_url.port() << "] received (" << len << " bytes): \"" << line <<
	          "\"");

	if(len < 32 || line[0] != '{')
	{
		if(!m_quiet)
		{
			LOG_ERR("[" << m_url.host() << ":" << m_url.port() << "] JSON decode failed");
		}

		return;
	}

	rapidjson::Document doc;
	if(doc.ParseInsitu(line).HasParseError())
	{
		if(!m_quiet)
		{
			LOG_ERR("[" << m_url.host() << ":" << m_url.port() << "] JSON decode failed: \"" <<
			        rapidjson::GetParseError_En(doc.GetParseError()) << "\"");
		}

		return;
	}

	if(!doc.IsObject())
	{
		return;
	}

	const rapidjson::Value & id = doc["id"];
	if(id.IsInt64())
	{
		parseResponse(id.GetInt64(), doc["result"], doc["error"]);
	}
	else
	{
		parseNotification(doc["method"].GetString(), doc["params"], doc["error"]);
	}
}


void Client::parseExtensions(const rapidjson::Value & value)
{
	if(!value.IsArray())
	{
		return;
	}

	for(size_t i = 0; i < value.GetArray().Size(); ++i)
	{
		const rapidjson::Value & ext = value.GetArray()[i];
		if(!ext.IsString())
		{
			continue;
		}

		if(strcmp(ext.GetString(), "nicehash") == 0)
		{
			m_nicehash = true;
		}
	}
}


void Client::parseNotification(const std::string & method, const rapidjson::Value & params,
                               const rapidjson::Value & error)
{
	if(error.IsObject())
	{
		if(!m_quiet)
		{
			LOG_ERR("[" << m_url.host() << ":" << m_url.port() << "] error: \"" << error["message"].GetString() <<
			        "\", code: " << error["code"].GetInt());
		}
		return;
	}

	if(0 == method.size())
	{
		return;
	}

	if(method == "job")
	{
		int code = -1;
		if(parseJob(params, &code))
		{
			m_listener->onJobReceived(this, m_job);
		}

		return;
	}

	LOG_WARN("[" << m_url.host() << ":" << m_url.port() << "] unsupported method: \"" << method << "\"");
}


void Client::parseResponse(int64_t id, const rapidjson::Value & result, const rapidjson::Value & error)
{
	if(error.IsObject())
	{
		const std::string message = error["message"].GetString();

		auto it = m_results.find(id);
		if(it != m_results.end())
		{
			it->second.done();
			m_listener->onResultAccepted(this, it->second, message);
			m_results.erase(it);
		}
		else if(!m_quiet)
		{
			LOG_ERR("[" << m_url.host() << ":" << m_url.port() << "] error: \"" << message << "\", code: " <<
			        error["code"].GetInt());
		}

		if(id == 1 || isCriticalError(message))
		{
			close();
		}

		return;
	}

	if(!result.IsObject())
	{
		return;
	}

	if(id == 1)
	{
		int code = -1;
		if(!parseLogin(result, &code))
		{
			if(!m_quiet)
			{
				LOG_ERR("[" << m_url.host() << ":" << m_url.port() << "] login error code: " << code);
			}

			close();
			return;
		}

		m_failures = 0;
		m_listener->onLoginSuccess(this);
		m_listener->onJobReceived(this, m_job);
		return;
	}

	auto it = m_results.find(id);
	if(it != m_results.end())
	{
		it->second.done();
		m_listener->onResultAccepted(this, it->second, "");
		m_results.erase(it);
	}
}


void Client::ping()
{
	send(snprintf(m_sendBuf, sizeof(m_sendBuf),
	              "{\"id\":%" PRId64 ",\"jsonrpc\":\"2.0\",\"method\":\"keepalived\",\"params\":{\"id\":\"%s\"}}\n",
	              m_sequence, m_rpcId.data().c_str()));
}


void Client::reconnect()
{
	if(m_failures == -1)
	{
		return m_listener->onClose(this, -1);
	}

	setState(ConnectingState);

#ifndef XMRIG_PROXY_PROJECT
	if(m_url.isKeepAlive())
	{
		uv_timer_stop(&m_keepAliveTimer);
	}
#endif

	m_failures++;
	m_listener->onClose(this, (int) m_failures);

	m_expire = uv_now(uv_default_loop()) + m_retryPause;
}


void Client::setState(SocketState state)
{
	LOG_DEBUG("[" << m_url.host() << ":" << m_url.port() << "] state: " << state);

	if(m_state == state)
	{
		return;
	}

	m_state = state;
}


void Client::startTimeout()
{
	m_expire = 0;

#ifndef XMRIG_PROXY_PROJECT
	if(!m_url.isKeepAlive())
	{
		return;
	}

	uv_timer_start(&m_keepAliveTimer, &Client::onTimeout, kKeepAliveTimeout, 0);
#endif
}

void Client::onTimeout(uv_timer_t* handle)
{
	getClient(handle->data)->ping();
}

void Client::onAllocBuffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
	auto client = getClient(handle->data);

	buf->base = &client->m_recvBuf.base[client->m_recvBufPos];
	buf->len  = client->m_recvBuf.len - (unsigned long)client->m_recvBufPos;
}


void Client::onClose(uv_handle_t* handle)
{
	auto client = getClient(handle->data);

	client->setState(UnconnectedState);
	client->reconnect();
}


void Client::onConnect(uv_connect_t* req, int status)
{
	auto client = getClient(req->data);
	client->processConnect(req, status);
}

void Client::processConnect(uv_connect_t* req, int status)
{
	if(status < 0)
	{
		if(!m_quiet)
		{
			LOG_ERR("[" << m_url.host() << ":" << m_url.port() << "] connect error: \"" << uv_strerror(
			            status) << "\"");
		}

		delete req;
		close();
		return;
	}

	m_stream = static_cast<uv_stream_t*>(req->handle);
	m_stream->data = req->data;

	if(m_url.isSsl())
	{
		uv_tcp_t* tcp = (uv_tcp_t*)req->handle;

		//free on uv_tls_close
		if(uv_tls_init(&m_ctx, tcp, &m_tls) < 0)
		{
			return;
		}
		assert(tcp->data == &m_tls);
		uv_tls_connect(&m_tls, Client::onHandshake);
	}
	else
	{
		m_stream = static_cast<uv_stream_t*>(req->handle);
		m_stream->data = req->data;

		uv_read_start(m_stream, Client::onAllocBuffer, Client::onRead);
		delete req;

		prelogin();
	}
}

void Client::onHandshake(uv_tls_t* tls, int status)
{
	assert(tls->tcp_hdl->data == tls);
	uv_tcp_t* socket = (uv_tcp_t*)tls->tcp_hdl->read_req.data;
	auto client = getClientFromSocket(socket);
	client->processHandhake(status);
}

void Client::processHandhake(int status)
{
	if(0 == status)    // TLS connection not failed
	{
		prelogin();
	}
	else
	{
		uv_tls_close(&m_tls, (uv_tls_close_cb)free);
	}
}

void Client::onRead(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
	auto client = getClient(stream->data);
	client->processRead(nread, buf);
}

void Client::processRead(ssize_t nread, const uv_buf_t* buf)
{
	if(nread < 0)
	{
		if(nread != UV_EOF && m_quiet)
		{
			LOG_ERR("[" << m_url.host() << ":" << m_url.port() << "] read error: \"" << uv_strerror((
			            int) nread) << "\"");
		}

		close();
		return;
	}

	if((size_t) nread > (sizeof(Buf) - 8 - m_recvBufPos))
	{
		close();
		return;
	}

	if(state() == ProxingState)
	{
		const char* const content = buf->base;
		LOG_DEBUG("[" << m_url.host() << ":" << m_url.port() << "] received from proxy (" << nread <<
		          " bytes): \"" << content << "\"");

		if(content == strstr(content, "HTTP/1.1 200"))
		{
			LOG_INFO("[" << m_url.host() << ":" << m_url.port() << "] Proxy connected to " <<
			         m_url.finalHost() << ":" << m_url.finalPort() << "!");
			setState(ConnectedState);
			login();
		}
		return;
	}

	m_recvBufPos += nread;

	char* end;
	char* start = m_recvBuf.base;
	size_t remaining = m_recvBufPos;

	if(m_encrypted)
	{
		char* read_encr_hex = static_cast<char*>(malloc(nread * 2 + 1));
		memset(read_encr_hex, 0, nread * 2 + 1);
		Job::toHex(std::string(start, nread), read_encr_hex);
		LOG_DEBUG("[" <<  m_ip << "] read encr. (" << nread << "  bytes): \"0x" << read_encr_hex << "\"");
		free(read_encr_hex);

		// DeEncrypt
		for(int i = 0; i < (int)nread; ++i)
		{
			start[i] ^= m_keystream[i];
		}
	}

	while((end = static_cast<char*>(memchr(start, '\n', remaining))) != nullptr)
	{
		end++;
		size_t len = end - start;
		parse(start, len);

		remaining -= len;
		start = end;
	}

	if(remaining == 0)
	{
		m_recvBufPos = 0;
		return;
	}

	if(start == m_recvBuf.base)
	{
		return;
	}

	memcpy(m_recvBuf.base, start, remaining);
	m_recvBufPos = remaining;
}


void Client::onResolved(uv_getaddrinfo_t* req, int status, struct addrinfo* res)
{
	auto client = getClient(req->data);
	if(status < 0)
	{
		if(!client->m_quiet)
		{
			LOG_ERR("[" << client->m_url.host() << ":" << client->m_url.port() << "] DNS error: \"" << uv_strerror(
			            status) << "\"");
		}

		return client->reconnect();
	}

	addrinfo* ptr = res;
	std::vector<addrinfo*> ipv4;
	std::vector<addrinfo*> ipv6;

	while(ptr != nullptr)
	{
		if(ptr->ai_family == AF_INET)
		{
			ipv4.push_back(ptr);
		}

		if(ptr->ai_family == AF_INET6)
		{
			ipv6.push_back(ptr);
		}

		ptr = ptr->ai_next;
	}

	if(ipv4.empty() && ipv6.empty())
	{
		if(!client->m_quiet)
		{
			LOG_ERR("[" << client->m_url.host() << ":" << client->m_url.port() <<
			        "] DNS error: \"No IPv4 (A) or IPv6 (AAAA) records found\"");
		}

		uv_freeaddrinfo(res);
		return client->reconnect();
	}

	client->connect(ipv4, ipv6);
	uv_freeaddrinfo(res);
}

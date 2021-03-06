/* XMRig
 * Copyright 2010      Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2012-2014 pooler      <pooler@litecoinpool.org>
 * Copyright 2014      Lucas Jones <https://github.com/lucasjones>
 * Copyright 2014-2016 Wolf9466    <https://github.com/OhGodAPet>
 * Copyright 2016      Jay D Dee   <jayddee246@gmail.com>
 * Copyright 2017-2018 XMR-Stak    <https://github.com/fireice-uk>, <https://github.com/psychocrypt>
 * Copyright 2018      Lee Clagett <https://github.com/vtnerd>
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


#include <memory.h>


#include "crypto/CryptoNight.h"
#include "Mem.h"
#include "Options.h"
#include "xmrig.h"


bool Mem::m_doubleHash                = false;
int Mem::m_algo                       = 0;
int Mem::m_flags                      = 0;
int Mem::m_threads                    = 0;
size_t Mem::m_offset                  = 0;
size_t Mem::m_size                    = 0;
VAR_ALIGN(16, uint8_t* Mem::m_memory) = nullptr;


cryptonight_ctx** Mem::create(int threadId)
{
#   ifndef XMRIG_NO_AEON
	if(m_algo == xmrig::ALGO_CRYPTONIGHT_LITE)
	{
		return createLite(threadId);
	}
#   endif

	cryptonight_ctx** ctx = new cryptonight_ctx*[2];

	cryptonight_ctx* ctx0 = reinterpret_cast<cryptonight_ctx*>(&m_memory[MONERO_MEMORY - sizeof(cryptonight_ctx) *
	                                      (threadId + 1)]);
	ctx0->memory = &m_memory[MONERO_MEMORY * (threadId * 1 + 1)];
	ctx[0] = ctx0;

	if(m_doubleHash)
	{
		cryptonight_ctx* ctx1 = reinterpret_cast<cryptonight_ctx*>(&m_memory[MONERO_MEMORY - sizeof(cryptonight_ctx) *
		                                      (threadId + 1)]);
		ctx1->memory = &m_memory[MONERO_MEMORY * (threadId * 2 + 1)];

		ctx[1] = ctx1;
	}
	else
	{
		ctx[1] = NULL;
	}

	return ctx;
}

void Mem::remove(cryptonight_ctx** ctx)
{
	delete [] ctx;
}


void* Mem::calloc(size_t num, size_t size)
{
	void* mem = &m_memory[m_offset];
	m_offset += (num * size);

	memset(mem, 0, num * size);

	return mem;
}


#ifndef XMRIG_NO_AEON
cryptonight_ctx* Mem::createLite(int threadId)
{
	cryptonight_ctx* ctx;

	if(!m_doubleHash)
	{
		const size_t offset = MONERO_MEMORY * (threadId + 1);

		ctx = reinterpret_cast<cryptonight_ctx*>(&m_memory[offset + AEON_MEMORY]);
		ctx->memory = &m_memory[offset];
		return ctx;
	}

	ctx = reinterpret_cast<cryptonight_ctx*>(&m_memory[MONERO_MEMORY - sizeof(cryptonight_ctx) * (threadId + 1)]);
	ctx->memory = &m_memory[MONERO_MEMORY * (threadId + 1)];

	return ctx;
}
#endif

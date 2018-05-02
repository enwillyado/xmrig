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

#include "crypto/CryptoNight.h"
#include "workers/SingleWorker.h"
#include "workers/Workers.h"

#include <log/Log.h>

#ifndef _WIN32
#include <thread>
#include <unistd.h>
#endif

SingleWorker::SingleWorker(Handle* handle)
	: Worker(handle)
{
}


void SingleWorker::start()
{
	while(Workers::sequence() > 0)
	{
		if(Workers::isPaused())
		{
			do
			{
#ifdef _WIN32
				Sleep(200);
#else
				usleep(200 * 1000);
#endif
			}
			while(Workers::isPaused());

			if(Workers::sequence() == 0)
			{
				break;
			}

			consumeJob();
		}

		while(!Workers::isOutdated(m_sequence))
		{
			*m_job.nonce() = m_result.nonce;

//			LOG_DEBUG("Hashing with nonce " << std::hex << std::setw(8) << std::setfill('0') << m_result.nonce << " by " << m_id << " instance " << m_job.getInstanceId() << " of " << m_job.getInstances());

			if(CryptoNight::hash(m_job, m_result, m_ctx))
			{
				Workers::submit(m_result);
			}

			if((m_count & 0xF) == 0)
			{
				storeStats();
			}

			m_count++;
			m_result.nonce += m_threads;
		}

		consumeJob();
	}
}


bool SingleWorker::resume(const Job & job)
{
	if(m_job.poolId() == -1 && job.poolId() >= 0 && job.id() == m_paused.id())
	{
		m_job          = m_paused;
		m_result       = m_job;
		m_result.nonce = *m_job.nonce();
		return true;
	}

	return false;
}


void SingleWorker::consumeJob()
{
	Job job = Workers::job();
	m_sequence = Workers::sequence();
	if(m_job == job)
	{
		return;
	}

	save(job);

	if(resume(job))
	{
		return;
	}

	m_job = std::move(job);
	m_result = m_job;

	if(m_job.isNicehash())
	{
		m_result.nonce = (0xff000000U & *m_job.nonce()) +
		                 (  0x010000U * (0x100 * m_job.getInstanceId() / m_job.getInstances())) +
		                 (0x00000001U * m_id);
	}
	else
	{
		m_result.nonce = (0x01000000U * (0x100 * m_job.getInstanceId() / m_job.getInstances())) +
		                 (0x00000001U * m_id);
	}
}


void SingleWorker::save(const Job & job)
{
	if(job.poolId() == -1 && m_job.poolId() >= 0)
	{
		m_paused = m_job;
	}
}

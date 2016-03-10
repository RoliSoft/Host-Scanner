#include "UdpScanner.h"
#include "Utils.h"
#include "DataReader.h"
#include "TaskQueueRunner.h"
#include <iostream>
#include <fstream>
#include <algorithm>
#include <string>
#include <chrono>
#include <thread>
#include <regex>
#include <mutex>
#include <tuple>
#include <boost/lexical_cast.hpp>
#include <boost/filesystem.hpp>

using namespace std;
using namespace boost;
namespace fs = boost::filesystem;

unordered_map<unsigned short, struct Payload*> UdpScanner::payloads = unordered_map<unsigned short, struct Payload*>();

void UdpScanner::Scan(Service* service)
{
	if (payloads.size() == 0)
	{
		loadPayloads();
	}

	initSocket(service);

	int iters = timeout / 10;

	for (int i = 0; i <= iters; i++)
	{
		if (i != 0)
		{
			this_thread::sleep_for(chrono::milliseconds(10));
		}

		pollSocket(service, i == iters - 1);

		if (service->reason != AR_InProgress)
		{
			break;
		}
	}
}

void UdpScanner::Scan(Services* services)
{
	if (payloads.size() == 0)
	{
		loadPayloads();
	}

	for (auto service : *services)
	{
		initSocket(service);
	}

	int iters = timeout / 10;
	int left = services->size();

	for (int i = 0; i <= iters; i++)
	{
		if (i != 0)
		{
			this_thread::sleep_for(chrono::milliseconds(10));
		}

		for (auto service : *services)
		{
			if (service->reason != AR_InProgress)
			{
				continue;
			}

			pollSocket(service, i == iters - 1);

			if (service->reason != AR_InProgress)
			{
				left--;
			}
		}

		if (left <= 0)
		{
			break;
		}
	}
}

void* UdpScanner::MakeTask(Service* service)
{
	if (payloads.size() == 0)
	{
		loadPayloads();
	}

	return MFN_TO_PTR(UdpScanner::Task1, this, service);
}

void* UdpScanner::Task1(Service* service)
{
	initSocket(service);

	return MFN_TO_PTR(UdpScanner::Task2, this, service);
}

void* UdpScanner::Task2(Service* service)
{
	if (service->reason == AR_InProgress)
	{
		pollSocket(service, false);
	}

	if (service->reason == AR_InProgress)
	{
		return MFN_TO_PTR(UdpScanner::Task2, this, service);
	}

	return nullptr;
}

void UdpScanner::initSocket(Service* service)
{
	// parse address

	struct addrinfo hint, *info = nullptr;
	memset(&hint, 0, sizeof(struct addrinfo));
	hint.ai_family = AF_UNSPEC; // allow both v4 and v6
	hint.ai_flags = AI_NUMERICHOST; // disable DNS lookups

	auto port = lexical_cast<string>(service->port);
	getaddrinfo(service->address.c_str(), port.c_str(), &hint, &info);
	
	// create socket

	auto sock = socket(info->ai_family, SOCK_DGRAM, IPPROTO_UDP);

	auto data = new UdpScanData();

	service->data = data;
	data->socket  = sock;

	service->reason = AR_InProgress;
	data->timeout   = chrono::system_clock::now() + chrono::milliseconds(timeout);

	// set it to non-blocking

	unsigned long mode = 1;
	ioctlsocket(sock, FIONBIO, &mode);
	
	// select payload based on port

	struct Payload* pld;

	auto iter = payloads.find(service->port);
	if (iter != payloads.end())
	{
		pld = (*iter).second;
	}
	else
	{
		pld = payloads[0];
	}

	// "connect", then send probe packet
	// the connect function in case of UDP just stores the address and port,
	// so send()/recv() will work without them, no need to store the addrinfo

	connect(sock, reinterpret_cast<struct sockaddr*>(info->ai_addr), info->ai_addrlen);
	send(sock, pld->data, pld->datlen, 0);

	// clean-up

	freeaddrinfo(info);
}

void UdpScanner::pollSocket(Service* service, bool last)
{
	if (service->reason != AR_InProgress || service->data == nullptr)
	{
		return;
	}

	auto data = reinterpret_cast<UdpScanData*>(service->data);

	char buf[1024];
	int buflen = 1024;

	// see if any responses were received

	auto res = recv(data->socket, buf, buflen, 0);

	// TODO receive ICMP Port Unreachable messages; may not be possible on Windows

	service->alive = res > 0;

	if (res > 0)
	{
		service->reason = AR_ReplyReceived;

		if (grabBanner)
		{
			// save service banner

			service->banner = string(buf, res);
		}
	}
	else
	{
		if (data->timeout < chrono::system_clock::now())
		{
			service->reason = AR_TimedOut;
		}
#if Unix
		else if (res == -1 && errno == ECONNREFUSED)
		{
			service->reason = AR_IcmpUnreachable;
		}
#endif
		else
		{
			return;
		}
	}

	// clean-up

	service->data = nullptr;

	closesocket(data->socket);

	delete data;
}

unordered_map<unsigned short, Payload*> UdpScanner::GetPayloads()
{
	if (payloads.size() == 0)
	{
		loadPayloads();
	}

	return payloads;
}

void UdpScanner::loadPayloads()
{
	static mutex mtx;
	auto locked = mtx.try_lock();
	if (!locked)
	{
		// wait until running parser finishes before returning
		lock_guard<mutex> guard(mtx);
		return;
	}

	// insert generic payload

	auto pld = new struct Payload();
	unsigned short port = 0;

	pld->data = new char[16] { 0 };
	pld->datlen = 16;

	payloads.emplace(port, pld);

	// open payloads file

	DataReader dr;

	if (!dr.OpenEnv("payloads"))
	{
		log(WRN, "Payloads database was not found!");

		mtx.unlock();
		return;
	}

	unsigned short ptype, pver;

	dr.Read(ptype);
	dr.Read(pver);

	if (ptype != 10)
	{
		log(WRN, "Payloads database type is incorrect.");

		mtx.unlock();
		return;
	}

	if (pver != 1)
	{
		log(WRN, "Payloads database version is not supported.");

		mtx.unlock();
		return;
	}

	unsigned int pnum;
	dr.Read(pnum);

	for (auto i = 0u; i < pnum; i++)
	{
		// read payload

		auto data = dr.ReadData();

		// copy read data

		pld = new struct Payload();
		pld->datlen = get<0>(data);
		pld->data = new char[pld->datlen];

		memcpy(pld->data, get<1>(data), pld->datlen);

		// enumerate over the mapped ports

		unsigned short pports;
		dr.Read(pports);

		for (auto j = 0u; j < pports; j++)
		{
			dr.Read(port);
			payloads.emplace(port, pld);
		}
	}

	// clean up

	mtx.unlock();
}

UdpScanner::~UdpScanner()
{
}

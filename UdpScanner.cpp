#include "UdpScanner.h"
#include "Utils.h"
#include "Host.h"
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

unordered_map<unsigned short, string> UdpScanner::payloads = unordered_map<unsigned short, string>();

bool UdpScanner::GetOption(int option, void* value)
{
	switch (option)
	{
	case OPT_TIMEOUT:
		*reinterpret_cast<unsigned long*>(value) = timeout;
		return true;

	case OPT_DELAY:
		*reinterpret_cast<unsigned long*>(value) = delay;
		return true;

	case OPT_BANNER:
		*reinterpret_cast<bool*>(value) = grabBanner;
		return true;

	default:
		return false;
	}
}

bool UdpScanner::SetOption(int option, void* value)
{
	switch (option)
	{
	case OPT_TIMEOUT:
		timeout = *reinterpret_cast<unsigned long*>(value);
		return true;

	case OPT_DELAY:
		delay = *reinterpret_cast<unsigned long*>(value);
		return true;

	case OPT_BANNER:
		grabBanner = *reinterpret_cast<bool*>(value);
		return true;

	default:
		return false;
	}
}

void* UdpScanner::GetTask(Service* service)
{
	if (payloads.size() == 0)
	{
		loadPayloads();
	}

	return MFN_TO_PTR(UdpScanner::initSocket, this, service);
}

void* UdpScanner::initSocket(Service* service)
{
	// parse address

	struct addrinfo hint, *info = nullptr;
	memset(&hint, 0, sizeof(struct addrinfo));
	hint.ai_family = AF_UNSPEC; // allow both v4 and v6
	hint.ai_flags = AI_NUMERICHOST; // disable DNS lookups

	auto port = lexical_cast<string>(service->port);
	getaddrinfo(service->address.c_str(), port.c_str(), &hint, &info);

	if (info == nullptr)
	{
		service->reason = AR_ScanFailed;
		log(ERR, "Failed to resolve IP address `" + service->address + "`");
		return nullptr;
	}

	// create socket

	auto sock = socket(info->ai_family, SOCK_DGRAM, IPPROTO_UDP);

	if (
#if Windows
		sock == INVALID_SOCKET
#else
		sock < 0
#endif
		)
	{
		service->reason = AR_ScanFailed;
		log(ERR, "Failed to open socket for udp://" + service->address + ":" + port + ": " + getNetErrStr());
		freeaddrinfo(info);
		return nullptr;
	}

	auto data = new UdpScanData();

	service->data = data;
	data->socket  = sock;

	service->reason = AR_InProgress;
	data->timeout   = chrono::system_clock::now() + chrono::milliseconds(timeout);

	// set it to non-blocking

	unsigned long mode = 1;
	ioctlsocket(sock, FIONBIO, &mode);
	
	// select payload based on port

	string pld;

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

	log(DBG, "Sending payload to udp://" + service->address + ":" + to_string(service->port) + "...");

	auto last = chrono::system_clock::now() - service->host->date;
	if (last < chrono::milliseconds(delay))
	{
		this_thread::sleep_for(chrono::milliseconds(delay) - last);
	}

	auto res = connect(sock, reinterpret_cast<struct sockaddr*>(info->ai_addr), info->ai_addrlen);

	if (res < 0)
	{
		service->reason = AR_ScanFailed;
		log(ERR, "Failed to connect to udp://" + service->address + ":" + port + ": " + getNetErrStr());

		freeaddrinfo(info);
		service->data = nullptr;
		delete data;

		return nullptr;
	}

	res = send(sock, pld.c_str(), pld.length(), 0);

	if (res < 0)
	{
		service->reason = AR_ScanFailed;
		log(ERR, "Failed to send packet to udp://" + service->address + ":" + port + ": " + getNetErrStr());

		freeaddrinfo(info);
		service->data = nullptr;
		delete data;

		return nullptr;
	}

	// clean-up

	freeaddrinfo(info);

	// return next task
	
	return MFN_TO_PTR(UdpScanner::pollSocket, this, service);
}

void* UdpScanner::pollSocket(Service* service)
{
	if (service->reason != AR_InProgress || service->data == nullptr)
	{
		return nullptr;
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

			log(DBG, "Got reply of " + pluralize(res, "byte") + " from udp://" + service->address + ":" + to_string(service->port) + "...");
		}
	}
	else
	{
		if (data->timeout < chrono::system_clock::now())
		{
			service->reason = AR_TimedOut;

			log(INT, "Waiting for udp://" + service->address + ":" + to_string(service->port) + " timed out...");
		}
#if Unix
		else if (res == -1 && errno == ECONNREFUSED)
		{
			service->reason = AR_IcmpUnreachable;

			log(INT, "Got ICMP unreachable for udp://" + service->address + ":" + to_string(service->port) + "...");
		}
#endif
		else
		{
			// return the current task to try polling the socket again

			return MFN_TO_PTR(UdpScanner::pollSocket, this, service);
		}
	}

	// clean-up

	service->data = nullptr;

	closesocket(data->socket);

	delete data;

	// return end-of-task

	return nullptr;
}

unordered_map<unsigned short, string> UdpScanner::GetPayloads()
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

	payloads.emplace(0, string(16, char(0)));

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

		auto data = dr.ReadString();

		// enumerate over the mapped ports

		unsigned short pports;
		dr.Read(pports);

		for (auto j = 0u; j < pports; j++)
		{
			unsigned short port;

			dr.Read(port);

			payloads.emplace(port, data);
		}
	}

	// clean up

	mtx.unlock();
}

UdpScanner::~UdpScanner()
{
}

#include "udpscanner.h"
#include "utils.h"
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

using namespace std;
using namespace boost;

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

void UdpScanner::initSocket(Service* service)
{
	// parse address

	struct addrinfo hint, *info = nullptr;
	memset(&hint, 0, sizeof(struct addrinfo));
	hint.ai_family = AF_UNSPEC; // allow both v4 and v6
	hint.ai_flags = AI_NUMERICHOST; // disable DNS lookups

	auto port = lexical_cast<string>(service->port);
	getaddrinfo(service->address, port.c_str(), &hint, &info);
	
	// create socket

	auto sock = socket(info->ai_family, SOCK_DGRAM, IPPROTO_UDP);

	auto data = new UdpScanData();
	service->data = data;
	data->socket = sock;

	service->reason = AR_InProgress;

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

		// save service banner

		service->banlen = res;
		service->banner = new char[res];

		memcpy(service->banner, buf, res);
	}
	else
	{
		if (last)
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
	static mutex pldmtx;
	auto locked = pldmtx.try_lock();
	if (!locked)
	{
		// wait until running parser finishes before returning
		lock_guard<mutex> guard(pldmtx);
		return;
	}

	// insert generic payload

	auto pld = new struct Payload();
	unsigned short port = 0;

	pld->data = new char[16] { 0 };
	pld->datlen = 16;

	payloads.emplace(port, pld);

	// open payloads file

	ifstream plfs;

	auto expth = get<0>(splitPath(getAppPath()));
	plfs.open(expth + PATH_SEPARATOR + "payloads");

	if (!plfs.good())
	{
		auto nxpth = splitPath(expth);

		if (get<1>(nxpth) == "build")
		{
			plfs.open(get<0>(nxpth) + PATH_SEPARATOR + "payloads");
		}
	}

	if (!plfs.good())
	{
		expth = getWorkDir();
		plfs.open(expth + PATH_SEPARATOR + "payloads");

		if (!plfs.good())
		{
			auto nxpth = splitPath(expth);

			if (get<1>(nxpth) == "build")
			{
				plfs.open(get<0>(nxpth) + PATH_SEPARATOR + "payloads");
			}
		}
	}

	if (!plfs.good())
	{
		cerr << "UDP payloads database not found!" << endl;
#if Windows
		cerr << "Download https://svn.nmap.org/nmap/nmap-payloads to the working directory and rename it to `payloads`." << endl;
#elif Unix
		cerr << "Run `wget https://svn.nmap.org/nmap/nmap-payloads -O payloads` in the working directory." << endl;
#endif

		plfs.close();
		pldmtx.unlock();
		return;
	}

	// define regexes for parsing the file

	regex skiprgx("^\\s*((#|source).*|$)");
	regex newprgx("^\\s*udp\\s+([\\d,]+)(?:\\s+\"(.+)\")?.*");
	regex datlrgx("^\\s*\"(.+)\".*");
	regex hexcrgx("\\\\x([a-fA-F0-9]{2})");

	// start parsing the file line-by-line

	string line;
	while (getline(plfs, line))
	{
		// skip comments and empty lines

		if (regex_match(line, skiprgx))
		{
			continue;
		}

		// check for "udp" and port enumeration lines

		smatch sm;
		if (regex_match(line, sm, newprgx))
		{
			pld = new struct Payload();

			// parse port enumeration

			if (sm[1].str().find(',') != string::npos)
			{
				// multiple ports, parse one by one

				string str = string(sm[1].str());
				size_t pos = 0;
				string token;
				while ((pos = str.find(',')) != string::npos)
				{
					token = str.substr(0, pos);
					port = (unsigned short)stoi(token);
					payloads.emplace(port, pld);
					str.erase(0, pos + 1);
				}

				// parse last port

				token = str.substr(0, pos);
				port = (unsigned short)stoi(token);
				payloads.emplace(port, pld);
			}
			else
			{
				// single port

				port = (unsigned short)stoi(sm[1].str());
				payloads.emplace(port, pld);
			}

			// parse payload, if starts on this line

			if (sm[2].matched)
			{
				// resolve hexadecimals

				string data;
				auto callback = [&](string const& m)
					{
						auto mc = m.c_str();
						if (mc[0] == '\\')
						{
							data += char(stoul(string(1, mc[2]) + mc[3], nullptr, 16));
						}
						else
						{
							data += m;
						}
					};

				string input = sm[2].str();
				sregex_token_iterator begin(input.begin(), input.end(), hexcrgx, { -1, 0 }), end;
				for_each(begin, end, callback);

				// copy to payload

				pld->datlen = data.length();
				pld->data = new char[pld->datlen];

				memcpy(pld->data, data.c_str(), pld->datlen);
			}

			continue;
		}

		// check for lines that start or continue payload data

		if (pld != nullptr && regex_match(line, sm, datlrgx))
		{
			string data;
			if (pld->data != nullptr)
			{
				data += string(pld->data, pld->datlen);
			}

			// resolve hexadecimals

			auto callback = [&](string const& m)
				{
					auto mc = m.c_str();
					if (mc[0] == '\\' && mc[1] == 'x')
					{
						data += char(stoul(string(1, mc[2]) + mc[3], nullptr, 16));
					}
					else
					{
						data += m;
					}
				};

			string input = sm[1].str();
			sregex_token_iterator begin(input.begin(), input.end(), hexcrgx, { -1, 0 }), end;
			for_each(begin, end, callback);

			// copy to payload

			delete pld->data;

			pld->datlen = data.length();
			pld->data = new char[pld->datlen];

			memcpy(pld->data, data.c_str(), pld->datlen);
		}
	}

	// clean up

	plfs.close();
	pldmtx.unlock();
}

UdpScanner::~UdpScanner()
{
}

#pragma once

#if _WIN32
	#define Windows 1
#elif __unix__
	#define Linux 1
#endif

#if Windows
	#include <winsock2.h>
	#include <ws2tcpip.h>

	#define sleep(t) Sleep(t)
	#define popen(c,m) _popen(c,m)
	#define pclose(s) _pclose(s)

	#define PATH_SEPARATOR "\\"

	#pragma comment(lib, "ws2_32.lib")
#elif Linux
	#include <unistd.h>
	#include <sys/socket.h>
	#include <sys/ioctl.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
	#include <netdb.h>

	#define SD_RECEIVE SHUT_RD
	#define SD_SEND SHUT_WR
	#define SD_BOTH SHUT_RDWR

	#define ioctlsocket(s,c,a) ioctl(s,c,a)
	#define sleep(t) usleep(t*1000)
	#define closesocket(s) close(s)

	#define PATH_SEPARATOR "/"

	typedef int SOCKET;
	typedef int IPPROTO;
	typedef struct timeval TIMEVAL;
#endif

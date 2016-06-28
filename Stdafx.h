#pragma once

#if _WIN32

	#define Windows 1

#elif __unix__

	#define Unix 1

	#if __linux__
		#define Linux 1
	#else
		#define BSD 1
	#endif

#endif

#if Windows

	#include <winsock2.h>
	#include <ws2tcpip.h>
	#include <iphlpapi.h>

	#define sleep(t) Sleep(t)
	#define popen(c,m) _popen(c,m)
	#define pclose(s) _pclose(s)

	#define PATH_SEPARATOR "\\"

	#pragma comment(lib, "ws2_32.lib")
	#pragma comment(lib, "iphlpapi.lib")

#elif Unix

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

#include <string>

/*!
 * Represents an error message.
 */
#define ERR 5

/*!
 * Represents a warning message.
 */
#define WRN 4

/*!
 * Represents a message with default severity.
 */
#define MSG 3

/*!
 * Represents a verbose message.
 * This is only visible with the --verbose switch.
 */
#define VRB 2

/*!
 * Represents a debug message.
 * This is only visible with the --debug switch.
 */
#define DBG 1

/*!
 * Represents an internal debug message.
 * This is only visible with the --internal switch.
 */
#define INT 0

/*!
 * Logs a message through the implemented provider.
 *
 * \param level Message severity level.
 * \param msg Message to log.
 * \param format Value indicating whether to enable formatting.
 */
void log(int level, const std::string& msg, bool format = true);

/*!
 * Logs a message with default severity level.
 *
 * \param msg Message to log.
 * \param format Value indicating whether to enable formatting.
 */
inline void log(const std::string& msg, bool format = true)
{
	log(MSG, msg, format);
}

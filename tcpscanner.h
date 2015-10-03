#pragma once
#include "stdafx.h"
#include "portscanner.h"

/*!
 * Represents scan data for the TCP scanner.
 */
struct ActiveTcpScanData
{
	/*!
	 * Active non-blocking socket.
	 */
	SOCKET socket;

	/*!
	 * File descriptor set for writability.
	 */
	fd_set* fdset;
};

/*!
 * Implements an active TCP port scanner.
 * 
 * This will try to initiate the three-way handshake with all the requested services.
 * It is not a stealthy method, and does not include any trickery to bypass firewalls.
 */
class TcpScanner : public PortScanner
{
public:
	
	/*!
	 * Number of milliseconds to wait for connections to finish.
	 */
	unsigned long timeout = 100;

	/*!
	 * Scans a list of services to determine aliveness.
	 * 
	 * \param services List of services.
	 */
	void Scan(Services* services) override;

private:

	/*!
	 * Initializes the sockets and starts the non-blocking connection.
	 * 
	 * \param services List of services.
	 */
	void initSocket(Service* service);

	/*!
	 * Collects the results of the socket connections.
	 * 
	 * \param services List of services.
	 */
	void pollSocket(Service* service);

};
#pragma once
#include "stdafx.h"
#include "portscanner.h"

/*!
 * Represents scan data for the UDP scanner.
 */
struct UdpScanData
{
	/*!
	 * "Connected" socket.
	 */
	SOCKET socket;
};

/*!
 * Implements an UDP port scanner.
 * 
 * This will try to initiate the three-way handshake with all the requested services.
 * It is not a stealthy method, and does not include any trickery to bypass firewalls.
 */
class UdpScanner : public PortScanner
{
public:
	
	/*!
	 * Number of milliseconds to wait for response.
	 */
	unsigned long timeout = 1000;

	/*!
	 * Scans a service to determine aliveness.
	 * 
	 * \param service Service.
	 */
	void Scan(Service* service) override;

	/*!
	 * Scans a list of services to determine aliveness.
	 * 
	 * \param services List of services.
	 */
	void Scan(Services* services) override;

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	~UdpScanner() override;

private:

	/*!
	 * Sends a datagram to each requested service, with crafted packet, when available.
	 * 
	 * \param services List of services.
	 */
	void initSocket(Service* service);

	/*!
	 * Receives the responses.
	 * 
	 * \param services List of services.
	 */
	void pollSocket(Service* service);

};
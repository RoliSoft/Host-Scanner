#pragma once
#include <chrono>
#include "Stdafx.h"
#include "ServiceScanner.h"

/*!
 * Represents internal scan data for the TCP scanner.
 */
struct TcpScanData
{

	/*!
	 * Active non-blocking socket.
	 */
	SOCKET socket;

	/*!
	 * File descriptor set for writability.
	 */
	fd_set* fdset;

	/*!
	 * Expiration time of the current operation.
	 */
	std::chrono::time_point<std::chrono::system_clock> timeout;

	/*!
	 * Number of probes sent to the service.
	 */
	int probes;

};

/*!
 * Implements an active TCP port scanner.
 * 
 * This will try to initiate the three-way handshake with all the requested services.
 * It is not a stealthy method, and does not include any trickery to bypass firewalls.
 */
class TcpScanner : public ServiceScanner
{
public:

	/*!
	 * Gets the currently set value for the option key.
	 *
	 * \param option Option index, see `OPT_*` macros.
	 * \param value Pointer to the value to set.
	 *
	 * \return true if it succeeds, false if it fails.
	 */
	bool GetOption(int option, void* value) override;

	/*!
	 * Sets a specified value for the option key.
	 *
	 * \param option Option index, see `OPT_*` macros.
	 * \param value Pointer to the value to set.
	 *
	 * \return true if it succeeds, false if it fails.
	 */
	bool SetOption(int option, void* value) override;
	
	/*!
	 * Get a task which scans a service to determine its aliveness.
	 *
	 * \param service Service to scan.
	 * 
	 * \return Task to scan the specified service.
	 */
	void* GetTask(Service* service) override;
	
	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	~TcpScanner() override;

private:
	
	/*!
	 * Number of milliseconds to wait for connections to finish.
	 */
	unsigned long timeout = 3000;
	
	/*!
	 * Number of milliseconds to wait between packets sent to the same host.
	 */
	unsigned long delay = 100;

	/*!
	 * Indicates whether to wait for and grab service banners.
	 */
	bool grabBanner = true;

	/*!
	 * Initializes the socket and starts the non-blocking connection.
	 *
	 * \param service Service.
	 * 
	 * \return Next task, or `nullptr` if failed to initialize socket.
	 */
	void* initSocket(Service* service);

	/*!
	 * Collects the result of the socket connection.
	 *
	 * \param service Service.
	 *
	 * \return Same task if no data received yet, otherwise next task to
	 * 		   read banner, or `nullptr` if failed to read from socket.
	 */
	void* pollSocket(Service* service);

	/*!
	 * Reads the banner from the specified service.
	 * This requires that the service have a connected socket.
	 *
	 * \param service Service.
	 *
	 * \return Same task if no data received yet, or `nullptr` if succeeded in
	 * 		   reading the banner or socket disconnected while trying to do so.
	 */
	void* readBanner(Service* service);

	/*!
	 * Sends a protocol probe to the specified service.
	 * This requires that the service have a connected socket.
	 *
	 * \param service Service.
	 *
	 * \return Previous task to re-try reading the service banner, or `nullptr`
	 * 		   if socket disconnected while trying to send packet.
	 */
	void* sendProbe(Service* service);

};

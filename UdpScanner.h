#pragma once
#include <chrono>
#include <unordered_map>
#include "Stdafx.h"
#include "ServiceScanner.h"

/*!
 * Represents internal scan data for the UDP scanner.
 */
struct UdpScanData
{

	/*!
	 * Connected socket.
	 */
	SOCKET socket;

	/*!
	 * Expiration time of the current operation.
	 */
	std::chrono::time_point<std::chrono::system_clock> timeout;

};

/*!
 * Represents a payload.
 */
struct Payload
{

	/*!
	 * Data in the payload.
	 */
	char* data = nullptr;

	/*!
	 * Length of the data.
	 */
	int datlen = 0;

};

/*!
 * Implements an UDP port scanner.
 * 
 * This will try to initiate the three-way handshake with all the requested services.
 * It is not a stealthy method, and does not include any trickery to bypass firewalls.
 */
class UdpScanner : public ServiceScanner
{
public:
	
	/*!
	 * Number of milliseconds to wait for response.
	 */
	unsigned long timeout = 5000;

	/*!
	 * Indicates whether to wait for and grab service banners.
	 */
	bool grabBanner = true;
	
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
	 * Gets the port-mapped protocol payloads.
	 *
	 * \return List of payloads.
	 */
	static std::unordered_map<unsigned short, struct Payload*> GetPayloads();

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	~UdpScanner() override;

private:

	/*!
	 * Map of well-known ports and their example payload.
	 */
	static std::unordered_map<unsigned short, struct Payload*> payloads;

	/*!
	 * Sends a datagram to the requested service, with crafted packet, when available.
	 *
	 * \param service Service.
	 *
	 * \return Next task, or `nullptr` if failed to initialize socket.
	 */
	void* initSocket(Service* service);

	/*!
	 * Receives the response.
	 *
	 * \param service Service.
	 *
	 * \return Same task if no data received yet, otherwise next task to
	 * 		   read banner, or `nullptr` if failed to read from socket.
	 */
	void* pollSocket(Service* service);

	/*!
	 * Loads the payload database from external file.
	 */
	static void loadPayloads();

};

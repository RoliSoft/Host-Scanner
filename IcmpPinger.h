#pragma once
#include <chrono>
#include "Stdafx.h"
#include "ServiceScanner.h"

#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY   0
#define ICMP_DEST_UNREACH 3

#define ICMP6_ECHO_REQUEST 128
#define ICMP6_ECHO_REPLY   129
#define ICMP6_DEST_UNREACH 1

/*!
 * Structure of an ICMP packet.
 */
struct IcmpHeader
{

	/*!
	 * Type of the packet.
	 */
	unsigned char type;

	/*!
	 * Code of the packet.
	 */
	unsigned char code;
	
	/*!
	 * Checksum of the packet, excluding the IP header.
	 */
	unsigned short checksum;

};

/*!
 * Structure of an ICMP packet for echo request/reply.
 */
struct IcmpEcho : IcmpHeader
{

	/*!
	 * ID of the echo request.
	 */
	unsigned short id;
	
	/*!
	 * Sequence number of the echo request.
	 */
	unsigned short seq;

	/*!
	 * Payload to be echoed.
	 */
	char data[32];

};

/*!
 * Represents scan data for the ICMP scanner.
 */
struct IcmpScanData
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
 * Implements a scanner which sends ICMP pings using raw sockets.
 */
class IcmpPinger : public ServiceScanner
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
	~IcmpPinger() override;

private:
	
	/*!
	 * Number of milliseconds to wait for a reply packet.
	 */
	unsigned long timeout = 3000;

	/*!
	 * Global sequence counter for the ping packets.
	 */
	static unsigned short sequence;

	/*!
	 * Sends an ICMP Echo Request to the specified service.
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
	 * \return Same task if no data received yet, or `nullptr` if succeeded in
	 * 		   reading the response or socket disconnected while trying to do so.
	 */
	void* pollSocket(Service* service);
	
	/*!
	 * Calculates the checksum for the specified packet, which is the 16-bit one's complement
	 * of the one's complement sum of the ICMP message starting with the `type` field.
	 *
	 * \param buf Packet to checksum.
	 * \param len Size of packet.
	 *
	 * \return Corresponding checksum.
	 */
	static unsigned short checksum(unsigned short* buf, int len);

};

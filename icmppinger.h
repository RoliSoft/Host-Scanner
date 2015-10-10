#pragma once
#include "stdafx.h"
#include "portscanner.h"

#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY   0
#define ICMP_TTL_EXPIRE   11
#define ICMP_DEST_UNREACH 3

#define ICMP6_ECHO_REQUEST 128
#define ICMP6_ECHO_REPLY   129
#define ICMP6_TTL_EXPIRE   3
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

};

/*!
 * Implements a scanner which sends ICMP pings using raw sockets.
 */
class IcmpPinger : public PortScanner
{
public:
	
	/*!
	 * Number of milliseconds to wait for a reply packet.
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
	~IcmpPinger() override;

private:

	/*!
	 * Global sequence counter for the ping packets.
	 */
	static unsigned short sequence;

	/*!
	 * Sends a datagram to each requested service, with crafted packet, when available.
	 *
	 * \param service Service.
	 */
	void initSocket(Service* service);

	/*!
	 * Receives the responses.
	 *
	 * \param service Service.
	 * \param last Whether this is the last iteration.
	 */
	void pollSocket(Service* service, bool last = false);
	
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

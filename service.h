#pragma once
#include <vector>
#include "stdafx.h"

/*!
 * List of reasons which caused the host to be determined as it is.
 */
typedef enum
{

	/*!
	 * Error occurred during scan.
	 */
	AR_ScanFailed = -1,

	/*!
	 * Service hasn't yet been scanned.
	 */
	AR_NotScanned = 0,

	/*!
	 * Service is being scanned.
	 */
	AR_InProgress = 1,

	/*!
	 * Service is alive, but still being scanned.
	 */
	AR_InProgress2 = 2,

	/*!
	 * Service didn't reply within specified timeframe.
	 */
	AR_TimedOut = 3,

	/*!
	 * ICMP Destination Unreachable received.
	 */
	AR_IcmpUnreachable = 4,

	/*!
	 * Service replied within specified timeframe.
	 */
	AR_ReplyReceived = 5

} AliveReason;

/*!
 * Represents a service in the form of an IP/port.
 */
class Service
{
public:

	/*!
	 * Remote address.
	 */
	char* address;

	/*!
	 * Remote port.
	 */
	unsigned short port;

	/*!
	 * Remote protocol.
	 */
	IPPROTO protocol;
	
	/*!
	 * Whether the service is alive at this host.
	 */
	bool alive = false;
	
	/*!
	 * Reason for the value specified in `alive`.
	 * Negative values are errors, positive values are scanner-dependent reasons.
	 */
	AliveReason reason = AR_NotScanned;

	/*!
	 * Service banner, if any.
	 */
	char* banner = nullptr;

	/*!
	 * Length of the service banner.
	 */
	int banlen = 0;

	/*!
	 * Object store reserved for the scanner.
	 */
	void* data = nullptr;

	/*!
	 * Creates a new instance of this type.
	 * 
	 * \param address Remote address.
	 * \param port Remote port.
	 * \param protocol Remote protocol, otherwise TCP.
	 */
	Service(char* address, unsigned short port, IPPROTO protocol = IPPROTO_TCP);

};

/*!
 * Represents a list of services.
 */
typedef std::vector<Service*> Services;

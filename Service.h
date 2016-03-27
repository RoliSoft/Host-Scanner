#pragma once
#include <vector>
#include <chrono>
#include "Stdafx.h"

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
	AR_InProgress_Extra = 2,

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
	std::string address;

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
	bool alive;
	
	/*!
	 * Reason for the value specified in `alive`.
	 * Negative values are errors, positive values are scanner-dependent reasons.
	 */
	AliveReason reason;

	/*!
	 * Service banner, if any.
	 */
	std::string banner;

	/*!
	 * CPE names of the service.
	 */
	std::vector<std::string> cpe;

	/*!
	 * Time of last packet sent to this service.
	 */
	std::chrono::time_point<std::chrono::system_clock> date;

	/*!
	 * Parent host of this service.
	 */
	class Host* host;

	/*!
	 * Object store reserved for the scanner.
	 */
	void* data;

	/*!
	 * Copies the specified instance.
	 *
	 * \param service Instance to copy.
	 */
	Service(const Service& service);

	/*!
	 * Creates a new instance of this type.
	 * 
	 * \param address Remote address.
	 * \param port Remote port.
	 * \param protocol Remote protocol, otherwise TCP.
	 */
	Service(const std::string& address, unsigned short port, IPPROTO protocol = IPPROTO_TCP);

	/*!
	 * Resolves the value of the enum `AliveReason` to its textual representation.
	 *
	 * \param reason Enum value.
	 *
	 * \return Textual representation.
	 */
	static std::string ReasonString(AliveReason reason);

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	~Service();

};

/*!
 * Represents a list of services.
 */
typedef std::vector<Service*> Services;

/*!
 * Frees up the structures allocated within this array.
 *
 * \param services List of services.
 */
void freeServices(Services& services);

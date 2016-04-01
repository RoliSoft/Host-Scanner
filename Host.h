#pragma once
#include <set>
#include <vector>
#include <chrono>
#include "Stdafx.h"
#include "Service.h"

/*!
 * List of operating systems.
 */
typedef enum
{

	/*!
	 * The operating system was not identified.
	 */
	Unidentified = -1,
	
	/*!
	 * Debian Linux
	 */
	Debian = 1,
	
	/*!
	 * Ubuntu Linux
	 */
	Ubuntu = 2,
	
	/*!
	 * Red Hat/CentOS Linux
	 */
	EnterpriseLinux = 3,
	
	/*!
	 * Fedora Linux
	 */
	Fedora = 4,

	/*!
	 * Windows
	 */
	WindowsNT = 10,

} OpSys;

/*!
 * Represents a host which hosts a collection of services.
 */
class Host
{
public:

	/*!
	 * Remote address.
	 */
	std::string address;
	
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
	 * CPE names of the host.
	 */
	std::vector<std::string> cpe;

	/*!
	 * List of services on this host.
	 */
	Services* services;

	/*!
	 * The operating system of the host.
	 */
	OpSys opSys;

	/*!
	 * The version of the operating system.
	 */
	double osVer;

	/*!
	 * Time of last packet sent to this host.
	 */
	std::chrono::time_point<std::chrono::system_clock> date;

	/*!
	 * Object store reserved for the scanner.
	 */
	void* data;

	/*!
	 * Copies the specified instance.
	 *
	 * \param host Instance to copy.
	 */
	Host(const Host& host);

	/*!
	 * Creates a new instance of this type.
	 * 
	 * \param address Remote address.
	 */
	explicit Host(const std::string& address);

	/*!
	 * Creates a new instance of this type.
	 *
	 * \param address Remote address.
	 * \param tcps List of TCP ports to attach as a service.
	 * \param udps List of UDP ports to attach as a service.
	 */
	Host(const std::string& address, const std::set<unsigned short>& tcps, const std::set<unsigned short>& udps = { });

	/*!
	 * Adds a service to the host.
	 * 
	 * \remarks If the address of the host and service object don't
	 * 			match, this function call will be silently rejected.
	 * 
	 * \param service The service object to add.
	 * 
	 * \return Service object added to list, or `nullptr` on failure.
	 */
	Service* AddService(Service* service);

	/*!
	 * Adds a service to the host.
	 *
	 * \param port Remote port.
	 * \param protocol Remote protocol, otherwise TCP.
	 * 
	 * \return Service object added to list, or `nullptr` on failure.
	 */
	Service* AddService(unsigned short port, IPPROTO protocol = IPPROTO_TCP);
	
	/*!
	 * Adds the specified list of services to the host.
	 *
	 * \remarks If the address of the host and service object don't
	 * 			match, this function call will be silently rejected.
	 *
	 * \param servlist The service objects to add.
	 *
	 * \return Number of added service objects.
	 */
	int AddServices(const Services& servlist);

	/*!
	 * Adds the specified list of services to the host.
	 *
	 * \param ports Remote ports.
	 * \param protocol Remote protocol, otherwise TCP.
	 *
	 * \return Number of added service objects.
	 */
	int AddServices(const std::set<unsigned short>& ports, IPPROTO protocol = IPPROTO_TCP);

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	~Host();

};

/*!
 * Represents a list of hosts.
 */
typedef std::vector<Host*> Hosts;

/*!
 * Frees up the structures allocated within this array.
 *
 * \param hosts List of hosts.
 */
void freeHosts(Hosts& hosts);

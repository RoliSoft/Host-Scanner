#pragma once
#include "stdafx.h"
#include "portscanner.h"

/*!
 * Provides interoperability with Nmap.
 */
class NmapScanner : public PortScanner
{
public:
	
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
	~NmapScanner() override;

private:

	/*!
	 * Runs Nmap on the specified services.
	 *
	 * \param services List of services.
	 * \param v6 Whether to turn on IPv6 support.
	 *
	 * \remarks Turning on IPv6 support means that IPv4 will be turned off.
	 *
	 * \return XML response from Nmap.
	 */
	std::string runNmap(Services* services, bool v6 = false);

	/*!
	 * Parses the specified XML output and updates matching services.
	 *
	 * \param xml XML response from Nmap.
	 * \param services List of services.
	 */
	void parseXml(std::string xml, Services* services);

	/*!
	 * Executes a command and returns its output.
	 *
	 * \param cmd Command to execute.
	 */
	static std::string execute(const char* cmd);

};

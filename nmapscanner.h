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
	 * Executes a command and returns its output.
	 *
	 * \param cmd Command to execute.
	 */
	static std::string execute(const char* cmd);

};

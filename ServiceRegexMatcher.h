#pragma once
#include "Stdafx.h"
#include "BannerProcessor.h"
#include <string>
#include <boost/regex.hpp>

/*!
 * Represents a service identifier entry.
 */
struct ServiceRegex
{

	/*!
	 * Regular expression to match against service banner.
	 */
	boost::regex regex;

	/*!
	 * CPE name of the matched service.
	 */
	std::string cpe;

	/*!
	 * Product name of the matched service.
	 */
	std::string product;

	/*!
	 * Version number of the matched service.
	 */
	std::string version;

};

/*!
 * Implements a bulk regular expression matcher against service banners.
 */
class ServiceRegexMatcher : public BannerProcessor
{
public:
	
	/*!
	 * Processes the banner of a service.
	 * 
	 * \param service Scanned service.
	 */
	void Scan(Service* service) override;

	/*!
	 * Gets the regular expressions.
	 *
	 * \return List of regular expressions.
	 */
	static std::vector<struct ServiceRegex*> GetRegexes();

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	~ServiceRegexMatcher() override;

private:

	/*!
	 * List of regular expressions with their associated product info.
	 */
	static std::vector<struct ServiceRegex*> regexes;

	/*!
	 * Loads the regex database from external file.
	 */
	static void loadRegexes();

};

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
	 * Processes the specified service banner.
	 * 
	 * \param banner Service banner.
	 * \param processVendor Whether to process vendor level patches appended to the end of the version
	 *                      number. This removes the patch level from the CPE version and appends it to
	 *                      the end via a semicolon separator.
	 * 
	 * \return Matching CPE entries.
	 */
	std::vector<std::string> Scan(const std::string& banner, bool processVendor = true) override;

	/*!
	 * Gets the regular expressions.
	 *
	 * \return List of regular expressions.
	 */
	static std::vector<ServiceRegex> GetRegexes();

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	~ServiceRegexMatcher() override;

private:

	/*!
	 * List of regular expressions with their associated product info.
	 */
	static std::vector<ServiceRegex> regexes;

	/*!
	 * Loads the regex database from external file.
	 */
	static void loadRegexes();

};

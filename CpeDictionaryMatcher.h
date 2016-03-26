#pragma once
#include "Stdafx.h"
#include "BannerProcessor.h"
#include <string>
#include <unordered_map>
#include <boost/regex.hpp>

/*!
 * Represents a sub-entry in the CPE dictionary.
 */
struct CpeVersionEntry
{

	/*!
	 * Version part of the CPE name.
	 */
	std::string cpe;

	/*!
	 * Version number token.
	 */
	std::string version;

	/*!
	 * Version-specific tokens of the entry.
	 */
	std::vector<boost::regex> tokens;

};

/*!
 * Represents a CPE dictionary entry.
 */
struct CpeEntry
{

	/*!
	 * CPE name of the entry.
	 */
	std::string cpe;

	/*!
	 * Common tokens of the entry.
	 */
	std::vector<boost::regex> tokens;

	/*!
	 * Known versions of the entry.
	 */
	std::vector<CpeVersionEntry> versions;

};

/*!
 * Implements fuzzy matching of CPE names to service banners.
 */
class CpeDictionaryMatcher : public BannerProcessor
{
public:
	
	/*!
	 * Processes the specified service banner.
	 * 
	 * \param banner Service banner.
	 * 
	 * \return Matching CPE entries.
	 */
	std::vector<std::string> Scan(const std::string& banner) override;

	/*!
	 * Gets the CPE entries.
	 *
	 * \return List of CPE entries.
	 */
	static std::vector<CpeEntry> GetEntries();
	
	/*!
	 * Gets the CPE aliases.
	 *
	 * \return List of CPE aliases.
	 */
	static std::unordered_map<std::string, std::vector<std::string>> GetAliases();

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	~CpeDictionaryMatcher() override;

private:

	/*!
	 * List of CPE dictionary entries with their associated product info.
	 */
	static std::vector<CpeEntry> entries;

	/*!
	 * List of CPE name aliases.
	 */
	static std::unordered_map<std::string, std::vector<std::string>> aliases;

	/*!
	 * Loads the entries and aliases database from external file.
	 */
	static void loadEntries();

};

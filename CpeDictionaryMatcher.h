#pragma once
#include "Stdafx.h"
#include "BannerProcessor.h"
#include <string>
#include <unordered_map>

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
	 * Vendor of the entry.
	 */
	std::string vendor;

	/*!
	 * Product name of the entry.
	 */
	std::string product;

	/*!
	 * User-friendly name of the entry.
	 */
	std::string name;

};

/*!
 * Implements fuzzy matching of CPE names to service banners.
 */
class CpeDictionaryMatcher : public BannerProcessor
{
public:
	
	/*!
	 * Processes the banner of a service.
	 * 
	 * \param service Scanned service.
	 */
	void Scan(Service* service) override;

	/*!
	 * Gets the CPE entries.
	 *
	 * \return List of CPE entries.
	 */
	static std::vector<struct CpeEntry*> GetEntries();
	
	/*!
	 * Gets the CPE aliases.
	 *
	 * \return List of CPE aliases.
	 */
	static std::unordered_map<std::string, std::vector<std::string>*> CpeDictionaryMatcher::GetAliases();

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	~CpeDictionaryMatcher() override;

private:

	/*!
	 * List of CPE dictionary entries with their associated product info.
	 */
	static std::vector<struct CpeEntry*> entries;

	/*!
	 * List of CPE name aliases.
	 */
	static std::unordered_map<std::string, std::vector<std::string>*> aliases;

	/*!
	 * Loads the entries and aliases database from external file.
	 */
	static void loadEntries();

};

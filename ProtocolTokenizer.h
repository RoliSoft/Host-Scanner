#pragma once
#include "Stdafx.h"
#include <vector>

/*!
 * Represents a lightweight protocol parser to be used for tokenizing service banners.
 */
class ProtocolTokenizer
{
public:
	
	/*!
	 * Determines whether the specified service banner can be tokenized using this
	 * instance of the protocol parser.
	 * 
	 * \param banner Service banner.
	 * 
	 * \return Value indicating ability to process.
	 */
	virtual bool CanTokenize(const std::string& banner) = 0;

	/*!
	 * Processes the specified service banner.
	 * 
	 * \param banner Service banner.
	 * 
	 * \return Extracted tokens.
	 */
	virtual std::vector<std::string> Tokenize(const std::string& banner) = 0;

	/*!
	 * Tries to processes the specified service banner with all known implementations
	 * of this class, in decreasing order of protocol popularity.
	 *
	 * \param banner Service banner.
	 * 
	 * \return Extracted tokens.
	 */
	static std::vector<std::string> AutoTokenize(const std::string& banner);

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	virtual ~ProtocolTokenizer();
	
};

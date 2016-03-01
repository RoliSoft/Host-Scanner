#pragma once
#include "Stdafx.h"
#include "ProtocolTokenizer.h"

/*!
 * Implements a lightweight HTTP protocol parser to be used for extraction of server names and version numbers.
 */
class HttpTokenizer : public ProtocolTokenizer
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
	bool CanTokenize(const std::string& banner) override;

	/*!
	 * Processes the specified service banner.
	 * 
	 * \param banner Service banner.
	 * 
	 * \return Extracted tokens.
	 */
	std::vector<std::string> Tokenize(const std::string& banner) override;

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	~HttpTokenizer() override;

};

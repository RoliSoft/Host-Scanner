#pragma once
#include "Stdafx.h"
#include "ProtocolTokenizer.h"

/*!
 * Implements a lightweight parser for protocols which use three-digit response codes, such as SMTP, NNTP and FTP.
 */
class ThreeDigitTokenizer : public ProtocolTokenizer
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
	~ThreeDigitTokenizer() override;

};

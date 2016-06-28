#pragma once
#include "Stdafx.h"
#include <string>
#include <tuple>
#include <functional>
#include <boost/optional.hpp>

#if HAVE_CURL
	#include <curl/curl.h>
#else
	typedef void CURL;
#endif

/*!
 * Executes a command and returns its output.
 *
 * \param cmd Command to execute.
 */
std::string execute(const char* cmd);

/*!
 * Gets the path to the executable.
 *
 * \return Path to executable.
 */
std::string getAppPath();

/*!
 * Gets the path to the current working directory.
 *
 * \return Path to working directory.
 */
std::string getWorkDir();

/*!
 * Gets the value of the requested environment variable.
 *
 * \param env Variable name.
 *
 * \return Environment variable, or empty string.
 */
std::string getEnvVar(const std::string& env);

/*!
 * Splits the path, second item will be top-level file or
 * directory, while the first will be the rest of the path.
 *
 * \param path Path to split.
 *
 * \return Rest of the path, top-level file or directory.
 */
std::tuple<std::string, std::string> splitPath(const std::string& path);

/*!
 * Pluralizes the specified unit based on the quantity.
 *
 * \param quantity Quantity of unit.
 * \param unit Unit to pluralize.
 * \param addIs Append `is` or `are`.
 * \param past Whether to append `addIs` in past tense.
 *
 * \return String with quantity and unit, pluralized if needed.
 */
std::string pluralize(int quantity, const std::string& unit, bool addIs = false, bool past = false);

/*!
 * Fetches the content behind the specified URL.
 *
 * \param url Location to download.
 * \param opts Optional callback function called right after setting up curl,
 *             and before performing the request. Within this function, you may
 *             manipulate any aspect of the request by calling `curl_easy_setopt`
 *             on the passed `CURL` pointer.
 *
 * \return Tuple containing two strings and the response code:
 *         the downloaded string, if any, and the error message, if any.
 */
std::tuple<std::string, std::string, int> getURL(const std::string& url, const std::function<void(CURL*)>& opts = nullptr);

/*!
 * Retrieves the error message for the last I/O error.
 * 
 * On Windows, it uses `WSAGetLastError()` with `FormatMessage()`.
 * On Linux, it uses `errno` with `strerror()`.
 *
 * \param code Optional error code. If not specified, will retrieve
 * 			   the last code from the operating system.
 * 
 * \return The net error string.
 */
std::string getNetErrStr(boost::optional<int> code = boost::none);

/*!
 * Converts textual dates to Unix timestamps.
 * 
 * \param datetime Textual date.
 * \param format Format string, RFC1123 by default.
 *
 * \return Number of seconds elapsed until specified date
 * 		   since Unix epoch.
 */
long dateToUnix(const std::string& datetime, const std::string& format = "%a, %d %b %Y %H:%M:%S");

/*!
 * Converts Unix timestamps to textual dates.
 * 
 * \param datetime Textual date.
 * \param format Format string, RFC1123 by default.
 *
 * \return Unix timestamp formatted as specified.
 */
std::string unixToDate(long datetime, const std::string& format = "%a, %d %b %Y %H:%M:%S");

/*!
 * Escapes the specified input in order to be used in a regular expression.
 *
 * \param input String to be escaped.
 *
 * \return String with characters having special meanings in regular
 * 		   expressions escaped safely.
 */
std::string escapeRegex(const std::string& input);

/*!
 * Compares the two specified dates.
 *
 * \param a First date.
 * \param b Second date.
 *
 * \return -1 if the first date is older,
 *          0 if the two dates are equal,
 *          1 if the first date is newer.
 */
int compareDates(const std::string& a, const std::string& b);

/*!
 * Compares the two specified version numbers.
 *
 * \param a First version number.
 * \param b Second version number.
 *
 * \return -1 if the first version is older,
 *          0 if the two versions are equal,
 *          1 if the first version is newer.
 */
int compareVersions(const std::string& a, const std::string& b);

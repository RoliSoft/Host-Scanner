#pragma once
#include "Stdafx.h"
#include <string>
#include <tuple>
#include <functional>
#include <curl/curl.h>

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
 * Splits the path, second item will be top-level file or
 * directory, while the first will be the rest of the path.
 *
 * \param path Path to split.
 *
 * \return Rest of the path, top-level file or directory.
 */
std::tuple<std::string, std::string> splitPath(const std::string& path);

/*!
 * Fetches the content behind the specified URL.
 *
 * \param url Location to download.
 * \param opts Optional callback function called right after setting up curl,
 *             and before performing the request. Within this function, you may
 *             manipulate any aspect of the request by calling `curl_easy_setopt`
 *             on the passed `CURL` pointer.
 *
 * \return Tuple containing two strings:
 *         the downloaded string, if any, and the error message, if any.
 */
std::tuple<std::string, std::string> getURL(const std::string& url, const std::function<void(CURL*)>& opts = nullptr);

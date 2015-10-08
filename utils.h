#include "stdafx.h"
#include <string>
#include <tuple>

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

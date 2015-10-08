#include "utils.h"
#include <string>
#if Linux
#include <limits.h>
#include <unistd.h>
#endif

using namespace std;

string execute(const char* cmd)
{
	// run the process

	auto pipe = popen(cmd, "r");

	if (!pipe)
	{
		return "Failed to execute command: `" + string(cmd) + "`";
	}

	// read what it writes to the standard output during its lifetime

	string result;

	char buffer[512];
	while (!feof(pipe))
	{
		if (fgets(buffer, 512, pipe) != NULL)
		{
			result += buffer;
		}
	}

	// clean up and return

	pclose(pipe);

	return result;
}

string getAppPath()
{
#if Windows
	char result[MAX_PATH];
	auto size = GetModuleFileName(NULL, result, MAX_PATH);
#elif Linux
	char result[PATH_MAX];
	auto size = readlink("/proc/self/exe", result, PATH_MAX);
#endif
	return string(result, (size > 0) ? size : 0);
}

string getWorkDir()
{
#if Windows
	char result[MAX_PATH];
	GetCurrentDirectory(MAX_PATH, result);
#elif Linux
	char result[PATH_MAX];
	getcwd(result, PATH_MAX);
#endif
	return string(result);
}

tuple<string, string> splitPath(const string& path)
{
	auto idx = path.find_last_of(PATH_SEPARATOR);

	if (idx == string::npos)
	{
		return make_tuple(path, "");
	}

	return make_tuple(path.substr(0, idx), path.substr(idx + 1));
}

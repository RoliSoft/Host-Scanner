#include "DataReader.h"
#include "Utils.h"
#include <iostream>
#include <boost/filesystem.hpp>

#if HAVE_ZLIB
	#include <boost/iostreams/filter/gzip.hpp>
#endif

using namespace std;
namespace io = boost::iostreams;
namespace fs = boost::filesystem;

DataReader::DataReader()
	: fs(nullptr), bs(nullptr)
{
}

bool DataReader::OpenFile(const string& filename)
{
	Close();

	fs = new ifstream();
	fs->open(filename, ifstream::binary);

	if (!fs->good())
	{
		Close();
		return false;
	}

	bs = new io::filtering_istreambuf();

	if (fs::path(filename).extension() == ".gz")
	{
#if HAVE_ZLIB
		try
		{
			bs->push(io::gzip_decompressor());
		}
		catch (boost::exception&)
		{
			Close();
			return false;
		}
#else
		Close();
		return false;
#endif
	}

	bs->push(*fs);

	return true;
}

bool DataReader::OpenEnv(const string& name)
{
	vector<string> paths = {
#if Windows
		get<0>(splitPath(getAppPath())) + "\\data\\" + name + ".dat",
#if HAVE_ZLIB
		get<0>(splitPath(getAppPath())) + "\\data\\" + name + ".dat.gz",
#endif
		getEnvVar("APPDATA") + "\\RoliSoft\\Host Scanner\\data\\" + name + ".dat",
#if HAVE_ZLIB
		getEnvVar("APPDATA") + "\\RoliSoft\\Host Scanner\\data\\" + name + ".dat.gz"
#endif
#else
		get<0>(splitPath(getAppPath())) + "/data/" + name + ".dat",
#if HAVE_ZLIB
		get<0>(splitPath(getAppPath())) + "/data/" + name + ".dat.gz",
#endif
		"/var/lib/HostScanner/data/" + name + ".dat",
#if HAVE_ZLIB
		"/var/lib/HostScanner/data/" + name + ".dat.gz"
#endif
#endif
	};

	for (auto path : paths)
	{
		fs::path fp(path);

		if (!fs::exists(fp) || !fs::is_regular_file(fp))
		{
			continue;
		}

		if (OpenFile(path))
		{
			return true;
		}
	}

	return false;
}

void DataReader::Close()
{
	if (bs != nullptr)
	{
		delete bs;

		bs = nullptr;
	}

	if (fs != nullptr)
	{
		if (fs->is_open())
		{
			fs->close();
		}

		delete fs;
		
		fs = nullptr;
	}
}

tuple<int, const char*> DataReader::ReadData()
{
	unsigned short len;
	Read(len);

	if (len == 0)
	{
		return make_tuple(len, nullptr);
	}

	auto data = new char[len];
	bs->sgetn(data, len);

	return make_tuple(len, data);
}

string DataReader::ReadString()
{
	auto data = ReadData();

	if (get<0>(data) == 0)
	{
		return "";
	}

	auto text = string(get<1>(data), get<0>(data));

	delete[] get<1>(data);

	return text;
}

DataReader::~DataReader()
{
	Close();
}

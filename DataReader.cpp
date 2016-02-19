#include "DataReader.h"
#include "Utils.h"
#include <iostream>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/filesystem.hpp>

using namespace std;
namespace io = boost::iostreams;
namespace fs = boost::filesystem;

DataReader::DataReader() : fs(nullptr), bs(nullptr)
{
}

bool DataReader::OpenFile(const string& filename)
{
	Close();

	fs = new ifstream();
	fs->open(filename, ifstream::binary);

	if (!fs->good())
	{
		delete fs;
		fs = nullptr;
		return false;
	}

	bs = new io::filtering_istreambuf();

	if (fs::path(filename).extension() == ".gz")
	{
		bs->push(io::gzip_decompressor());
	}

	bs->push(*fs);

	return true;
}

bool DataReader::OpenEnv(const string& name)
{
	vector<string> paths = {
#if Windows
		get<0>(splitPath(getAppPath())) + "\\data\\" + name + ".dat",
		get<0>(splitPath(getAppPath())) + "\\data\\" + name + ".dat.gz",
		getEnvVar("APPDATA") + "\\RoliSoft\\Host Scanner\\data\\" + name + ".dat",
		getEnvVar("APPDATA") + "\\RoliSoft\\Host Scanner\\data\\" + name + ".dat.gz"
#else
		get<0>(splitPath(getAppPath())) + "/data/" + name + ".dat",
		get<0>(splitPath(getAppPath())) + "/data/" + name + ".dat.gz",
		"/var/lib/HostScanner/data/" + name + ".dat",
		"/var/lib/HostScanner/data/" + name + ".dat.gz"
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

	auto data = new char[len];
	bs->sgetn(data, len);

	return make_tuple(len, data);
}

string DataReader::ReadString()
{
	auto data = ReadData();
	return string(get<1>(data), get<0>(data));
}

DataReader::~DataReader()
{
	Close();
}

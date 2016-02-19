#include "DataReader.h"

using namespace std;

DataReader::DataReader(const string& filename)
{
	fs = new ifstream();
	fs->open(filename, ifstream::binary);
}

tuple<int, const char*> DataReader::ReadData()
{
	unsigned short len;
	Read(len);

	auto data = new char[len];
	fs->read(data, len);

	return make_tuple(len, data);
}

string DataReader::ReadString()
{
	auto data = ReadData();
	return string(get<1>(data), get<0>(data));
}

DataReader::~DataReader()
{
	if (fs != nullptr)
	{
		if (fs->is_open())
		{
			fs->close();
		}

		delete fs;
	}
}

#include "DataReader.h"

using namespace std;

DataReader::DataReader() : fs(nullptr)
{
}

bool DataReader::Open(const string& filename)
{
	Close();

	fs = new ifstream();
	fs->open(filename, ifstream::binary);

	return fs->good();
}

void DataReader::Close()
{
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
	Close();
}

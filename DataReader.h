#pragma once
#include "Stdafx.h"
#include <fstream>
#include <tuple>
#include <boost/iostreams/filtering_streambuf.hpp>

#if BOOST_VERSION >= 105800
	#include <boost/endian/conversion.hpp>
#endif

/*!
 * Implements a file stream wrapper for reading binary data files.
 */
class DataReader
{
public:

	/*!
	 * Creates a new instance of this type.
	 */
	DataReader();
	
	/*!
	 * Opens the specified file for reading.
	 *
	 * \param filename Path to the data file.
	 *
	 * \return Value indicating whether the file was opened successfully.
	 */
	bool OpenFile(const std::string& filename);
	
	/*!
	 * Finds the data file with the specified name and opens it for reading.
	 *
	 * \param name Name of the data file.
	 *
	 * \return Value indicating whether the file was opened successfully.
	 */
	bool OpenEnv(const std::string& name);

	/*!
	 * Closes the currently open file, if any.
	 */
	void Close();

	/*!
	 * Reads the next field as a numeric of type `T` from the file.
	 *
	 * \param value Reference to variable where to store numeric of type `T`.
	 */
	template <class T>
	void Read(T& value)
	{
		bs->sgetn(reinterpret_cast<char*>(&value), sizeof(T));
#if BOOST_VERSION >= 105800
		boost::endian::little_to_native_inplace(value);
#endif
	}
	
	/*!
	 * Reads the next field as a variable-length binary data from the file.
	 *
	 * \return Field as variable-length binary data.
	 */
	std::tuple<int, const char*> ReadData();

	/*!
	 * Reads the next field as string from the file.
	 *
	 * \return Field as string value.
	 */
	std::string ReadString();

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	~DataReader();

private:

	/*!
	 * Pointer to the currently open data file.
	 */
	std::ifstream *fs;

	/*!
	 * Pointer to the filtering stream buffer the currently open file is wrapped in.
	 */
	boost::iostreams::filtering_istreambuf* bs;

};

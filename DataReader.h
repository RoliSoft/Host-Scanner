#pragma once
#include "Stdafx.h"
#include <fstream>
#include <tuple>
#include <boost/endian/conversion.hpp>

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
	 * \param filename Name of the data file.
	 *
	 * \return Value indicating whether the file was opened successfully.
	 */
	bool Open(const std::string& filename);

	/*!
	 * Closes the currently open file, if any.
	 */
	void Close();

	/*!
	 * Reads the next field as a numeric of type `T` from the file.
	 *
	 * \return Field as numeric of type `T`.
	 */
	template <class T>
	void Read(T& value)
	{
		fs->read(reinterpret_cast<char*>(&value), sizeof(T));
		boost::endian::little_to_native_inplace(value);
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

};

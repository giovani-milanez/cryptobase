/*
 * ByteArray.cpp
 *
 *      Author: Giovani Milanez Espindola
 *	   Contact: giovani.milanez@gmail.com
 *	Created on: 04/09/2013
 */

#include "cryptobase/ByteArray.hpp"

#include <fstream>
#include <sys/stat.h>

namespace cryptobase {

ByteArray createFromFile(const std::string& filename)
{
	struct stat s;
	bool isFile = (stat (filename.c_str(), &s) == 0);
	if(!isFile)
		throw cryptobase::OpenFileException("'"+filename+"' does not exists or is not a file");

	std::ifstream ifs(filename, std::ios::binary|std::ios::ate);
	std::ifstream::pos_type pos = ifs.tellg();
	ByteArray result(pos);
    ifs.seekg(0, std::ios::beg);
    ifs.read((char *)result.begin(), pos);
    return result;
}

std::string hex(const ByteArray& ba)
{
	int size = ba.size();
    char *hex_data = new char[size*2 +1];

    int j = 0;
    for(int i = 0; i < size; i++)
    {
		sprintf(&hex_data[j], "%02X", ba[i]);
		j+=2;
    }
    hex_data[j] = '\0';
	std::string data(hex_data);
	delete[] hex_data;
    return data;

}

std::ostream& operator<<( std::ostream& os, const ByteArray& buffer )
{
	os.write(reinterpret_cast<const char*>(buffer.begin()), buffer.size());
	return os;
}

}

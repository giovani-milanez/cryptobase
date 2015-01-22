/*
 * ByteArray.hpp
 *
 *      Author: Giovani Milanez Espindola
 *	   Contact: giovani.milanez@gmail.com
 *	Created on: 03/09/2013
 */

#ifndef cryptobase_BYTEARRAY_H_
#define cryptobase_BYTEARRAY_H_

#include "cryptobase/Buffer.hpp"

#include <fstream>

namespace cryptobase {

typedef Buffer<unsigned char> CRYPTOBASE_API ByteArray;

CRYPTOBASE_API ByteArray createFromFile(const std::string& filename);
CRYPTOBASE_API std::string hex(const ByteArray& ba);
CRYPTOBASE_API std::ostream& operator<<( std::ostream& os, const ByteArray& buffer );

}
#endif /* BYTEARRAY_H_ */

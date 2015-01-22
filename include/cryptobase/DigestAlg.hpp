/*
 * DigestAlg.hpp
 *
 *      Author: Giovani Milanez Espindola
 *	   Contact: giovani.milanez@gmail.com
 *	Created on: 04/09/2013
 */

#ifndef DIGESTALG_HPP_
#define DIGESTALG_HPP_

namespace cryptobase {

enum DigestAlg
{
	MD4 = 257,
	MD5 = 4,
	RIPEMD160 = 117,
	SHA = 41,
	SHA1 = 64,
	SHA224 = 675,
	SHA256 = 672,
	SHA384 = 673,
	SHA512 = 674,
};

}

#endif /* DIGESTALG_HPP_ */

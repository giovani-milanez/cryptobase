/*
 * PublicKey.hpp
 *
 *  Created on: 10/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef PUBLICKEY_HPP_
#define PUBLICKEY_HPP_

#include "cryptobase/AsymmetricKey.hpp"

namespace cryptobase {

class CRYPTOBASE_API PublicKey : public AsymmetricKey
{
public:
	explicit PublicKey(EVP_PKEY *key);
	explicit PublicKey(RSA *key);
	explicit PublicKey(EC_KEY *key);

	PublicKey(PublicKey&& src);
	PublicKey& operator=(PublicKey&& rhs);

	virtual ~PublicKey();

	ByteArray getDerEncoded() const;
	std::string getPemEncoded() const;
};

} /* namespace cryptobase */
#endif /* PUBLICKEY_HPP_ */

/*
 * PrivateKey.hpp
 *
 *  Created on: 10/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef PRIVATEKEY_HPP_
#define PRIVATEKEY_HPP_

#include "cryptobase/AsymmetricKey.hpp"

namespace cryptobase {

class CRYPTOBASE_API PrivateKey : public AsymmetricKey
{
public:
	explicit PrivateKey(EVP_PKEY *key);
	explicit PrivateKey(RSA *key);
	explicit PrivateKey(EC_KEY *key);
	explicit PrivateKey(const ByteArray& derEncoded);
	explicit PrivateKey(const std::string& pemEncoded, const std::string& passphrase = "");

	PrivateKey(PrivateKey&& src);
	PrivateKey& operator=(PrivateKey&& rhs);

	virtual ~PrivateKey();

	ByteArray getDerEncoded() const;
	std::string getPemEncoded() const;
};

} /* namespace cryptobase */
#endif /* PRIVATEKEY_HPP_ */

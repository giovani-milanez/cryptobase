/*
 * AsymmetricKey.hpp
 *
 *  Created on: 10/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef ASYMMETRICKEY_HPP_
#define ASYMMETRICKEY_HPP_

typedef struct evp_pkey_st EVP_PKEY;
typedef struct rsa_st RSA;
typedef struct ec_key_st EC_KEY;

#include "cryptobase/Defs.h"
#include "cryptobase/ByteArray.hpp"

namespace cryptobase {

class CRYPTOBASE_API AsymmetricKey
{
public:
	explicit AsymmetricKey(EVP_PKEY *key);
	explicit AsymmetricKey(RSA *key);
	explicit AsymmetricKey(EC_KEY *key);

	AsymmetricKey(AsymmetricKey&& src);
	AsymmetricKey& operator=(AsymmetricKey&& rhs);

	virtual ~AsymmetricKey();

	virtual ByteArray getDerEncoded() const = 0;
	virtual std::string getPemEncoded() const = 0;

	EVP_PKEY* internal_;
protected:
	AsymmetricKey(const AsymmetricKey&);
	AsymmetricKey& operator=(const AsymmetricKey&);
};

}

#endif /* ASYMMETRICKEY_HPP_ */

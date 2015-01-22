/*
 * PublicKey.cpp
 *
 *  Created on: 10/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#include "cryptobase/PublicKey.hpp"

#include <openssl/pem.h>

namespace cryptobase {

PublicKey::~PublicKey()
{
}

PublicKey::PublicKey(EVP_PKEY* key) :
		AsymmetricKey(key)
{
	//TODO ensure it is a public key
}

PublicKey::PublicKey(RSA* key) :
		AsymmetricKey(key)
{
	//TODO ensure it is a public key
}

PublicKey::PublicKey(EC_KEY* key) :
		AsymmetricKey(key)
{
	//TODO ensure it is a public key
}

PublicKey::PublicKey(PublicKey&& src) :
		AsymmetricKey(std::move(src))
{
}

PublicKey& PublicKey::operator=(PublicKey&& rhs)
{
	if (this == &rhs)
		return *this;

	EVP_PKEY_free(internal_);
	internal_ = rhs.internal_;
	rhs.internal_ = nullptr;
	return *this;
}

ByteArray PublicKey::getDerEncoded() const
{
	std::size_t size = i2d_PUBKEY(internal_, nullptr);
	ByteArray responseDer(size);
	unsigned char *derPtr = responseDer.begin();
	unsigned char *tmp = derPtr;
	i2d_PUBKEY(internal_, &tmp);
	return responseDer;
}

std::string PublicKey::getPemEncoded() const
{
	const char *data;
	BIO *buffer = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(buffer, internal_);
	std::size_t ndata = BIO_ctrl(buffer,3,0,(char *)&data);
	std::string ret(data, ndata);
	BIO_free(buffer);
	return ret;
}

} /* namespace cryptobase */

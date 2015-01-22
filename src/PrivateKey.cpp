/*
 * PrivateKey.cpp
 *
 *  Created on: 10/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#include "cryptobase/PrivateKey.hpp"

#include <openssl/pem.h>

#include <string>

#include <iostream>

namespace cryptobase {

PrivateKey::PrivateKey(EVP_PKEY* key) :
		AsymmetricKey(key)
{
	//TODO ensure key is private
}

PrivateKey::PrivateKey(RSA* key) :
		AsymmetricKey(key)
{
	//TODO ensure key is private
}

PrivateKey::PrivateKey(EC_KEY* key) :
		AsymmetricKey(key)
{
	//TODO ensure key is private
}


PrivateKey::PrivateKey(const ByteArray& derEncoded) :
		AsymmetricKey(EVP_PKEY_new())
{
	EVP_PKEY_free(internal_);
	BIO *buffer = BIO_new(BIO_s_mem());
	BIO_write(buffer, derEncoded.begin(), derEncoded.size());
	internal_ = d2i_PrivateKey_bio(buffer, nullptr);
	if (internal_ == nullptr)
	{
		BIO_free(buffer);
		throw DerDecodeException("Could not decode DER private key");
	}
	BIO_free(buffer);
}

PrivateKey::PrivateKey(const std::string& pemEncoded, const std::string& passphrase) :
		AsymmetricKey(EVP_PKEY_new())
{
	EVP_PKEY_free(internal_);
	BIO *buffer = BIO_new(BIO_s_mem());
	BIO_write(buffer, pemEncoded.c_str(), pemEncoded.size());
	internal_ = PEM_read_bio_PrivateKey(buffer, nullptr, nullptr, passphrase == "" ? nullptr : (char *)passphrase.c_str());
	if (internal_ == nullptr)
	{
		BIO_free(buffer);
		throw PemDecodeException("Could not decode PEM private key");
	}
	BIO_free(buffer);
}

PrivateKey::PrivateKey(PrivateKey&& src) :
		AsymmetricKey(std::move(src))
{

}

PrivateKey& PrivateKey::operator=(PrivateKey&& rhs)
{
	AsymmetricKey::operator =(std::move(rhs));
	return *this;
}

PrivateKey::~PrivateKey()
{
}

ByteArray PrivateKey::getDerEncoded() const
{
	std::size_t size = i2d_PrivateKey(internal_, nullptr);
	ByteArray responseDer(size);
	unsigned char *derPtr = responseDer.begin();
	unsigned char *tmp = derPtr;
	i2d_PrivateKey(internal_, &tmp);
	return responseDer;
}

std::string PrivateKey::getPemEncoded() const
{
	const char *data;
	BIO *buffer = BIO_new(BIO_s_mem());
	PEM_write_bio_PrivateKey(buffer, internal_, NULL, NULL, 0, NULL, NULL);
	std::size_t ndata = BIO_get_mem_data(buffer, &data);
	std::string ret(data, ndata);
	BIO_free(buffer);
	return ret;
}

} /* namespace cryptobase */

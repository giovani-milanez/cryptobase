/*
 * AsymmetricKey.cpp
 *
 *  Created on: 10/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#include "cryptobase/AsymmetricKey.hpp"
#include "cryptobase/Exception.hpp"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>

namespace cryptobase {

AsymmetricKey::AsymmetricKey(EVP_PKEY* key) :
	internal_(key)
{
	if(internal_ == nullptr)
		throw NullPointerException("Null EVP_PKEY pointer");
}

AsymmetricKey::AsymmetricKey(RSA* key)
{
	if(key == nullptr)
		throw NullPointerException("Null RSA pointer");

	internal_ = EVP_PKEY_new();
	internal_->type = EVP_PKEY_RSA;
	EVP_PKEY_set1_RSA(internal_, key);
	RSA_free(key);
}

AsymmetricKey::AsymmetricKey(EC_KEY* key)
{
	if(key == nullptr)
		throw NullPointerException("Null EC_KEY pointer");

	internal_ = EVP_PKEY_new();
	internal_->type = EVP_PKEY_EC;
	EVP_PKEY_set1_EC_KEY(internal_, key);
	EC_KEY_free(key);
}

AsymmetricKey::AsymmetricKey(AsymmetricKey&& src) :
		internal_(src.internal_)
{
	src.internal_ = nullptr;
}

AsymmetricKey& AsymmetricKey::operator=(AsymmetricKey&& rhs)
{
	if (this == &rhs)
		return *this;

	EVP_PKEY_free(internal_);
	internal_ = rhs.internal_;
	rhs.internal_ = nullptr;
	return *this;
}

AsymmetricKey::~AsymmetricKey()
{
	EVP_PKEY_free(internal_);
}

}

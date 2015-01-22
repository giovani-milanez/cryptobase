/*
 * MessageDigest.cpp
 *
 *      Author: Giovani Milanez Espindola
 *	   Contact: giovani.milanez@gmail.com
 *	Created on: 04/09/2013
 */

#include "cryptobase/MessageDigest.hpp"

#include <openssl/evp.h>

namespace cryptobase {

MessageDigest::MessageDigest(DigestAlg algorithm)
try :
	algorithm_(algorithm),
	md_(EVP_get_digestbynid(algorithm)),
	ctx_(EVP_MD_CTX_create())
{
	if(md_ == nullptr)
		throw NullPointerException("Could not initialize MessageDigest. Try adding OpenSSL_add_all_digests().");

	int rc = EVP_DigestInit_ex(ctx_, md_, nullptr);
	if (!rc)
		throw RuntimeException("Could not initialize MessageDigest");
}catch(...)
{
	EVP_MD_CTX_destroy(ctx_);
	throw;
}

MessageDigest::~MessageDigest()
{
	EVP_MD_CTX_destroy(ctx_);
}

void MessageDigest::update(const ByteArray& data)
{
	int rc = EVP_DigestUpdate(ctx_, data.begin(), data.size());
	if (!rc)
		throw RuntimeException("Could not update MessageDigest");

}

void MessageDigest::update(const std::string& data)
{
	update(ByteArray((const unsigned char *)data.c_str(), data.size()));
}

ByteArray MessageDigest::doFinal()
{
	ByteArray hash(EVP_MD_size(ctx_->digest));
	int rc = EVP_DigestFinal_ex(ctx_, hash.begin(), nullptr);
	if (!rc)
		throw RuntimeException("Could not finish MessageDigest");

	EVP_DigestInit_ex(ctx_, md_, nullptr);
	return hash;
}

ByteArray MessageDigest::doFinal(const ByteArray& data)
{
	update(data);
	return doFinal();
}

ByteArray MessageDigest::doFinal(const std::string& data)
{
	update(data);
	return doFinal();
}


} /* namespace cryptobase */

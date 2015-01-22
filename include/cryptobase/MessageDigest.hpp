/*
 * MessageDigest.hpp
 *
 *      Author: Giovani Milanez Espindola
 *	   Contact: giovani.milanez@gmail.com
 *	Created on: 04/09/2013
 */

#ifndef MESSAGEDIGEST_HPP_
#define MESSAGEDIGEST_HPP_

#include "cryptobase/Defs.h"
#include "cryptobase/DigestAlg.hpp"
#include "cryptobase/ByteArray.hpp"

typedef struct env_md_ctx_st EVP_MD_CTX;
typedef struct env_md_st EVP_MD;

namespace cryptobase {

class CRYPTOBASE_API MessageDigest
{
public:
	explicit MessageDigest(DigestAlg algorithm);

	virtual ~MessageDigest();

	void update(const ByteArray& data);
	void update(const std::string& data);

	// Finishes a digest operation and returns the result digest within a ByteArray. The internal state
	// is reseted. A new digest operation can be started by calling any of the update() functions.
	ByteArray doFinal();

	// Make a last update and then finishes the digest operation, returning the result digest within
	// a ByteArray. The internal state is reseted. A new digest operation can be started by calling
	// any of the update()'s functions (or this function).
	ByteArray doFinal(const ByteArray& data);

	// Make a last update and then finishes the digest operation, returning the result digest within
	// a ByteArray. The internal state is reseted. A new digest operation can be started by calling
	// any of the update()'s functions (or this function).
	ByteArray doFinal(const std::string& data);

	DigestAlg getAlgorithm() const;
private:
	DigestAlg algorithm_;
	const EVP_MD *md_;
	EVP_MD_CTX *ctx_;

	MessageDigest(const MessageDigest& src);
	MessageDigest& operator=(const MessageDigest& rhs);
	MessageDigest(MessageDigest&& src);
	MessageDigest& operator=(MessageDigest&& rhs);
};

inline DigestAlg MessageDigest::getAlgorithm() const
{
	return algorithm_;
}


} /* namespace cryptobase */

#endif /* MESSAGEDIGEST_HPP_ */

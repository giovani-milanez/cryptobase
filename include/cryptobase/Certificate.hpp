/*
 * Certificate.hpp
 *
 *      Author: Giovani Milanez Espindola
 *	   Contact: giovani.milanez@gmail.com
 *	Created on: 08/10/2013
 */

#ifndef CERTIFICATE_HPP_
#define CERTIFICATE_HPP_

#include "cryptobase/Asn1Class.hpp"
#include "cryptobase/DigestAlg.hpp"
#include "cryptobase/X509Name.hpp"
#include "cryptobase/Extension.hpp"
#include "cryptobase/PublicKey.hpp"

typedef struct x509_st X509;

namespace cryptobase {

ASN1_DECLARE_CLASS_PEM(CertificateAsn1, X509)

class CRYPTOBASE_API Certificate : public CertificateAsn1
{
public:
	explicit Certificate(X509* p);
	explicit Certificate(const ByteArray& derEncoded);
	explicit Certificate(const std::string& pemEncoded);
	virtual ~Certificate();

	unsigned long getSerialNumber() const;
	std::string getSerialNumberString() const;
	ObjectIdentifier getSignatureAlgorithm() const;
	PublicKey getPublicKey() const;
	//ByteArray getPublicKeyInfo(DigestAlg alg) const;
	long getVersion() const;
	timeval getNotBefore() const;
	timeval getNotAfter() const;
	X509Name getIssuer() const;
	X509Name getSubject() const;
	std::vector<Extension> getExtensions() const;
	ByteArray getFingerPrint(DigestAlg algorithm) const;
	//bool verify(const PublicKey& publicKey) const;
	bool operator ==(const Certificate& value);
	bool operator !=(const Certificate& value);

	static Certificate fromFile(const std::string& filePath);

};

} /* namespace cryptobase */

#endif /* CERTIFICATE_HPP_ */

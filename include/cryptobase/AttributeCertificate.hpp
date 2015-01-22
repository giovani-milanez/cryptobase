/*
 * AttributeCertificate.hpp
 *
 *  Created on: 04/09/2013
 *      Author: Giovani Milanez Espindola
 *  giovani.milanez@gmail.com
 */

#ifndef ATTRIBUTECERTIFICATE_HPP_
#define ATTRIBUTECERTIFICATE_HPP_

#include "cryptobase/Asn1Class.hpp"
#include "cryptobase/ObjectIdentifier.hpp"
#include "cryptobase/AttributeCertificateInfo.hpp"
#include "cryptobase/DigestAlg.hpp"

#include <vector>

typedef struct X509AC_st X509AC;

namespace cryptobase {

class PrivateKey;
class Certificate;
class PublicKey;
class CertificateRevocationList;

ASN1_DECLARE_CLASS_PEM(AttributeCertificateAsn1, X509AC)

CRYPTOBASE_DECLARE_EXCEPTION(CRYPTOBASE_API, SignACException, Exception)

class CRYPTOBASE_API AttributeCertificate : public AttributeCertificateAsn1
{
public:
	AttributeCertificate(
			const PrivateKey& signKey,
			DigestAlg algor,
			const Holder& holder,
			const X509Name& issuer,
			std::uint64_t serial,
			const AttributeCertificateValidity& validity,
			const std::vector<Attribute>& attributes,
			const std::vector<Extension>& extensions = std::vector<Extension>());

	explicit AttributeCertificate(X509AC *p);
	AttributeCertificate(const ByteArray& derEncoded);
	AttributeCertificate(const std::string& pemEncoded);
	virtual ~AttributeCertificate();

	AttributeCertificateInfo getInfo() const;
	ObjectIdentifier getSignatureAlgorithm() const;
	ByteArray getSignature() const;

	/**
	 * @throw CertificateVerificationException In case of verification issue (e.g. certificate expired)
	 */
	void verifyTrustPath(const cryptobase::Certificate& issuerCert, const std::vector<cryptobase::Certificate>& trustedCerts,
			const std::vector<cryptobase::CertificateRevocationList>& crls, time_t trustedTime);
	void verifyTrustPath(const cryptobase::Certificate& issuerCert, const std::vector<cryptobase::Certificate>& trustedCerts, const std::vector<cryptobase::CertificateRevocationList>& crls);
	void verifyTrustPath(const cryptobase::Certificate& issuerCert, const std::vector<cryptobase::Certificate>& trustedCerts, time_t trustedTime);
	void verifyTrustPath(const cryptobase::Certificate& issuerCert, const std::vector<cryptobase::Certificate>& trustedCerts);

	/**
	 * Verifies signature integrity based on issuer certificate
	 */
	bool verifySignature(const cryptobase::Certificate& issuerCert) const;
	/**
	 * Verifies signature integrity based on issuer public key
	 */
	bool verifySignature(const cryptobase::PublicKey& issuerPubKey) const;
	/**
	 *	Uses a trusted time to evaluate validity,
	 *	that is the time is greater than notBefore and less than notAfter
	 */
	bool verifyValidity(time_t trustedTime) const;
	/**
	 * Uses the current system time to evaluate validity
	 */
	bool verifyValidity() const;

};

} /* namespace cryptobase */
#endif /* ATTRIBUTECERTIFICATE_HPP_ */

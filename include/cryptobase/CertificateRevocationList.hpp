/*
 * CertificateRevocationList.hpp
 *
 *  Created on: 28/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef CERTIFICATEREVOCATIONLIST_HPP_
#define CERTIFICATEREVOCATIONLIST_HPP_

#include "cryptobase/Asn1Class.hpp"
#include "cryptobase/Certificate.hpp"
#include "cryptobase/DigestAlg.hpp"
#include "cryptobase/RevokedCertificate.hpp"

typedef struct X509_crl_st X509_CRL;

namespace cryptobase {

class PrivateKey;

ASN1_DECLARE_CLASS_PEM(CertificateRevocationListAsn1, X509_CRL)
CRYPTOBASE_DECLARE_EXCEPTION(CRYPTOBASE_API, SignCRLException, Exception)

class CRYPTOBASE_API CertificateRevocationList : public CertificateRevocationListAsn1
{
public:
	explicit CertificateRevocationList(X509_CRL *p);
	explicit CertificateRevocationList(const ByteArray& derEncoded);
	explicit CertificateRevocationList(const std::string& pemEncoded);

	virtual ~CertificateRevocationList();

	void setSerialNumber(std::uint32_t serial);
	std::uint32_t getSerialNumber() const;
	void setVersion(int version);
	int getVersion() const;
	void setIssuer(const Certificate& issuerCert);
	void setIssuer(const X509Name& issuerDn);
	X509Name getIssuer() const;
	void setLastUpdate(time_t lastUpdateEpoch);
	time_t getLastUpdate() const;
	void setNextUpdate(time_t nextUpdateEpoch);
	time_t getNextUpdate() const;
	void addRevoked(const RevokedCertificate& toRevoke);
	std::vector<RevokedCertificate> getRevokedCertificates() const;
	void addExtension(const Extension& ext);
	std::vector<Extension> getExtensions() const;
	void appendRevokedCertificates(const CertificateRevocationList& anotherCrl);

	/**
	 * throw SignCRLException on sign error
	 */
	void sign(const PrivateKey& privKey, DigestAlg digestAlg);
	bool verify(const Certificate& issuerCert) const;
	bool verify(const PublicKey& issuerPubKey) const;
};

} /* namespace cryptobase */
#endif /* CERTIFICATEREVOCATIONLIST_HPP_ */

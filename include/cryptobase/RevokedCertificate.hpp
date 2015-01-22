/*
 * RevokedCertificate.hpp
 *
 *  Criado em: 18/03/2014
 *      Autor: Giovani Milanez Espindola
 *  giovani.milanez@gmail.com
 */

#ifndef REVOKEDCERTIFICATE_HPP_
#define REVOKEDCERTIFICATE_HPP_

#include "cryptobase/Asn1Class.hpp"

typedef struct x509_revoked_st X509_REVOKED;

CRYPTOBASE_DECLARE_ASN1_DUP_FUNCTION(X509_REVOKED)

namespace cryptobase {

class Certificate;
class AttributeCertificate;

ASN1_DECLARE_CLASS(RevokedCertificateAsn1, X509_REVOKED)

class CRYPTOBASE_API RevokedCertificate : public RevokedCertificateAsn1
{
public:

	 enum CRLReason {
	  unspecified = 0,
	  keyCompromise = 1,
	  cACompromise = 2,
	  affiliationChanged = 3,
	  superseded = 4,
	  cessationOfOperation = 5,
	  certificateHold = 6,
	  removeFromCRL = 8,
	  privilegeWithdrawn = 9,
	  aACompromise = 10
	 };

	explicit RevokedCertificate(X509_REVOKED *p);
	virtual ~RevokedCertificate();

	void setReason(CRLReason reason);
	CRLReason getReason() const;
	void setSerialNumber(std::uint32_t serial) const;
	void setSerialNumber(const std::string& serial) const;
	std::string getSerialNumber() const;
	void setRevocationDate(time_t dateEpoch);
	time_t getRevocationDate() const;


	static RevokedCertificate fromSerial(const std::string& serial, CRLReason reason);
	static RevokedCertificate fromCertificate(const Certificate& cert, CRLReason reason);
	static RevokedCertificate fromAttributeCertificate(const AttributeCertificate& ac, CRLReason reason);


};

} /* namespace cryptobase */
#endif /* REVOKEDCERTIFICATE_HPP_ */

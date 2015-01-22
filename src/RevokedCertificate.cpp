/*
 * RevokedCertificate.cpp
 *
 *  Criado em: 18/03/2014
 *      Autor: Giovani Milanez Espindola
 *  giovani.milanez@gmail.com
 */

#include "cryptobase/RevokedCertificate.hpp"
#include "cryptobase/Certificate.hpp"
#include "cryptobase/AttributeCertificate.hpp"
#include "cryptobase/TimeFunctions.hpp"

#include <openssl/x509.h>

CRYPTOBASE_IMPLEMENT_ASN1_DUP_FUNCTION(X509_REVOKED)

namespace cryptobase {

ASN1_IMPLEMENT_CLASS(RevokedCertificateAsn1, X509_REVOKED)

RevokedCertificate::RevokedCertificate(X509_REVOKED *p) :
	RevokedCertificateAsn1(p)
{
}

RevokedCertificate::~RevokedCertificate()
{
}

void RevokedCertificate::setReason(CRLReason reason)
{
	ASN1_ENUMERATED *asn1Enumerated = ASN1_ENUMERATED_new();
	ASN1_ENUMERATED_set(asn1Enumerated, reason);
	X509_REVOKED_add1_ext_i2d(internal_, NID_crl_reason, asn1Enumerated, 0, 0);
	ASN1_ENUMERATED_free(asn1Enumerated);
}

RevokedCertificate::CRLReason RevokedCertificate::getReason() const
{
	CRLReason reason = CRLReason::unspecified;
	ASN1_ENUMERATED *asn1Enumerated = (ASN1_ENUMERATED*) X509_REVOKED_get_ext_d2i(internal_, NID_crl_reason, NULL, NULL);
	if (asn1Enumerated != nullptr)
	{
		reason = (CRLReason)ASN1_ENUMERATED_get(asn1Enumerated);
		ASN1_ENUMERATED_free(asn1Enumerated);
	}
	return reason;
}

void RevokedCertificate::setSerialNumber(std::uint32_t serial) const
{
	if(internal_->serialNumber == nullptr)
		internal_->serialNumber = ASN1_INTEGER_new();

	ASN1_INTEGER_set(internal_->serialNumber, serial);
}

void RevokedCertificate::setSerialNumber(const std::string& serial) const
{
	BIGNUM *bn = BN_new();
	BN_dec2bn(&bn, (const char *)serial.c_str());
	ASN1_INTEGER *serialAsn1 = ASN1_INTEGER_new();
	BN_to_ASN1_INTEGER(bn, serialAsn1);

	X509_REVOKED_set_serialNumber(internal_, serialAsn1);
	BN_free(bn);
	ASN1_INTEGER_free(serialAsn1);
}

std::string RevokedCertificate::getSerialNumber() const
{
	BIGNUM *bn = ASN1_INTEGER_to_BN(internal_->serialNumber, nullptr);
	char *str = BN_bn2dec(bn);
	std::string ret(str);
	OPENSSL_free(str);
	BN_free(bn);
	return ret;
}

void RevokedCertificate::setRevocationDate(time_t dateEpoch)
{
	timeval tv;
	tv.tv_sec = dateEpoch;
	tv.tv_usec = 0;
	GeneralizedTime time(tv);
	X509_REVOKED_set_revocationDate(internal_, time.internal_);
}

time_t RevokedCertificate::getRevocationDate() const
{
	return GeneralizedTime(internal_->revocationDate).getEpoch();
}

RevokedCertificate RevokedCertificate::fromSerial(const std::string& serial, CRLReason reason)
{
	timeval tv;
	gettimeofday(&tv, nullptr);

	RevokedCertificate revoked(X509_REVOKED_new());
	revoked.setSerialNumber(serial);
	revoked.setReason(reason);
	revoked.setRevocationDate(tv.tv_sec);

	return revoked;
}

RevokedCertificate RevokedCertificate::fromCertificate(const Certificate& cert, CRLReason reason)
{
	return RevokedCertificate::fromSerial(cert.getSerialNumberString(), reason);
}

RevokedCertificate RevokedCertificate::fromAttributeCertificate(const AttributeCertificate& ac, CRLReason reason)
{
	return RevokedCertificate::fromSerial(ac.getInfo().getSerialString(), reason);
}

} /* namespace cryptobase */

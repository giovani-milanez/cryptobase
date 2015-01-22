/*
 * CertificateRevocationList.cpp
 *
 *  Created on: 28/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#include "cryptobase/CertificateRevocationList.hpp"
#include "cryptobase/GeneralizedTime.hpp"
#include "cryptobase/PrivateKey.hpp"

#include <openssl/x509.h>

namespace cryptobase {

ASN1_IMPLEMENT_CLASS_PEM(CertificateRevocationListAsn1, X509_CRL)
CRYPTOBASE_IMPLEMENT_EXCEPTION(SignCRLException, Exception, "Could not sign CRL")

CertificateRevocationList::CertificateRevocationList(X509_CRL *p) :
		CertificateRevocationListAsn1(p)
{
}

CertificateRevocationList::CertificateRevocationList(const ByteArray& derEncoded) :
		CertificateRevocationListAsn1(derEncoded)
{
}

CertificateRevocationList::CertificateRevocationList(const std::string& pemEncoded) :
		CertificateRevocationListAsn1(pemEncoded)
{
}


CertificateRevocationList::~CertificateRevocationList()
{
}

void CertificateRevocationList::setSerialNumber(std::uint32_t serial)
{
	ASN1_INTEGER* serialAsn1 = ASN1_INTEGER_new();
	ASN1_INTEGER_set(serialAsn1, serial);
	X509_CRL_add1_ext_i2d(internal_, NID_crl_number, serialAsn1, 0, 0);
	ASN1_INTEGER_free(serialAsn1);
}

std::uint32_t CertificateRevocationList::getSerialNumber() const
{
	ASN1_INTEGER *asn1Int = (ASN1_INTEGER*) X509_CRL_get_ext_d2i(internal_, NID_crl_number, 0, 0);
	return ASN1_INTEGER_get(asn1Int);
}

void CertificateRevocationList::setVersion(int version)
{
	X509_CRL_set_version(internal_, version);
}

int CertificateRevocationList::getVersion() const
{
	return X509_CRL_get_version(internal_);
}

void CertificateRevocationList::setIssuer(const Certificate& issuerCert)
{
	setIssuer(issuerCert.getSubject());
}

void CertificateRevocationList::setIssuer(const X509Name& issuerDn)
{
	X509_CRL_set_issuer_name(internal_, issuerDn.internal_);
}

X509Name CertificateRevocationList::getIssuer() const
{
	return X509Name(X509_NAME_dup(X509_CRL_get_issuer(internal_)));
}

void CertificateRevocationList::setLastUpdate(time_t lastUpdateEpoch)
{
	timeval tv;
	tv.tv_sec = lastUpdateEpoch;
	tv.tv_usec = 0;
	GeneralizedTime time(tv);
	X509_CRL_set_lastUpdate(internal_, time.internal_);
}

time_t CertificateRevocationList::getLastUpdate() const
{
	GeneralizedTime time(ASN1_GENERALIZEDTIME_dup(X509_CRL_get_lastUpdate(internal_)));
	return time.getEpoch();
}

void CertificateRevocationList::setNextUpdate(time_t nextUpdateEpoch)
{
	timeval tv;
	tv.tv_sec = nextUpdateEpoch;
	tv.tv_usec = 0;
	GeneralizedTime time(tv);
	X509_CRL_set_nextUpdate(internal_, time.internal_);
}

time_t CertificateRevocationList::getNextUpdate() const
{	
	GeneralizedTime time(ASN1_GENERALIZEDTIME_dup(X509_CRL_get_nextUpdate(internal_)));
	return time.getEpoch();
}

void CertificateRevocationList::addRevoked(const RevokedCertificate& toRevoke)
{
	X509_CRL_add0_revoked(internal_, X509_REVOKED_dup(toRevoke.internal_)); // check if need to dup
}
std::vector<RevokedCertificate> CertificateRevocationList::getRevokedCertificates() const
{
	std::vector<RevokedCertificate> revocatedCertificates;
	STACK_OF(X509_REVOKED)* revokedStack = X509_CRL_get_REVOKED(internal_);
	int revokedCount = sk_X509_REVOKED_num(revokedStack);
	revocatedCertificates.reserve(revokedCount);
	for (int i = 0; i < revokedCount; i++)
	{
		X509_REVOKED *revoked = sk_X509_REVOKED_value(revokedStack, i);
		revocatedCertificates.push_back(RevokedCertificate(X509_REVOKED_dup(revoked)));
	}
	return revocatedCertificates;
}

void CertificateRevocationList::addExtension(const Extension& ext)
{
	X509_CRL_add_ext(internal_, ext.internal_, -1);
}

std::vector<Extension> CertificateRevocationList::getExtensions() const
{
	std::vector<Extension> extensions;
	int extCount = X509_CRL_get_ext_count(internal_);
	extensions.reserve(extCount);
	for (int i = 0; i < extCount ; i++)
	{
		X509_EXTENSION *ext = X509_CRL_get_ext(internal_, i);
		extensions.push_back(Extension(X509_EXTENSION_dup(ext)));
	}

	return extensions;
}

void CertificateRevocationList::appendRevokedCertificates(const CertificateRevocationList& anotherCrl)
{
	for(auto revCert : anotherCrl.getRevokedCertificates())
		addRevoked(revCert);
}

void CertificateRevocationList::sign(const PrivateKey& privKey, DigestAlg digestAlg)
{
	int rc = X509_CRL_sign(internal_, privKey.internal_, EVP_get_digestbynid(digestAlg));
	if (rc == 0)
		throw SignCRLException("Error trying to sign the CRL");
}

bool CertificateRevocationList::verify(const Certificate& issuerCert) const
{
	return verify(issuerCert.getPublicKey());
}

bool CertificateRevocationList::verify(const PublicKey& issuerPubKey) const
{
	return X509_CRL_verify(internal_, issuerPubKey.internal_) == 1;
}

} /* namespace cryptobase */

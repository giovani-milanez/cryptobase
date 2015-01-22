/*
 * AttributeCertificate.cpp
 *
 *  Created on: 04/09/2013
 *      Author: Giovani Milanez Espindola
 *  giovani.milanez@gmail.com
 */

#include "cryptobase/AttributeCertificate.hpp"
#include "cryptobase/PrivateKey.hpp"
#include "cryptobase/PublicKey.hpp"
#include "cryptobase/Certificate.hpp"
#include "cryptobase/CertificateRevocationList.hpp"
#include "cryptobase/x509ac.h"
#include "cryptobase/x509ac-supp.h"
#include "cryptobase/TimeFunctions.hpp"

#include <typeinfo>
#include <string>
#include <sstream>

namespace cryptobase {

ASN1_IMPLEMENT_CLASS_PEM(AttributeCertificateAsn1, X509AC)

CRYPTOBASE_IMPLEMENT_EXCEPTION(SignACException, Exception, "Could not sign the attribute certificate")

AttributeCertificate::AttributeCertificate(
		const PrivateKey& signKey,
		DigestAlg algor,
		const Holder& holder,
		const X509Name& issuer,
		std::uint64_t serial,
		const AttributeCertificateValidity& validity,
		const std::vector<Attribute>& attributes,
		const std::vector<Extension>& extensions) :
		AttributeCertificateAsn1(X509AC_new())
{
	ASN1_INTEGER_set(internal_->info->version, 1);
	X509AC_HOLDER_free(internal_->info->holder);
	internal_->info->holder = X509AC_HOLDER_dup(holder.internal_);

	internal_->info->issuer->type = 1;
	internal_->info->issuer->d.v2Form = X509AC_V2FORM_new();
	internal_->info->issuer->d.v2Form->issuer = GENERAL_NAMES_new();
	sk_GENERAL_NAME_push(internal_->info->issuer->d.v2Form->issuer, GENERAL_NAME_new());
	GENERAL_NAME_set0_value(sk_GENERAL_NAME_value(internal_->info->issuer->d.v2Form->issuer, 0), GEN_DIRNAME, X509_NAME_dup(issuer.internal_));

	std::stringstream ss;
	ss << serial;
	std::string serialStr = ss.str();
	BIGNUM *bn = BN_new();
	BN_dec2bn(&bn, serialStr.c_str());
	ASN1_INTEGER_free(internal_->info->serial);
	internal_->info->serial = BN_to_ASN1_INTEGER(bn, nullptr);
	BN_free(bn);

	X509AC_VAL_free(internal_->info->validity);
	internal_->info->validity = X509AC_VAL_dup(validity.internal_);

	for(auto attr : attributes)
		sk_X509_ATTRIBUTE_push(internal_->info->attributes, X509_ATTRIBUTE_dup(attr.internal_));

	for(auto ext : extensions)
	{
		if(internal_->info->extensions == nullptr)
			internal_->info->extensions = sk_X509_EXTENSION_new_null();
		sk_X509_EXTENSION_push(internal_->info->extensions, X509_EXTENSION_dup(ext.internal_));
	}

	int sigRet = ASN1_sign( (i2d_of_void*)i2d_X509AC_INFO, internal_->info->algor,
			internal_->algor, internal_->signature, (char*)internal_->info, signKey.internal_, EVP_get_digestbynid(algor));

	if(sigRet == 0)
		throw SignACException("Error trying to sign AC.", sigRet);
}

AttributeCertificate::AttributeCertificate(X509AC *p) :
		AttributeCertificateAsn1(p)
{
}

AttributeCertificate::AttributeCertificate(const cryptobase::ByteArray& derEncoded) :
		AttributeCertificateAsn1(derEncoded)
{
}

AttributeCertificate::AttributeCertificate(const std::string& pemEncoded) :
		AttributeCertificateAsn1(pemEncoded)
{
}

AttributeCertificate::~AttributeCertificate()
{
}

AttributeCertificateInfo AttributeCertificate::getInfo() const
{
	return AttributeCertificateInfo(X509AC_INFO_dup(internal_->info));
}

ObjectIdentifier AttributeCertificate::getSignatureAlgorithm() const
{
	return ObjectIdentifier(OBJ_dup(internal_->algor->algorithm));
}

ByteArray AttributeCertificate::getSignature() const
{
	return ByteArray((const unsigned char *)internal_->signature->data, internal_->signature->length);
}

void AttributeCertificate::verifyTrustPath(const cryptobase::Certificate& issuerCert, const std::vector<cryptobase::Certificate>& trustedCerts,
		const std::vector<cryptobase::CertificateRevocationList>& crls, time_t trustedTime)
{
	if(issuerCert.getSubject() != getInfo().getIssuer())
		throw RuntimeException(std::string("The issuer certificate informed is not the one that signed the AC:\n").append(issuerCert.getSubject().getOneLine()).append(std::string("\n")).append(getInfo().getIssuer().getOneLine()));

	X509_STORE_CTX *store_ctx = X509_STORE_CTX_new();
	X509_STORE *store = X509_STORE_new();

	for (auto& cert : trustedCerts)
		X509_STORE_add_cert(store, cert.internal_);

	for(auto& crl : crls)
		X509_STORE_add_crl(store, crl.internal_);

	if(!crls.empty())
	{
		X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
		X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK_ALL);
	}

	X509_STORE_CTX_init(store_ctx, store, issuerCert.internal_, nullptr);
	X509_STORE_CTX_set_time(store_ctx, 0, trustedTime);
	X509_STORE_CTX_set_flags(store_ctx, X509_V_FLAG_USE_CHECK_TIME);


	int error = X509_V_OK;
	if(X509_verify_cert(store_ctx) != 1)
		error = X509_STORE_CTX_get_error(store_ctx);

	X509_STORE_free(store);
	X509_STORE_CTX_free(store_ctx);

	if(error != X509_V_OK)
		throw CertificateVerificationException(std::string(X509_verify_cert_error_string(error)), error);
}

void AttributeCertificate::verifyTrustPath(const cryptobase::Certificate& issuerCert, const std::vector<cryptobase::Certificate>& trustedCerts,
		const std::vector<cryptobase::CertificateRevocationList>& crls)
{
	timeval tv;
	gettimeofday(&tv, nullptr);
	time_t secs = tv.tv_sec;

	verifyTrustPath(issuerCert, trustedCerts, crls, secs);
}

void AttributeCertificate::verifyTrustPath(const cryptobase::Certificate& issuerCert, const std::vector<cryptobase::Certificate>& trustedCerts, time_t trustedTime)
{
	verifyTrustPath(issuerCert, trustedCerts, std::vector<cryptobase::CertificateRevocationList>(), trustedTime);
}

void AttributeCertificate::verifyTrustPath(const cryptobase::Certificate& issuerCert, const std::vector<cryptobase::Certificate>& trustedCerts)
{
	timeval tv;
	gettimeofday(&tv, nullptr);
	time_t secs = tv.tv_sec;

	verifyTrustPath(issuerCert, trustedCerts, std::vector<cryptobase::CertificateRevocationList>(), secs);
}

bool AttributeCertificate::verifySignature(const cryptobase::Certificate& issuerCert) const
{
	cryptobase::PublicKey pkey(X509_get_pubkey(issuerCert.internal_));
	return verifySignature(pkey);
}

bool AttributeCertificate::verifySignature(const cryptobase::PublicKey& issuerPubKey) const
{
	int ret = ASN1_item_verify(ASN1_ITEM_rptr(X509AC_INFO), internal_->algor, internal_->signature, internal_->info, issuerPubKey.internal_);
	return ret > 0;
}

bool AttributeCertificate::verifyValidity(time_t trustedTime) const
{
	int diffBefore = X509_cmp_time(internal_->info->validity->notBefore, &trustedTime);
	int diffAfter = X509_cmp_time(internal_->info->validity->notAfter, &trustedTime);

	return diffBefore < 0 && diffAfter > 0;
}

bool AttributeCertificate::verifyValidity() const
{
	timeval tv;
	gettimeofday(&tv, nullptr);
	time_t secs = tv.tv_sec;
	return verifyValidity(secs);
}

} /* namespace cryptobase */

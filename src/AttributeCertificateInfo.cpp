/*
 * AttributeCertificateInfo.cpp
 *
 *  Created on: 16/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#include "cryptobase/AttributeCertificateInfo.hpp"
#include "cryptobase/x509ac.h"

namespace cryptobase {

ASN1_IMPLEMENT_CLASS(AttributeCertificateInfoAsn1, X509AC_INFO)

AttributeCertificateInfo::AttributeCertificateInfo(X509AC_INFO *p) :
		AttributeCertificateInfoAsn1(p)
{
}

AttributeCertificateInfo::~AttributeCertificateInfo()
{
}

int AttributeCertificateInfo::getVersion() const
{
	return ASN1_INTEGER_get(internal_->version);
}

Holder AttributeCertificateInfo::getHolder() const
{
	return Holder(X509AC_HOLDER_dup(internal_->holder));
}

X509Name AttributeCertificateInfo::getIssuer() const
{
	return X509Name(X509_NAME_dup(sk_GENERAL_NAME_value(internal_->issuer->d.v2Form->issuer, 0)->d.directoryName));
}

ObjectIdentifier AttributeCertificateInfo::getSignature() const
{
	return ObjectIdentifier(OBJ_dup(internal_->algor->algorithm));
}

long int AttributeCertificateInfo::getSerial() const
{
	BIGNUM *bn = ASN1_INTEGER_to_BN(internal_->serial, nullptr);
	unsigned long tmp = BN_get_word(bn);
	BN_free(bn);
	return tmp;
}

std::string AttributeCertificateInfo::getSerialString() const
{
	BIGNUM *bn = ASN1_INTEGER_to_BN(internal_->serial, nullptr);
	char *str = BN_bn2dec(bn);
	std::string ret(str);
	OPENSSL_free(str);
	BN_free(bn);
	return ret;
}

AttributeCertificateValidity AttributeCertificateInfo::getValidity() const
{
	return AttributeCertificateValidity(X509AC_VAL_dup(internal_->validity));
}

std::vector<Attribute> AttributeCertificateInfo::getAttributes() const
{

	std::vector<Attribute> attributes;
	int count = X509at_get_attr_count(internal_->attributes);
	for(int i = 0; i < count; i++)
		attributes.push_back(Attribute(X509_ATTRIBUTE_dup(X509at_get_attr(internal_->attributes, i))));

	return attributes;
}

std::vector<Extension> AttributeCertificateInfo::getExtensions() const
{
	std::vector<Extension> exts;
	int count = sk_X509_EXTENSION_num(internal_->extensions);
	for(int i = 0; i < count; i++)
		exts.push_back(Extension(X509_EXTENSION_dup(sk_X509_EXTENSION_value(internal_->extensions, i))));
	return exts;
}

} /* namespace cryptobase */

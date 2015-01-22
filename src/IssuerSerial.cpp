/*
 * IssuerSerial.cpp
 *
 *  Created on: 11/09/2013
 *      Author: Giovani Milanez Espindola
 *  giovani.milanez@gmail.com
 */

#include "cryptobase/IssuerSerial.hpp"
#include "cryptobase/x509ac.h"

#include <string>

namespace cryptobase {

ASN1_IMPLEMENT_CLASS(IssuerSerialAsn1, X509AC_ISSUER_SERIAL)

IssuerSerial::IssuerSerial(X509AC_ISSUER_SERIAL *p) :
	IssuerSerialAsn1(p)
{
}

IssuerSerial::IssuerSerial(const X509Name& issuer, const std::string& serial):
	IssuerSerialAsn1(X509AC_ISSUER_SERIAL_new())
{
	if(internal_->issuer == nullptr)
		internal_->issuer = sk_GENERAL_NAME_new_null();

	GENERAL_NAME *gn = GENERAL_NAME_new();
	GENERAL_NAME_set0_value(gn, GEN_DIRNAME, X509_NAME_dup(issuer.internal_));
	sk_GENERAL_NAME_push(internal_->issuer, gn);

	BIGNUM *bn = BN_new();
	BN_dec2bn(&bn, serial.c_str());
	ASN1_INTEGER_free(internal_->serial);
	internal_->serial = BN_to_ASN1_INTEGER(bn, nullptr);
	BN_free(bn);
}

IssuerSerial::~IssuerSerial()
{
}

X509Name IssuerSerial::getIssuer() const
{
	GENERAL_NAME *gn = sk_GENERAL_NAME_value(internal_->issuer, 0);
	if(gn == nullptr)
		throw NullPointerException("Empty issuer");

	return X509Name(X509_NAME_dup(gn->d.directoryName));
}

long int IssuerSerial::getSerial() const
{
	return ASN1_INTEGER_get(internal_->serial);
}

std::string IssuerSerial::getSerialString() const
{
	BIGNUM *bn = ASN1_INTEGER_to_BN(internal_->serial, nullptr);
	char *str = BN_bn2dec(bn);
	std::string ret(str);
	OPENSSL_free(str);
	BN_free(bn);
	return ret;
}

ByteArray IssuerSerial::getIssuerUid() const
{
	return ByteArray((const unsigned char *)internal_->issuerUniqueID->data, internal_->issuerUniqueID->length);
}

bool IssuerSerial::operator ==(const IssuerSerial& value) const
{
	return getIssuer() == value.getIssuer() && getSerialString() == value.getSerialString();
}

bool IssuerSerial::operator !=(const IssuerSerial& value) const
{
	return !this->operator==(value);
}

} /* namespace cryptobase */

/*
 * Holder.cpp
 *
 *  Created on: 16/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#include "cryptobase/Holder.hpp"
#include "cryptobase/x509ac.h"
#include "cryptobase/Certificate.hpp"

namespace cryptobase {

ASN1_IMPLEMENT_CLASS(HolderAsn1, X509AC_HOLDER)

Holder::Holder(const Certificate& holderCert) :
		HolderAsn1(X509AC_HOLDER_new()),
		type_(Holder::HolderType::BASE_CERT_ID)
{
	IssuerSerial baseCertId(holderCert.getIssuer(), holderCert.getSerialNumberString());
	internal_->baseCertID = X509AC_ISSUER_SERIAL_dup(baseCertId.internal_);
}

Holder::Holder(const X509Name& holderName) :
		HolderAsn1(X509AC_HOLDER_new()),
		type_(Holder::HolderType::ENTITY_NAME)
{
	internal_->entity = GENERAL_NAMES_new();
	GENERAL_NAME *gn = GENERAL_NAME_new(); // TODO check leak
	GENERAL_NAME_set0_value(gn, GEN_DIRNAME, X509_NAME_dup(holderName.internal_));
	sk_GENERAL_NAME_push(internal_->entity, gn);
}

Holder::Holder(const IssuerSerial& baseCertId) :
	HolderAsn1(X509AC_HOLDER_new()),
	type_(Holder::HolderType::BASE_CERT_ID)
{
	internal_->baseCertID = X509AC_ISSUER_SERIAL_dup(baseCertId.internal_);
}

Holder::Holder(X509AC_HOLDER *p) :
		HolderAsn1(p)
{
	type_ = internal_->baseCertID != nullptr ? Holder::HolderType::BASE_CERT_ID :
			sk_GENERAL_NAME_value(internal_->entity, 0) != nullptr ? Holder::HolderType::ENTITY_NAME : Holder::HolderType::OBJECT_DIGEST_INFO;
}

Holder::~Holder()
{
}

IssuerSerial Holder::getHolderBaseCertId() const
{
	if(internal_->baseCertID == nullptr)
		throw NullPointerException("Empty holder of type entity base certificate id");

	return IssuerSerial(X509AC_ISSUER_SERIAL_dup(internal_->baseCertID));
}

X509Name Holder::getHolderEntityName() const
{
	GENERAL_NAME *gn = sk_GENERAL_NAME_value(internal_->entity, 0);
	if(gn == nullptr)
		throw NullPointerException("Empty holder of type entity name");

	return X509Name(X509_NAME_dup(gn->d.directoryName));
}

ObjectDigestInfo Holder::getHolderObjectDigestInfo() const
{
	if(internal_->objectDigestInfo == nullptr)
		throw NullPointerException("Empty holder of type entity object digest info");

	return ObjectDigestInfo(X509AC_OBJECT_DIGESTINFO_dup(internal_->objectDigestInfo));
}

bool Holder::operator ==(const Holder& value) const
{
	if(getType() == HolderType::BASE_CERT_ID && value.getType() == HolderType::BASE_CERT_ID)
	{
		return getHolderBaseCertId() == value.getHolderBaseCertId();
	}
	else if(getType() == HolderType::ENTITY_NAME && value.getType() == HolderType::ENTITY_NAME)
	{
		return getHolderEntityName() == value.getHolderEntityName();
	}
	else if(getType() == HolderType::OBJECT_DIGEST_INFO && value.getType() == HolderType::OBJECT_DIGEST_INFO)
	{
		return getHolderObjectDigestInfo() == value.getHolderObjectDigestInfo();
	}

	return false;
}
bool Holder::operator !=(const Holder& value) const
{
	return !this->operator==(value);
}

} /* namespace cryptobase */

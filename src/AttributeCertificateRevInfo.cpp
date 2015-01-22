/*
 * AttributeCertificateRevInfo.cpp
 *
 *  Criado em: 02/04/2014
 *      Autor: Giovani Milanez Espindola
 *  giovani.milanez@gmail.com
 */

#include "cryptobase/AttributeCertificateRevInfo.hpp"
#include "cryptobase/ObjectIdentifier.hpp"
#include "cryptobase/x509acreq.h"

namespace cryptobase {

ASN1_IMPLEMENT_CLASS(AttributeCertificateRevInfoAsn1, X509AC_REV_INFO)

AttributeCertificateRevInfo::AttributeCertificateRevInfo(const Holder& holder, const ObjectIdentifier& attrOid) :
	AttributeCertificateRevInfoAsn1(X509AC_REV_INFO_new())
{
	internal_->holder = X509AC_HOLDER_dup(holder.internal_);
	internal_->attributeOid = OBJ_dup(attrOid.internal_);
}

AttributeCertificateRevInfo::AttributeCertificateRevInfo(X509AC_REV_INFO *p) :
	AttributeCertificateRevInfoAsn1(p)
{
}

AttributeCertificateRevInfo::~AttributeCertificateRevInfo()
{
}

void AttributeCertificateRevInfo::setAttributeOid(const ObjectIdentifier& attrOid)
{
	ASN1_OBJECT_free(internal_->attributeOid);
	internal_->attributeOid = OBJ_dup(attrOid.internal_);
}

void AttributeCertificateRevInfo::setHolder(const Holder& holder)
{
	X509AC_HOLDER_free(internal_->holder);
	internal_->holder = X509AC_HOLDER_dup(holder.internal_);
}

Holder AttributeCertificateRevInfo::getHolder() const
{
	return Holder(X509AC_HOLDER_dup(internal_->holder));
}

ObjectIdentifier AttributeCertificateRevInfo::getAttributeOid() const
{
	return ObjectIdentifier(OBJ_dup(internal_->attributeOid));
}

} /* namespace cryptobase */

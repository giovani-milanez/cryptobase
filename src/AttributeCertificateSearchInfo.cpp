/*
 * AttributeCertificateSearchInfo.cpp
 *
 *  Criado em: 02/04/2014
 *      Autor: Giovani Milanez Espindola
 *  giovani.milanez@gmail.com
 */

#include "cryptobase/AttributeCertificateSearchInfo.hpp"
#include "cryptobase/ObjectIdentifier.hpp"
#include "cryptobase/x509acreq.h"

namespace cryptobase {

ASN1_IMPLEMENT_CLASS(AttributeCertificateSearchInfoAsn1, X509AC_SEARCH_INFO)

AttributeCertificateSearchInfo::AttributeCertificateSearchInfo(const Holder& holder) :
	AttributeCertificateSearchInfoAsn1(X509AC_SEARCH_INFO_new())
{
	internal_->holder = X509AC_HOLDER_dup(holder.internal_);
}

AttributeCertificateSearchInfo::AttributeCertificateSearchInfo(X509AC_SEARCH_INFO *p) :
	AttributeCertificateSearchInfoAsn1(p)
{
}

AttributeCertificateSearchInfo::~AttributeCertificateSearchInfo()
{
}

void AttributeCertificateSearchInfo::setAttributesOid(const std::vector<ObjectIdentifier>& attrsOid)
{
	for(auto attrOid : attrsOid)
		setAttributesOid(attrOid);
}

void AttributeCertificateSearchInfo::setAttributesOid(const ObjectIdentifier& attrOid)
{
	if(internal_->attributesOid == nullptr)
		internal_->attributesOid = sk_ASN1_OBJECT_new_null();

	sk_ASN1_OBJECT_push(internal_->attributesOid, OBJ_dup(attrOid.internal_));
}

Holder AttributeCertificateSearchInfo::getHolder() const
{
	return Holder(X509AC_HOLDER_dup(internal_->holder));
}

std::unique_ptr<std::vector<ObjectIdentifier>> AttributeCertificateSearchInfo::getAttributesOid() const
{
	std::unique_ptr<std::vector<ObjectIdentifier> > attrs;
	if(internal_->attributesOid != nullptr)
	{
		attrs.reset(new std::vector<ObjectIdentifier>);
		int count = sk_ASN1_OBJECT_num(internal_->attributesOid);
		attrs->reserve(count);
		for(int i = 0; i < count; i++)
			attrs->push_back(ObjectIdentifier(OBJ_dup(sk_ASN1_OBJECT_value(internal_->attributesOid, i))));
	}
	return attrs;
}

} /* namespace cryptobase */

/*
 * AttributeCertificateIssueInfo.cpp
 *
 *  Created on: 16/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#include "cryptobase/AttributeCertificateIssueInfo.hpp"
#include "cryptobase/GeneralizedTime.hpp"
#include "cryptobase/Extension.hpp"
#include "cryptobase/Attribute.hpp"
#include "cryptobase/AttributeCertificateValidity.hpp"
#include "cryptobase/x509acreq.h"

namespace cryptobase {

ASN1_IMPLEMENT_CLASS(AttributeCertificateIssueInfoAsn1, X509AC_ISSUE_INFO)


AttributeCertificateIssueInfo::AttributeCertificateIssueInfo(const Holder& holder) :
	AttributeCertificateIssueInfoAsn1(X509AC_ISSUE_INFO_new())
{
	X509AC_HOLDER_free(internal_->holder);
	internal_->holder = X509AC_HOLDER_dup(holder.internal_);
}
AttributeCertificateIssueInfo::AttributeCertificateIssueInfo(X509AC_ISSUE_INFO* p) :
		AttributeCertificateIssueInfoAsn1(p)
{
}

AttributeCertificateIssueInfo::~AttributeCertificateIssueInfo()
{
}

void AttributeCertificateIssueInfo::setTemplateId(int templateId)
{
	if(internal_->templateId == nullptr)
		internal_->templateId = ASN1_INTEGER_new();
	ASN1_INTEGER_set(internal_->templateId, templateId);
}

void AttributeCertificateIssueInfo::setIssuer(const X509Name& issuer)
{
	sk_GENERAL_NAME_push(internal_->issuer->d.v2Form->issuer, GENERAL_NAME_new());
	GENERAL_NAME_set0_value(sk_GENERAL_NAME_value(internal_->issuer->d.v2Form->issuer, 0), GEN_DIRNAME, X509_NAME_dup(issuer.internal_));
}

void AttributeCertificateIssueInfo::setValidity(const AttributeCertificateValidity& validity)
{
	X509AC_VAL_free(internal_->validity);
	internal_->validity = X509AC_VAL_dup(validity.internal_);
}

void AttributeCertificateIssueInfo::setAttributes(const std::vector<Attribute>& attributes)
{
	for(auto attr : attributes)
		setAttributes(attr);
}

void AttributeCertificateIssueInfo::setAttributes(Attribute& attribute)
{
	if(internal_->attributes == nullptr)
		internal_->attributes = sk_X509_ATTRIBUTE_new_null();
	sk_X509_ATTRIBUTE_push(internal_->attributes, X509_ATTRIBUTE_dup(attribute.internal_));
}

void AttributeCertificateIssueInfo::setExtensions(const std::vector<Extension>& extensions)
{
	for(auto ext : extensions)
		setExtensions(ext);
}

void AttributeCertificateIssueInfo::setExtensions(const Extension& extension)
{
	sk_X509_EXTENSION_push(internal_->extensions, X509_EXTENSION_dup(extension.internal_));
}

std::unique_ptr<int> AttributeCertificateIssueInfo::getTemplateId() const
{
	std::unique_ptr<int> tmplId;
	if(internal_->templateId != nullptr)
		tmplId.reset(new int(ASN1_INTEGER_get(internal_->templateId)));
	return tmplId;
}

Holder AttributeCertificateIssueInfo::getHolder() const
{
	return Holder(X509AC_HOLDER_dup(internal_->holder));
}

std::unique_ptr<X509Name> AttributeCertificateIssueInfo::getIssuer() const
{
	std::unique_ptr<X509Name> issuer;
	if(internal_->issuer->d.v2Form->issuer != nullptr)
		issuer.reset(new X509Name(X509_NAME_dup(sk_GENERAL_NAME_value(internal_->issuer->d.v2Form->issuer, 0)->d.directoryName)));
	return issuer;
}

std::unique_ptr<AttributeCertificateValidity> AttributeCertificateIssueInfo::getValidity() const
{
	std::unique_ptr<AttributeCertificateValidity> val;
	if(internal_->validity != nullptr)
		val.reset(new AttributeCertificateValidity(X509AC_VAL_dup(internal_->validity)));
	return val;
}

std::unique_ptr<std::vector<Attribute> > AttributeCertificateIssueInfo::getAttributes() const
{
	std::unique_ptr<std::vector<Attribute> > attrs;
	if(internal_->attributes != nullptr)
	{
		attrs.reset(new std::vector<Attribute>);
		int count = X509at_get_attr_count(internal_->attributes);
		for(int i = 0; i < count; i++)
			attrs->push_back(Attribute(X509_ATTRIBUTE_dup(X509at_get_attr(internal_->attributes, i))));
	}
	return attrs;
}

std::unique_ptr<std::vector<Extension> > AttributeCertificateIssueInfo::getExtensions() const
{
	std::unique_ptr<std::vector<Extension>> exts;
	if(internal_->extensions != nullptr)
	{
		exts.reset(new std::vector<Extension>);
		int count = sk_X509_EXTENSION_num(internal_->extensions);
		for(int i = 0; i < count; i++)
			exts->push_back(Extension(X509_EXTENSION_dup(sk_X509_EXTENSION_value(internal_->extensions, i))));
	}
	return exts;
}

} /* namespace cryptobase */


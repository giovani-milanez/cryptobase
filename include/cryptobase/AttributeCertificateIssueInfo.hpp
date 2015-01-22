/*
 * AttributeCertificateReqInfo.hpp
 *
 *  Created on: 16/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef ATTRIBUTECERTIFICATEREQINFO_HPP_
#define ATTRIBUTECERTIFICATEREQINFO_HPP_

#include "cryptobase/Asn1Class.hpp"
#include "cryptobase/Holder.hpp"

#include <memory>

typedef struct X509AC_ISSUE_INFO_st X509AC_ISSUE_INFO;

namespace cryptobase {

class GeneralizedTime;
class Attribute;
class Extension;
class AttributeCertificateValidity;
class Holder;

ASN1_DECLARE_CLASS(AttributeCertificateIssueInfoAsn1, X509AC_ISSUE_INFO)

class CRYPTOBASE_API AttributeCertificateIssueInfo : public AttributeCertificateIssueInfoAsn1
{
public:
	AttributeCertificateIssueInfo(const Holder& holder);
	AttributeCertificateIssueInfo(X509AC_ISSUE_INFO* p);
	virtual ~AttributeCertificateIssueInfo();

	void setTemplateId(int templateId);
	void setIssuer(const X509Name& issuer);
	void setValidity(const AttributeCertificateValidity& validity);
	void setAttributes(const std::vector<Attribute>& attributes);
	void setAttributes(Attribute& attribute);
	void setExtensions(const std::vector<Extension>& extensions);
	void setExtensions(const Extension& extension);

	std::unique_ptr<int> getTemplateId() const;
	Holder getHolder() const;
	std::unique_ptr<X509Name> getIssuer() const;
	std::unique_ptr<AttributeCertificateValidity> getValidity() const;
	std::unique_ptr<std::vector<Attribute>> getAttributes() const;
	std::unique_ptr<std::vector<Extension>> getExtensions() const;

};

} /* namespace cryptobase */
#endif /* ATTRIBUTECERTIFICATEREQINFO_HPP_ */

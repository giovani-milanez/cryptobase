/*
 * AttributeCertificateSearchInfo.hpp
 *
 *  Criado em: 02/04/2014
 *      Autor: Giovani Milanez Espindola
 *  giovani.milanez@gmail.com
 */

#ifndef ATTRIBUTECERTIFICATESEARCHINFO_HPP_
#define ATTRIBUTECERTIFICATESEARCHINFO_HPP_

#include "cryptobase/Asn1Class.hpp"
#include "cryptobase/Holder.hpp"

#include <vector>
#include <memory>

typedef struct X509AC_SEARCH_INFO_st X509AC_SEARCH_INFO;

namespace cryptobase {

class ObjectIdentifier;

ASN1_DECLARE_CLASS(AttributeCertificateSearchInfoAsn1, X509AC_SEARCH_INFO)

class CRYPTOBASE_API AttributeCertificateSearchInfo : public AttributeCertificateSearchInfoAsn1
{
public:
	explicit AttributeCertificateSearchInfo(const Holder& holder);
	explicit AttributeCertificateSearchInfo(X509AC_SEARCH_INFO *p);
	virtual ~AttributeCertificateSearchInfo();

	void setAttributesOid(const std::vector<ObjectIdentifier>& attrsOid);
	void setAttributesOid(const ObjectIdentifier& attrOid);
	Holder getHolder() const;
	std::unique_ptr<std::vector<ObjectIdentifier>> getAttributesOid() const;

};

} /* namespace cryptobase */

#endif /* ATTRIBUTECERTIFICATESEARCHINFO_HPP_ */
